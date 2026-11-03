"""修復動作：所有「會修改這台 Mac」的功能都集中在這裡。

流程（一律如此，沒有例外）：
  1. 預覽：伺服器依最近一次掃描結果與目前狀態，產生要執行的步驟清單（plan）。步驟內容只在伺服器端產生並保存，
     前端只能勾選要執行哪些步驟的 id，不能送任何路徑或指令進來。
  2. 授權：使用者按下執行後，跳出 macOS 系統的 Touch ID 對話框（只接受指紋，不能改用密碼），
     對話框裡會寫出這次要做的事。沒通過就什麼都不做。
  3. 執行：在背景依序執行，結果寫進 data/actions.jsonl。

威脅模型（擋得住的範圍）：其他網頁、遠端，以及只能呼叫 Web UI API 的程式（例如被 prompt injection、只拿得到
HTTP 存取權的 AI 助手）。這些都無法在沒有人按指紋的情況下讓 secaudit 修改系統。
擋不住的範圍：已經能以你的身分寫入檔案或執行程式的東西。它可以直接改 secaudit 的程式碼，或自己執行這些指令，
本來就不需要經過這裡。Touch ID 執行檔會比對雜湊，只是提高門檻，不是對同機程式的保證。
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid

from .app import DATA, REPORTS, _read
from .core import HOME, home_rel
from .rules import SECRET_RULES

SWIFT_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "touchid.swift")
BIN_DIR = os.path.join(DATA, "bin")
LOG = os.path.join(DATA, "actions.jsonl")
PLAN_TTL = 600            # 預覽 10 分鐘內有效
SECRET_ENV = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "OLLAMA_API_KEY")

_plans = {}
_lock = threading.Lock()
_lock_bin = threading.Lock()
status = {"running": False, "phase": "", "action": "", "title": "", "started": "", "finished": "", "ok": None,
          "message": "", "results": []}
recent = []   # 最近 5 次執行的完整結果（含輸出），只放記憶體；data/actions.jsonl 只記摘要


# ---------------------------------------------------------------- Touch ID
_bin = {"path": "", "sha": ""}   # 這個程序自己編譯出來的執行檔與雜湊（只放記憶體）


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _touchid_bin():
    """每個常駐程序第一次使用時自己編譯 touchid.swift，記下雜湊；之後每次使用前比對，不信任磁碟上現成的檔案。"""
    with _lock_bin:
        p = _bin["path"]
        if p and os.path.isfile(p) and _sha(p) == _bin["sha"]:
            return p
        os.makedirs(BIN_DIR, mode=0o700, exist_ok=True)
        for old in os.listdir(BIN_DIR):
            if old.startswith("touchid-"):
                os.remove(os.path.join(BIN_DIR, old))
        out = os.path.join(BIN_DIR, "touchid-" + uuid.uuid4().hex[:12])
        tmp = out + ".tmp"
        r = subprocess.run(["xcrun", "swiftc", "-O", "-o", tmp, SWIFT_SRC], capture_output=True, text=True,
                           timeout=600, env=_env())
        if r.returncode != 0:
            raise RuntimeError("編譯 Touch ID 工具失敗（需要 Xcode Command Line Tools）：" + (r.stderr or r.stdout)[-300:])
        os.chmod(tmp, 0o700)
        os.replace(tmp, out)
        _bin.update(path=out, sha=_sha(out))
        return out


def touchid_available():
    try:
        r = subprocess.run([_touchid_bin(), "--check"], capture_output=True, text=True, timeout=30, env=_env())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        return False, str(e)[:300]
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]


def authorize(reason):
    """跳出 Touch ID 對話框。回傳 (通過與否, 訊息)。"""
    try:
        r = subprocess.run([_touchid_bin(), reason[:500]], capture_output=True, text=True, timeout=180, env=_env())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        return False, str(e)[:300]
    if r.returncode == 0:
        return True, ""
    if r.returncode == 2:
        return False, "這台 Mac 現在不能用 Touch ID（例如筆電螢幕闔上、沒有設定指紋）：" + r.stderr.strip()[:200]
    return False, "未通過 Touch ID（取消、失敗或逾時）"


# ---------------------------------------------------------------- 共用
_SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSW|PWD|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE|CHAT_ID", re.I)
_ENV_KEEP = {"PWD", "OLDPWD", "SSH_AUTH_SOCK"}


def _env(**extra_vars):
    """子程序用的環境變數：拿掉常駐程式持有的機密。
    除了固定名單，也拿掉 SECAUDIT_SECRET_KEYS 列出的名稱（1Password 載入的變數），以及名稱看起來像機密的變數。"""
    drop = set(SECRET_ENV) | {k for k in os.environ.get("SECAUDIT_SECRET_KEYS", "").split(",") if k}
    env = {k: v for k, v in os.environ.items()
           if k not in drop and (k in _ENV_KEEP or not _SECRETISH.search(k)) and k != "SECAUDIT_SECRET_KEYS"}
    extra = ["/opt/homebrew/bin", "/usr/local/bin", os.path.join(HOME, ".cargo", "bin"), os.path.join(HOME, ".bun", "bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH") or "/usr/bin:/bin:/usr/sbin:/sbin"])
    env.update(HOMEBREW_NO_ENV_HINTS="1", NONINTERACTIVE="1", CI="1")
    env.update(extra_vars)
    return env


def _latest_findings():
    try:
        names = sorted(f for f in os.listdir(REPORTS) if f.endswith(".json"))
    except OSError:
        names = []
    if not names:
        return "", []
    return names[-1][:-5], _read(os.path.join(REPORTS, names[-1]), {}).get("findings", [])


def _run_cmd(argv, timeout=3600, keep=4000, env=None):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env or _env(), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False, "逾時（%d 秒）" % timeout
    except OSError as e:
        return False, str(e)
    if keep is None:
        return r.returncode == 0, r.stdout
    out = (r.stdout + ("\n" + r.stderr if r.stderr else "")).strip()
    return r.returncode == 0, out[-keep:]


# ---------------------------------------------------------------- 動作 1：遮罩 AI 對話紀錄裡的金鑰
TRANSCRIPT_DIRS = [os.path.expanduser(p) for p in ("~/.claude/projects", "~/.claude/paste-cache", "~/.codex/sessions")]
TRANSCRIPT_FILES = [os.path.expanduser("~/.claude/history.jsonl")]
_BRULES = [(rid, re.compile(rx.pattern.encode())) for rid, _n, rx, _s in SECRET_RULES]
_PK_HEAD = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")
_PK_END = re.compile(rb"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")
_PK_BODY = re.compile(rb"(?:(?<=\\n)|(?<=\\r)|(?<=\s))[A-Za-z0-9+/=]+")
_LABEL = b"[REDACTED]"


def _transcript_path_ok(p):
    rp = os.path.realpath(p)
    return os.path.isfile(rp) and not os.path.islink(p) and (
        rp in TRANSCRIPT_FILES or any(rp.startswith(os.path.realpath(d) + os.sep) for d in TRANSCRIPT_DIRS))


def _mask(raw, rid):
    """遮罩後長度不變：可以直接覆寫原檔的那幾個位元組，不必重寫整個檔案。
    這樣正在寫入這個檔案的程式（Claude Code 等）不會因為檔案被換掉而把新內容寫到已刪除的舊檔。"""
    if rid == "private-key":   # 保留標頭、換行與 JSON 跳脫字元，只遮掉 base64 內容（含最後比較短的那一行）
        h = _PK_HEAD.match(raw)
        n = h.end() if h else 0
        e = _PK_END.search(raw, n)
        stop = e.start() if e else len(raw)
        return raw[:n] + _PK_BODY.sub(lambda m: b"*" * len(m.group()), raw[n:stop]) + raw[stop:]
    if len(raw) < len(_LABEL):
        return b"*" * len(raw)
    return _LABEL + b"*" * (len(raw) - len(_LABEL))


def redact_file(path):
    """回傳 (遮罩處數, 因檔案內容已變動而略過的處數)。
    每次寫入前會重讀那個位置，內容和比對到的一樣才寫；檔案在讀取後被截斷或重寫時就略過，不會寫到別的內容上。"""
    n = skipped = 0
    with open(path, "r+b") as fh:
        data = fh.read()
        edits = []
        for rid, rx in _BRULES:
            for m in rx.finditer(data):
                start, raw = m.start(), m.group()
                if rid == "private-key":   # 正規式只比對到前面的長行，延伸到 END 標記，才能遮到最後一行
                    e = _PK_END.search(data, m.end(), m.end() + 4096)
                    if e:
                        raw = data[start:e.end()]
                rep = _mask(raw, rid)
                if rep != raw:
                    edits.append((start, raw, rep))
        for start, raw, rep in edits:
            fh.seek(start)
            if fh.read(len(raw)) != raw:
                skipped += 1
                continue
            fh.seek(start)
            fh.write(rep)
            n += 1
        fh.flush()
        os.fsync(fh.fileno())
    return n, skipped


def plan_redact():
    name, fs = _latest_findings()
    files = {}
    for f in fs:
        if f.get("rule", "").startswith("transcript-") and f.get("path"):
            p = os.path.expanduser(f["path"])
            if _transcript_path_ok(p):
                files.setdefault(p, []).append("%s（%s）" % (f["title"].split("出現 ")[-1], f.get("detail", "")))
    steps = [{"id": "f%d" % i, "label": home_rel(p), "detail": "、".join(files[p]), "kind": "redact", "path": p}
             for i, p in enumerate(sorted(files))]
    return {"title": "遮罩 AI 對話紀錄裡的金鑰", "report": name, "steps": steps,
            "notes": ["把金鑰字串換成同樣長度的 [REDACTED]***，不留備份（備份等於保留機密）。",
                      "只處理最近一次掃描報告列出的檔案，而且只限 ~/.claude、~/.codex 底下的對話紀錄。",
                      "掃描只涵蓋 ~/.claude/projects、~/.claude/history.jsonl、paste-cache、~/.codex/sessions。同一組金鑰可能還留在"
                      " ~/.claude/file-history、debug、shell-snapshots、todos、~/.codex/history.jsonl、~/.zsh_history，請另外檢查。",
                      "遮罩不等於安全：這些金鑰已經被視為外洩，仍然要到各平台撤銷、換新。"]}


# ---------------------------------------------------------------- 動作 2：升級執行環境（同一版本線）
BREW_RUNTIME = re.compile(r"^(?:node(?:@\d+)?|python@3\.\d+|go(?:@[\d.]+)?|ruby(?:@[\d.]+)?|openjdk(?:@\d+)?|php(?:@[\d.]+)?|rust|deno|bun|dotnet(?:@\d+)?|pnpm)$")


BREW_ENV = {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK": "1"}


def _brew_targets(formulae):
    """Homebrew 目前（不更新索引）會把每個 formula 升到哪一版。"""
    ok, out = _run_cmd(["brew", "info", "--json=v2", "--formula"] + list(formulae), timeout=120, keep=None, env=_env(**BREW_ENV))
    try:
        return {x["name"]: x["versions"]["stable"] for x in json.loads(out)["formulae"]} if ok else {}
    except (ValueError, KeyError):
        return {}


def plan_upgrade():
    from .runtimes import _vkey, discover, eol_data, find_cycle
    cache = _read(os.path.join(DATA, "cache.json"), {}).get("osv", {})   # 掃描時執行環境資料存在 osv 底下
    brew, steps, seen = {}, [], set()
    for x in discover(cache.get("runtime_versions", {})):
        cy = find_cycle(eol_data(x["product"], cache, online=False), x["version"])
        latest = str((cy or {}).get("latest") or "")
        if not latest or _vkey(latest) <= _vkey(x["version"]):
            continue
        if x["source"] == "Homebrew":
            f = x["where"][5:]
            if BREW_RUNTIME.match(f):
                brew.setdefault(f, set()).add("%s → %s" % (x["version"], latest))
        elif x["source"] == "rustup" and x["where"] == "rustup stable" and "rustup" not in seen:
            seen.add("rustup")
            steps.append({"id": "rustup", "label": "rustup update stable", "detail": "Rust %s → 最新 stable（只更新 stable，不動 1.69 / 1.70 這類釘選的 toolchain）" % x["version"],
                          "kind": "cmd", "argv": [os.path.join(HOME, ".cargo", "bin", "rustup"), "update", "stable"]})
        elif x["product"] == "bun" and x["source"] == "官方安裝程式" and "bun" not in seen:
            seen.add("bun")
            steps.append({"id": "bun", "label": "bun upgrade", "detail": "Bun %s → %s" % (x["version"], latest),
                          "kind": "cmd", "argv": [x["path"], "upgrade"]})
        elif x["product"] == "pnpm" and "pnpm" not in seen:
            seen.add("pnpm")
            rp = os.path.realpath(x["path"])
            # discover 給的是真實路徑（例如 corepack/dist/pnpm.js）；corepack、npm 要從 PATH 上原本那個 bin 資料夾找
            bindir = next((d for d in _env()["PATH"].split(os.pathsep)
                           if os.path.isfile(os.path.join(d, "pnpm")) and os.path.realpath(os.path.join(d, "pnpm")) == rp), "")
            if not bindir:
                continue
            if "/corepack/" in rp:
                argv = [os.path.join(bindir, "corepack"), "install", "-g", "pnpm@%s" % latest]
            elif "/Library/pnpm/" in rp:
                argv = [os.path.join(bindir, "pnpm"), "self-update", latest]
            elif "/node_modules/pnpm/" in rp:
                argv = [os.path.join(bindir, "npm"), "install", "-g", "pnpm@%s" % latest]
            else:
                continue
            if not os.path.isfile(argv[0]):
                continue
            steps.append({"id": "pnpm", "label": " ".join([os.path.basename(argv[0])] + argv[1:]),
                          "detail": "pnpm %s → %s（%s）" % (x["version"], latest, home_rel(rp)), "kind": "cmd", "argv": argv})
    # 沒有 @ 的 formula（node、openjdk、php…）永遠跟著最新主版本，brew upgrade 可能直接跨版本線，要先問 brew 會升到哪一版
    targets = _brew_targets(sorted(brew)) if brew else {}
    dry = ""
    if brew:
        ok, dry = _run_cmd(["brew", "upgrade", "--formula", "--dry-run"] + sorted(brew), timeout=300, env=_env(**BREW_ENV), keep=None)
    for f in sorted(brew, reverse=True):
        tgt = targets.get(f, "")
        cur = sorted(brew[f])[0].split(" → ")[0]
        n = 1 if f.startswith(("node", "openjdk")) else 2      # Node / Java 以主版本為一條版本線
        cross = bool(tgt) and _vkey(tgt)[:n] != _vkey(cur)[:n]
        detail = "、".join(sorted(brew[f])) + ("；Homebrew 實際會裝 %s" % tgt if tgt else "")
        if cross:
            detail = "⚠️ 會跨版本線升到 %s（不只是修補版），可能不相容，預設不勾選。目前：%s" % (tgt, "、".join(sorted(brew[f])))
        steps.insert(0, {"id": "brew:" + f, "label": "brew upgrade " + f, "detail": detail,
                         "kind": "brew", "formula": f, "target": tgt, "default": not cross})
    steps.sort(key=lambda s: (not s["id"].startswith("brew:"), s["id"]))
    notes = []
    if dry:
        notes.append("Homebrew 預演（brew upgrade --dry-run，含所有候選項目；相依套件也可能一起升級）：" + dry.strip()[:1500])
    return {"title": "升級執行環境（同一版本線的修補版）", "report": "", "steps": steps,
            "notes": notes + ["只升級小版號，不會移除任何版本線；Homebrew 升級後會自動清掉同一個 formula 的舊修補版。",
                      "執行時不會讓 Homebrew 自動更新套件索引；執行前會再確認一次目標版本，和預覽不同就略過那一項。",
                      "正在執行的程式（例如 PM2 的服務）不會被重啟，下次重啟時才會用到新版。",
                      "版本資訊來自最近一次掃描的 endoflife.date 快取；Homebrew 實際會升到它目前提供的最新版。"]}


# ---------------------------------------------------------------- 動作 3：清掉用不到的 Go toolchain 快取
GO_TC = os.path.join(HOME, "go", "pkg", "mod", "golang.org")
GO_DL = os.path.join(HOME, "go", "pkg", "mod", "cache", "download", "golang.org", "toolchain", "@v")


def plan_go_cache():
    from .runtimes import _vkey
    ok, out = _run_cmd(["go", "env", "GOVERSION"], timeout=30, env=_env(GOTOOLCHAIN="local"))   # 不讓 go 自動下載 toolchain
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", out) if ok else None
    steps = []
    if m:
        local = m.group(1)
        for d in sorted(os.listdir(GO_TC)) if os.path.isdir(GO_TC) else []:
            mm = re.match(r"^toolchain@v0\.0\.1-go(\d+\.\d+(?:\.\d+)?)\.[\w-]+$", d)
            if not mm or _vkey(mm.group(1)) >= _vkey(local):
                continue
            ver = mm.group(1)
            paths = [os.path.join(GO_TC, d)]
            if os.path.isdir(GO_DL):
                paths += [os.path.join(GO_DL, f) for f in os.listdir(GO_DL) if f.startswith(d.split("@", 1)[1] + ".")]
            steps.append({"id": "go" + ver, "label": "刪除 Go %s toolchain 快取" % ver,
                          "detail": "、".join(home_rel(p) for p in paths), "kind": "rm", "paths": paths})
        steps.sort(key=lambda s: _vkey(s["id"][2:]))
    return {"title": "清除比本機 Go（%s）舊的 toolchain 快取" % (m.group(1) if m else "?"), "report": "", "steps": steps,
            "notes": ["本機的 Go 比這些版本新，go.mod 的 toolchain 指令會直接用本機版本，不會再用到這些快取。",
                      "就算之後真的需要，Go 也會自動重新下載。"]}


def _rm_ok(p):
    rp = os.path.realpath(p)
    return (rp.startswith(os.path.realpath(GO_TC) + os.sep + "toolchain@v0.0.1-go") or
            rp.startswith(os.path.realpath(GO_DL) + os.sep + "v0.0.1-go"))


def _rm(p):
    if os.path.isdir(p) and not os.path.islink(p):
        for dp, dns, fns in os.walk(p):           # Go 模組快取是唯讀的，要先加上寫入權限
            os.chmod(dp, 0o700)
        shutil.rmtree(p)
    elif os.path.lexists(p):
        os.remove(p)


# ---------------------------------------------------------------- 對外介面
ACTIONS = {
    "redact-transcripts": ("🔑", "遮罩 AI 對話紀錄裡的金鑰", plan_redact),
    "upgrade-runtimes": ("⬆️", "升級執行環境（同一版本線）", plan_upgrade),
    "clean-go-toolchains": ("🧹", "清除舊的 Go toolchain 快取", plan_go_cache),
}


def catalog():
    _, fs = _latest_findings()
    n_tr = sum(1 for f in fs if f.get("rule", "").startswith("transcript-"))
    hints = {"redact-transcripts": "最近一次報告有 %d 項對話紀錄金鑰" % n_tr if n_tr else "最近一次報告沒有發現"}
    return [{"id": k, "icon": v[0], "title": v[1], "hint": hints.get(k, "")} for k, v in ACTIONS.items()]


def make_plan(action):
    if action not in ACTIONS:
        raise KeyError(action)
    plan = ACTIONS[action][2]()
    pid = uuid.uuid4().hex
    with _lock:
        now = time.time()
        for k in [k for k, v in _plans.items() if now - v["created"] > PLAN_TTL]:
            del _plans[k]
        _plans[pid] = dict(plan, action=action, created=now)
    public = [{"id": s["id"], "label": s["label"], "detail": s["detail"], "default": s.get("default", True)} for s in plan["steps"]]
    return {"plan_id": pid, "action": action, "title": plan["title"], "report": plan.get("report", ""),
            "steps": public, "notes": plan.get("notes", [])}


def _binding(plan_id, step_ids):
    return "%s|%s" % (plan_id, ",".join(sorted(set(step_ids or []))))


def _notify(text):
    try:   # 使用者規定：需要介入前先通知（常駐程式已持有 Telegram 金鑰）
        from .notify import telegram_send
        import html as _h
        telegram_send(_h.escape(text))
    except Exception:
        pass


def yubikey_options(plan_id, step_ids):
    """YubiKey 授權修復動作：challenge 綁定這份預覽與勾選的步驟，換步驟就失效。"""
    from . import webauthn
    with _lock:
        if plan_id not in _plans:
            return None
    return webauthn.request_options("run", _binding(plan_id, step_ids))


def start(plan_id, step_ids, method="touchid", assertion=None, port=0):
    """回傳 (是否開始, 訊息)。method = touchid（背景跳 Touch ID）或 yubikey（先驗證 assertion）。進度看 status。"""
    with _lock:
        if status["running"]:
            return False, "已經有一個修復動作在進行"
        plan = _plans.get(plan_id)
        if not plan or time.time() - plan["created"] > PLAN_TTL:
            return False, "預覽已過期，請重新預覽"
        want = set(step_ids or [])
        steps = [s for s in plan["steps"] if s["id"] in want]
        if not steps:
            return False, "沒有選擇任何步驟"
    key_name = None
    if method == "yubikey":
        from . import webauthn
        try:
            key_name = webauthn.verify_assertion(assertion or {}, "run", _binding(plan_id, step_ids), port)
        except (ValueError, KeyError, TypeError) as e:
            return False, "YubiKey 驗證失敗：%s" % e
    elif method != "touchid":
        return False, "未知的授權方式"
    with _lock:
        if status["running"] or _plans.pop(plan_id, None) is None:
            return False, "預覽已被使用或已有動作在進行"
        status.update(running=True, phase="等待 Touch ID" if not key_name else "執行中", action=plan["action"],
                      title=plan["title"], started=time.strftime("%Y-%m-%d %H:%M:%S"), finished="", ok=None,
                      message="", results=[], method="YubiKey「%s」" % key_name if key_name else "Touch ID")
    threading.Thread(target=_execute, args=(plan, steps, key_name), daemon=True).start()
    return True, ""


def _execute(plan, steps, key_name=None):
    results = []
    try:
        labels = "、".join(s["label"] for s in steps[:4]) + ("…等 %d 項" % len(steps) if len(steps) > 4 else "")
        reason = "執行 secaudit 修復「%s」：%s" % (plan["title"], labels)
        if key_name:
            _notify("🔑 secaudit 已用 YubiKey「%s」授權並開始執行：%s。不是你做的話請立即檢查。" % (key_name, reason))
        else:
            _notify("🔒 secaudit 正在請求 Touch ID 授權修復動作：%s。不是你按的話請按取消。" % reason)
            ok, msg = authorize(reason)
            if not ok:
                status.update(ok=False, message=msg)
                return
        status["phase"] = "執行中"
        brew = [s for s in steps if s["kind"] == "brew"]
        if brew:
            status["phase"] = "確認 Homebrew 目標版本"
            now = _brew_targets([s["formula"] for s in brew])
            go = []
            for s in brew:
                if s.get("target") and now.get(s["formula"]) != s["target"]:
                    results.append({"id": s["id"], "label": s["label"], "ok": False,
                                    "output": "略過：目標版本已從預覽時的 %s 變成 %s，請重新預覽" % (s["target"], now.get(s["formula"]) or "?")})
                else:
                    go.append(s)
            if go:
                status["phase"] = "brew upgrade（可能需要幾分鐘）"
                ok, out = _run_cmd(["brew", "upgrade", "--formula"] + [s["formula"] for s in go], env=_env(**BREW_ENV))
                for s in go:
                    results.append({"id": s["id"], "label": s["label"], "ok": ok, "output": out})
            status["results"] = results
        for s in steps:
            if s["kind"] == "brew":
                continue
            status["phase"] = s["label"]
            if s["kind"] == "redact":
                if not _transcript_path_ok(s["path"]):
                    r = (False, "路徑不在允許範圍，略過")
                else:
                    try:
                        done, skipped = redact_file(s["path"])
                        r = (not skipped, "遮罩 %d 處%s" % (done, "；%d 處因檔案在讀取後被改動而略過，請重新掃描後再執行一次" % skipped
                                                            if skipped else ""))
                    except OSError as e:
                        r = (False, str(e))
            elif s["kind"] == "cmd":
                r = _run_cmd(s["argv"])
            elif s["kind"] == "rm":
                done, errs = 0, []
                for p in s["paths"]:
                    if not _rm_ok(p):
                        errs.append("略過（不在允許範圍）：" + home_rel(p))
                        continue
                    try:
                        _rm(p)
                        done += 1
                    except OSError as e:
                        errs.append("%s：%s" % (home_rel(p), e))
                r = (not errs, "刪除 %d 項%s" % (done, ("\n" + "\n".join(errs)) if errs else ""))
            else:
                r = (False, "未知的步驟類型")
            results.append({"id": s["id"], "label": s["label"], "ok": r[0], "output": r[1]})
            status["results"] = results
        fails = sum(1 for r in results if not r["ok"])
        status.update(ok=not fails, message="完成，%d 個步驟%s" % (len(results), "，%d 個失敗" % fails if fails else "全部成功"))
    except Exception as e:   # 背景執行緒不能讓例外消失
        status.update(ok=False, message="%s: %s" % (type(e).__name__, str(e)[:300]))
    finally:
        status.update(running=False, phase="", finished=time.strftime("%Y-%m-%d %H:%M:%S"), results=results)
        recent.insert(0, {k: status.get(k) for k in ("title", "method", "started", "finished", "ok", "message")})
        recent[0]["results"] = list(results)
        del recent[5:]
        _log({"time": status["started"], "finished": status["finished"], "action": plan["action"], "ok": status["ok"],
              "method": status.get("method", ""),
              "message": status["message"], "steps": [{"id": r["id"], "label": r["label"], "ok": r["ok"]} for r in results]
              or [{"id": s["id"], "label": s["label"], "ok": None} for s in steps]})


def _log(entry):
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def history(n=10):
    try:
        with open(LOG, encoding="utf-8") as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------- YubiKey 金鑰管理（本身也要授權）
def _key_auth(method, assertion, purpose, binding, port, reason):
    """授權金鑰的新增 / 刪除：Touch ID，或已註冊的 YubiKey。回傳 (通過, 訊息, 授權方式)。"""
    from . import webauthn
    if method == "yubikey":
        try:
            return True, "", "YubiKey「%s」" % webauthn.verify_assertion(assertion or {}, purpose, binding, port)
        except (ValueError, KeyError, TypeError) as e:
            return False, "YubiKey 驗證失敗：%s" % e, ""
    if method != "touchid":
        return False, "未知的授權方式", ""
    _notify("🔒 secaudit 正在請求 Touch ID：%s。不是你按的話請按取消。" % reason)
    ok, msg = authorize(reason)
    return ok, msg, "Touch ID"


def key_add_binding(reg):
    return "add|" + hashlib.sha256(str(reg.get("attestationObject", "")).encode()).hexdigest()


def key_add(reg, method, assertion, port):
    """新增 YubiKey：先驗證註冊資料，再要求授權，通過才存。"""
    from . import webauthn
    try:
        entry = webauthn.check_registration(reg or {}, port)
    except (ValueError, KeyError, TypeError, IndexError) as e:
        return False, "註冊資料無效：%s" % e
    ok, msg, how = _key_auth(method, assertion, "add-key", key_add_binding(reg), port,
                             "新增 YubiKey「%s」為 secaudit 的授權金鑰" % entry["name"])
    if not ok:
        return False, msg
    webauthn.add_key(entry)
    _log({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "action": "add-key", "ok": True, "method": how,
          "message": "新增 YubiKey「%s」" % entry["name"], "steps": []})
    _notify("🔑 secaudit 新增了授權用的 YubiKey「%s」（以 %s 授權）。不是你做的話請立即到 Web UI 刪除。" % (entry["name"], how))
    return True, ""


def key_remove(kid, method, assertion, port):
    from . import webauthn
    k = next((x for x in webauthn.keys() if x["id"] == kid), None)
    if not k:
        return False, "找不到這把金鑰"
    ok, msg, how = _key_auth(method, assertion, "del-key", "del|" + kid, port, "從 secaudit 移除 YubiKey「%s」" % k["name"])
    if not ok:
        return False, msg
    webauthn.remove_key(kid)
    _log({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "action": "remove-key", "ok": True, "method": how,
          "message": "移除 YubiKey「%s」" % k["name"], "steps": []})
    _notify("🔑 secaudit 移除了 YubiKey「%s」（以 %s 授權）。" % (k["name"], how))
    return True, ""
