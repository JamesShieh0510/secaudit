"""GitHub 監控：定期抓各帳號、各組織 repo 的變動，找出 CI 供應鏈攻擊的手法。

針對的攻擊型態（2026-11 實際發生過）：同事的 GitHub token 外流，攻擊者
  1. 對一百多個 repo 各開一個無害的 PR（探測哪些 repo 有寫入權限）
  2. 直接 push 到預設分支，在 workflow 裡加一段把 toJSON(secrets) 送到外部 IP 的步驟，
     一分鐘後再 push 一次「restore」改回來，main 的內容看起來沒變
  3. 或推一個隨機名稱的分支，帶一個新的 workflow，push 一觸發就把機密送出去

做法：只用 GitHub REST API 讀取（不修改任何東西），每個帳號用 `gh auth token -u <帳號>` 取得 token
（或環境變數 GH_TOKEN_<帳號>，可由 1Password 注入），token 不寫入任何檔案、不寫進 log。
  - 每次檢查：列出「上次之後有 push」的 repo → 讀 repo 事件（push / 開分支 / PR / 成員 / 公開）
    → push 有動到 workflow 的，抓 diff 掃可疑內容、判斷是否繞過 PR、是否「改了又還原」
    → 讀這段時間的 workflow 執行紀錄：可疑 commit 有沒有真的被執行、執行紀錄有沒有被刪掉
  - 每天一次（需要 admin 權限的項目拿不到就略過）：新成員 / 外部協作者、webhook、deploy key、
    repo 變成公開、預設分支沒有保護、組織機密開放給所有 repo
結果存在 data/ghwatch.json 的 alerts，掃描時由 checks_github 轉成報告裡的「GitHub 監控」問題。
"""
import base64
import collections
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SECAUDIT_DATA", os.path.join(ROOT, "data"))
STORE = os.path.join(DATA, "ghwatch.json")
API = "https://api.github.com"
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
ZERO = "0" * 40
ALERT_KEEP_DAYS = 30
FIRST_LOOKBACK_H = 72          # 第一次監控一個帳號 / 組織時往回看幾小時（剛被攻擊時能直接抓到）
AUDIT_EVERY_H = 24
_lock = threading.Lock()
_st_lock = threading.RLock()      # 各 repo 並行檢查時，保護共用的 alerts
WORKERS = 8

# workflow 新增內容的可疑寫法：(標籤, 嚴重度, regex)
WF_PATTERNS = [
    ("把所有機密轉成 JSON（toJSON(secrets)）", "high", re.compile(r"toJSON\(\s*secrets\s*\)", re.I)),
    ("把所有變數轉成 JSON（toJSON(vars)）", "medium", re.compile(r"toJSON\(\s*vars\s*\)", re.I)),
    ("讀取 runner 內部 token（ACTIONS_RUNTIME_TOKEN / OIDC）", "high",
     re.compile(r"ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL)|ACTIONS_CACHE_URL")),
    # 本機 / 內網位址（127.x、10.x、192.168.x、172.16–31.x、0.0.0.0）是部署腳本常見的健康檢查，不算外連；
    # 169.254.x（雲端 metadata，可拿到雲端憑證）仍然算
    ("連到裸 IP 位址", "high", re.compile(r"\bhttps?://(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?")),
    ("常見的外傳 / 暫存服務", "high", re.compile(
        r"webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|trycloudflare\.com|transfer\.sh|"
        r"pastebin\.com|paste\.ee|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|interact\.sh|oast\.", re.I)),
    ("讀取 runner 程序記憶體", "high", re.compile(r"/proc/\d*\*?/(?:mem|maps|environ)|Runner\.Worker|memdump|WF_MEMSCAN", re.I)),
    ("下載後直接執行", "medium", re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh", re.I)),
    ("字眼像在外傳資料（exfil / callback）", "high", re.compile(r"\bexfil|WF_CALLBACK|\bcallback_url\b", re.I)),
    ("改成 pull_request_target（外部 PR 也拿得到機密）", "medium", re.compile(r"^\s*pull_request_target\s*:", re.M)),
    ("權限改成 write-all", "medium", re.compile(r"permissions\s*:\s*write-all")),
]
WF_PATH_RE = re.compile(r"^(?:\.github/workflows/[^/]+\.ya?ml|(?:.*/)?action\.ya?ml|\.github/actions/.+)$")
BOT_RE = re.compile(r"\[bot\]$|^dependabot|^renovate|^github-actions$|^web-flow$")


# ---------------------------------------------------------------------------------------------- 帳號與 token
def _gh_bin():
    return shutil.which("gh") or next((p for p in ("/opt/homebrew/bin/gh", "/usr/local/bin/gh") if os.path.exists(p)), None)


def gh_accounts():
    """本機 gh CLI 已登入的 github.com 帳號（給設定頁選）。"""
    gh = _gh_bin()
    if not gh:
        return []
    try:
        r = subprocess.run([gh, "auth", "status", "-h", "github.com"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted(set(re.findall(r"account (\S+)", (r.stdout or "") + (r.stderr or ""))))


def _token(login):
    env = os.environ.get("GH_TOKEN_" + re.sub(r"\W", "_", login).upper())
    if env:
        return env.strip()
    gh = _gh_bin()
    if not gh:
        return None
    try:
        r = subprocess.run([gh, "auth", "token", "-h", "github.com", "-u", login], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    t = (r.stdout or "").strip()
    return t if r.returncode == 0 and t else None


class GH:
    def __init__(self, token):
        self.token = token
        self.calls = 0
        self.remaining = None

    def req(self, path, params=None, etag=None):
        url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
        h = {"Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
             "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "secaudit-ghwatch"}
        if etag:
            h["If-None-Match"] = etag
        self.calls += 1
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=25) as r:
                self.remaining = r.headers.get("X-RateLimit-Remaining", self.remaining)
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None), r.headers
        except urllib.error.HTTPError as e:
            self.remaining = e.headers.get("X-RateLimit-Remaining", self.remaining) if e.headers else self.remaining
            if e.code == 304:
                return 304, None, e.headers
            try:
                body = json.loads(e.read() or b"null")
            except ValueError:
                body = None
            return e.code, body, e.headers

    def low(self):
        try:
            return self.remaining is not None and int(self.remaining) < 300
        except ValueError:
            return False

    def pages(self, path, params=None, maxpages=5, stop=None):
        out = []
        p = dict(params or {})
        p.setdefault("per_page", 100)
        for page in range(1, maxpages + 1):
            p["page"] = page
            code, data, _ = self.req(path, p)
            if code != 200 or data is None:
                if page == 1:
                    raise _ApiError(code, data)
                break
            items = data.get("workflow_runs", data.get("secrets", [])) if isinstance(data, dict) else data
            out.extend(items)
            if len(items) < p["per_page"] or (stop and items and stop(items[-1])):
                break
        return out


class _ApiError(Exception):
    def __init__(self, code, data):
        super().__init__("HTTP %s %s" % (code, (data or {}).get("message", "") if isinstance(data, dict) else ""))
        self.code = code


# ---------------------------------------------------------------------------------------------- 工具
def _ts(s):
    """GitHub 的 ISO 時間 → epoch。"""
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (TypeError, ValueError):
        return 0


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _local(t):
    return time.strftime("%m-%d %H:%M", time.localtime(t))


def _load():
    try:
        with open(STORE, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    st.setdefault("owners", {})
    st.setdefault("alerts", {})
    st.setdefault("recent", [])
    st.setdefault("status", {})
    return st


def _save(st):
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    tmp = STORE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, STORE)


def load_alerts():
    return _load()


def _alert(st, key, now, **f):
    """新增或更新一筆警示；回傳是否為新的。同一個 key 的多次事件合併，次數與時間累加。"""
    with _st_lock:
        return _alert_locked(st, key, now, **f)


def _alert_locked(st, key, now, **f):
    a = st["alerts"].get(key)
    if a:
        a["last"] = now
        a["count"] = a.get("count", 1) + 1
        for k in ("severity", "title", "detail", "evidence"):
            if k in f and (k != "severity" or _sev_rank(f[k]) < _sev_rank(a.get(k, "info"))):
                a[k] = f[k]
        return False
    st["alerts"][key] = dict(f, first=now, last=now, count=1)
    return True


def _sev_rank(s):
    return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(s, 9)


def _added_lines(patch):
    return "\n".join(l[1:] for l in (patch or "").splitlines() if l.startswith("+") and not l.startswith("+++"))


def scan_workflow_text(text):
    """回傳 [(標籤, 嚴重度, 片段)]，片段截斷並遮掉看起來像 token 的長字串。"""
    hits = []
    for label, sev, rx in WF_PATTERNS:
        m = rx.search(text or "")
        if m:
            ln = text.count("\n", 0, m.start())
            line = (text.splitlines() or [""])[min(ln, len(text.splitlines()) - 1)].strip()
            line = re.sub(r"[A-Za-z0-9_\-]{24,}", lambda x: x.group(0)[:4] + "…", line)
            hits.append((label, sev, line[:140]))
    return hits


# ---------------------------------------------------------------------------------------------- 單一 repo
def _file_text(gh, full, path, ref):
    code, data, _ = gh.req("/repos/%s/contents/%s" % (full, urllib.parse.quote(path)), {"ref": ref})
    if code == 200 and isinstance(data, dict) and data.get("encoding") == "base64":
        try:
            return base64.b64decode(data.get("content", "")).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    return ""


def _scan_push(gh, st, owner_key, repo, ev, rst, now):
    """一次 push：有動到 workflow 的才深入看。回傳新警示數。"""
    full, default = repo["full_name"], repo.get("default_branch") or "main"
    pl = ev.get("payload") or {}
    ref = pl.get("ref") or ""
    branch = ref.replace("refs/heads/", "", 1)
    before, head = pl.get("before") or ZERO, pl.get("head") or ""
    actor = (ev.get("actor") or {}).get("login", "?")
    t = _ts(ev.get("created_at"))
    if not head or not ref.startswith("refs/heads/"):
        return 0
    new_branch = before == ZERO
    base = default if new_branch else before
    if new_branch and branch == default:
        return 0
    code, cmp, _ = gh.req("/repos/%s/compare/%s...%s" % (full, urllib.parse.quote(base, safe=""), head))
    if code != 200 or not isinstance(cmp, dict):
        return 0
    wf = [f for f in cmp.get("files") or [] if WF_PATH_RE.match(f.get("filename", ""))]
    st["recent"].append({"o": owner_key, "a": actor, "k": "push", "r": full, "t": t, "wf": bool(wf), "b": branch})
    if not wf:
        return 0
    created = 0
    url = "https://github.com/%s/commit/%s" % (full, head)
    hits = []
    for f in wf:
        text = _added_lines(f.get("patch"))
        if not text and f.get("status") in ("added", "modified", "renamed"):
            text = _file_text(gh, full, f["filename"], head)     # diff 太大時 API 不給 patch，改讀整個檔案
        for h in scan_workflow_text(text):
            hits.append((f["filename"],) + h)
    files = "、".join(sorted({f["filename"] for f in wf}))[:300]
    when = _local(t)
    if hits:
        rst.setdefault("bad_shas", {})[head] = t
        for c in (cmp.get("commits") or [])[-20:]:
            rst["bad_shas"][c.get("sha", "")] = t
        sev = "high" if any(h[2] == "high" for h in hits) else "medium"
        ev_txt = "\n".join("%s：%s｜%s" % (h[0], h[1], h[3]) for h in hits[:8])
        created += _alert(st, "gh-wf-exfil|%s" % full, now, rule="gh-wf-exfil", severity=sev, owner=owner_key,
                          title="%s：workflow 被加入可疑內容（%s）" % (full, "、".join(sorted({h[1] for h in hits}))[:120]),
                          path=url, evidence=ev_txt,
                          detail="%s 由 %s push 到分支 %s%s，改了 %s。" % (when, actor, branch, "（新分支）" if new_branch else "", files),
                          why="workflow 裡出現把機密或 runner token 送出去的寫法。只要這個版本被執行過一次，這個 repo 讀得到的所有機密（含組織機密）都要當作已外洩。",
                          fix="1. 到 Actions 看這個 commit 有沒有被執行（secaudit 也會自動檢查，執行過會另外列出）。\n"
                              "2. 執行過 → 立刻輪替這個 repo 讀得到的所有機密，並撤銷 push 者的 token / 授權。\n"
                              "3. 沒執行過 → 仍要確認 push 者帳號是否被盜，並把這段改動還原。")
    is_pr_merge = False
    if branch == default:
        code, prs, _ = gh.req("/repos/%s/commits/%s/pulls" % (full, head))
        is_pr_merge = code == 200 and bool(prs)
    if branch == default and not is_pr_merge:
        created += _alert(st, "gh-wf-direct|%s|%s" % (full, actor), now, rule="gh-wf-direct", severity="medium", owner=owner_key,
                          title="%s：%s 直接 push 到 %s 修改 workflow（沒有經過 PR）" % (full, actor, default),
                          path=url, detail="%s，改了 %s。" % (when, files),
                          why="workflow 決定 CI 能拿到哪些機密。不經過 PR 審核直接改，是這類攻擊最常見的入口。",
                          fix="確認是 %s 本人的改動。之後建議用 branch protection / ruleset 禁止直接 push 到 %s，並用 CODEOWNERS 要求 .github/workflows 的改動必須審核。" % (actor, default))
    elif new_branch:
        created += _alert(st, "gh-wf-branch|%s|%s" % (full, branch), now, rule="gh-wf-branch", severity="medium", owner=owner_key,
                          title="%s：新分支 %s 帶著 workflow 改動" % (full, branch), path=url,
                          detail="%s 由 %s 建立，改了 %s。push 到分支就會觸發 on: push 的 workflow，不需要合併。" % (when, actor, files),
                          why="攻擊者常推一個隨機名稱的分支，帶一個新的 workflow，push 一觸發就把機密送出去。",
                          fix="確認是誰、為什麼建這個分支；不認得就刪除分支並檢查它觸發過的執行紀錄。")
    # 改了又還原：同一個分支、同一個 workflow 檔，在 2 小時內被改回原樣
    ch = rst.setdefault("wf_changes", {})
    for f in wf:
        k = branch + "|" + f["filename"]
        prev = ch.get(k)
        if prev and 0 < t - prev["t"] < 7200 and prev["head"] != head:
            c2, cmp2, _ = gh.req("/repos/%s/compare/%s...%s" % (full, prev["before"], head))
            if c2 == 200 and isinstance(cmp2, dict) and f["filename"] not in {x.get("filename") for x in cmp2.get("files") or []}:
                rst.setdefault("bad_shas", {})[prev["head"]] = prev["t"]
                created += _alert(st, "gh-wf-flipflop|%s|%s" % (full, f["filename"]), now, rule="gh-wf-flipflop", severity="high",
                                  owner=owner_key, title="%s：workflow 改了又還原（%s）" % (full, f["filename"]),
                                  path="https://github.com/%s/compare/%s...%s" % (full, prev["before"][:12], head[:12]),
                                  detail="%s 改了 %s，%d 分鐘後又改回原樣（%s）。最後的內容看起來沒變，但中間那個版本可能已經被執行。" % (
                                      _local(prev["t"]), f["filename"], max(1, int((t - prev["t"]) / 60)), actor),
                                  why="正常開發很少這樣做；這是用來在 CI 跑一次惡意 workflow、再把痕跡蓋掉的手法。",
                                  fix="看中間那個 commit 的內容（上面的比較連結）與它觸發的執行紀錄；有執行過就輪替機密。")
                fkey = "gh-wf-flipflop|%s|%s" % (full, f["filename"])
                try:
                    res = assess_midversions(gh, full, f["filename"], prev["before"], head, branch=branch, mids=[prev["head"]])
                except _ApiError as e:
                    res = {"verdict": "unknown", "notes": ["查詢失敗：%s" % e], "runs": []}
                _apply_assessment(st, fkey, res, now)
            ch.pop(k, None)
        else:
            ch[k] = {"before": before if not new_branch else default, "head": head, "t": t}
    for k in [k for k, v in ch.items() if now - v["t"] > 86400]:
        ch.pop(k, None)
    return created


# ---------------------------------------------------------------------------------------------- 「改了又還原」中間版本有沒有被執行
def _glob_re(pat):
    """GitHub Actions 的 branches / paths 篩選語法：* 不跨 /，** 可跨 /，? 一個字元。"""
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**", i):
            out += ".*"; i += 2
        elif pat[i] == "*":
            out += "[^/]*"; i += 1
        elif pat[i] == "?":
            out += "."; i += 1
        else:
            out += re.escape(pat[i]); i += 1
    return re.compile("^" + out + "$")


def _filter_ok(name, include, exclude):
    """include / exclude 都是 pattern 清單；include 裡的 !pattern 是排除。"""
    if include is not None:
        ok = False
        for pat in include if isinstance(include, list) else [include]:
            pat = str(pat)
            if pat.startswith("!"):
                if _glob_re(pat[1:]).match(name):
                    ok = False
            elif _glob_re(pat).match(name):
                ok = True
        return ok
    if exclude is not None:
        return not any(_glob_re(str(x)).match(name) for x in (exclude if isinstance(exclude, list) else [exclude]))
    return True


def workflow_triggers(text, branch, changed_files):
    """回傳 (push 到 branch 會不會觸發：True / False / None=無法判斷, 其他能觸發它的事件, 說明)。"""
    try:
        import yaml
        y = yaml.safe_load(text or "")
    except Exception as e:          # noqa: BLE001 — 解析失敗就當成無法判斷
        return None, [], "workflow 解析失敗（%s）" % type(e).__name__
    if not isinstance(y, dict):
        return None, [], "workflow 內容不是 YAML 物件"
    on = y.get("on", y.get(True))   # YAML 1.1 會把 on 解析成 True
    if on is None:
        return None, [], "workflow 沒有 on: 設定"
    if isinstance(on, str):
        on = {on: None}
    elif isinstance(on, list):
        on = {str(k): None for k in on}
    elif not isinstance(on, dict):
        return None, [], "無法解析 on: 設定"
    others = [k for k in on if k != "push"]
    if "push" not in on:
        return False, others, "沒有 on: push，push 不會觸發"
    cfg = on.get("push") or {}
    if not isinstance(cfg, dict):
        return True, others, "on: push（所有分支）"
    has_b = "branches" in cfg or "branches-ignore" in cfg
    has_t = "tags" in cfg or "tags-ignore" in cfg
    if has_t and not has_b:
        return False, others, "on: push 只篩選 tag（%s），push 到分支不會觸發" % ", ".join(map(str, cfg.get("tags") or cfg.get("tags-ignore") or []))[:80]
    if has_b and not _filter_ok(branch, cfg.get("branches"), cfg.get("branches-ignore")):
        return False, others, "on: push 的 branches 篩選（%s）不包含 %s" % (", ".join(map(str, cfg.get("branches") or ["!" + str(x) for x in cfg.get("branches-ignore") or []]))[:80], branch)
    if "paths" in cfg or "paths-ignore" in cfg:
        if changed_files is None:
            return None, others, "on: push 有 paths 篩選，不確定這次的改動是否符合"
        if not any(_filter_ok(f, cfg.get("paths"), cfg.get("paths-ignore")) for f in changed_files):
            return False, others, "on: push 的 paths 篩選不包含這次改的檔案"
    return True, others, "on: push 會觸發（分支 %s）" % branch


def _run_gaps(runs):
    """同一個 workflow 的執行編號缺號（代表有執行紀錄被刪除）。"""
    by = {}
    for r in runs:
        by.setdefault(r.get("workflow_id"), set()).add(int(r.get("run_number") or 0))
    gaps = []
    for nums in by.values():
        ns = sorted(nums)
        gaps += [n for a, b in zip(ns, ns[1:]) for n in range(a + 1, b)]
    return gaps


def assess_midversions(gh, full, filename, before, head, branch=None, mids=None):
    """判斷「改了又還原」的中間版本實際上有沒有被執行。
    依據：(1) 執行紀錄 head_sha (2) 中間版本是不是單獨被 push 成分支的最新 commit
    (3) 中間版本 workflow 的觸發條件 (4) Actions 是否開啟 (5) 前後的執行編號有沒有缺號。
    回傳 {verdict: executed / not_triggered / no_run / unknown, notes: [...], runs: [...]}"""
    notes, runs_found = [], []
    code, repo, _ = gh.req("/repos/%s" % full)
    default = (repo or {}).get("default_branch", "main") if code == 200 else "main"
    pushed = {}             # 被單獨 push 成分支最新 commit 的 sha → ref
    if mids is None or branch is None:
        # 不依賴偵測時記下的那一組：把這個檔案最近 30 天的所有版本拿出來，內容和還原後不一樣的都算中間版本
        c, cmp, _ = gh.req("/repos/%s/compare/%s...%s" % (full, before, head))
        if c != 200 or not isinstance(cmp, dict):
            return {"verdict": "unknown", "notes": notes + ["讀不到 commit 比較（HTTP %s）。" % c], "runs": []}
        restored = before if cmp.get("status") == "behind" else head        # 比較晚的那個才是還原後的版本
        c, act, _ = gh.req("/repos/%s/activity" % full, {"per_page": 100, "time_period": "quarter"})
        act = act if c == 200 and isinstance(act, list) else None
        if branch is None:
            c, br, _ = gh.req("/repos/%s/commits/%s/branches-where-head" % (full, restored))
            branch = next((b.get("name") for b in br or [] if isinstance(b, dict)), None) if c == 200 else None
            if branch is None and act:
                branch = next((a.get("ref", "").replace("refs/heads/", "", 1) for a in act
                               if (a.get("after") or "").startswith(restored)), None)
            branch = branch or default
        try:
            hist = gh.pages("/repos/%s/commits" % full, {"path": filename, "sha": branch,
                                                         "since": _iso(time.time() - 30 * 86400)}, maxpages=1)
        except _ApiError as e:
            return {"verdict": "unknown", "notes": notes + ["讀不到檔案歷史：%s" % e], "runs": []}
        final = _file_text(gh, full, filename, restored)
        cand = []
        for cm in hist[:15]:
            sha = cm.get("sha", "")
            if sha and not sha.startswith(restored) and _file_text(gh, full, filename, sha) != final:
                cand.append(sha)
        if not cand:
            return {"verdict": "unknown", "notes": notes + ["在 %s 分支最近 30 天的歷史裡找不到和還原後不同的版本。" % branch], "runs": [], "branch": branch}
        if act is None:
            mids = cand
            notes.append("讀不到 repo activity，無法確認每個中間版本是不是單獨被 push，全部當成可能被觸發。")
        else:
            heads = {a.get("after") for a in act}
            mids = [x for x in cand if x in heads]
            if len(mids) < len(cand):
                notes.append("%d 個中間版本沒有被單獨 push（和後面的 commit 一起送上來），push 不會用那些版本觸發 workflow。" % (len(cand) - len(mids)))
            if mids:
                notes.append("%d 個中間版本是單獨被 push 成 %s 的最新 commit（%s%s）。" % (
                    len(mids), branch, "、".join(x[:8] for x in mids[:6]), "…" if len(mids) > 6 else ""))
    else:
        notes.append("中間版本是單獨一次 push 送上 %s 的。" % branch)
    if not mids:
        return {"verdict": "not_triggered", "notes": notes + ["中間版本從來不是分支的最新 commit，不會被 push 觸發。"], "runs": []}
    c, perm, _ = gh.req("/repos/%s/actions/permissions" % full)
    if c == 200 and isinstance(perm, dict) and perm.get("enabled") is False:
        notes.append("這個 repo 的 Actions 是關閉的。")
    trig_states, trig_notes = [], {}
    for sha in mids:
        c, rr, _ = gh.req("/repos/%s/actions/runs" % full, {"head_sha": sha, "per_page": 20})
        for r in (rr or {}).get("workflow_runs") or [] if c == 200 else []:
            runs_found.append("%s #%s %s（%s，%s，%s）" % (_local(_ts(r.get("created_at"))), r.get("run_number"), r.get("name", ""),
                                                      r.get("event", ""), r.get("conclusion") or r.get("status", ""),
                                                      (r.get("actor") or {}).get("login", "")))
        text = _file_text(gh, full, filename, sha)
        c2, cm, _ = gh.req("/repos/%s/commits/%s" % (full, sha))
        changed = [f.get("filename") for f in (cm or {}).get("files") or []] if c2 == 200 else None
        trig, others, why = workflow_triggers(text, branch, changed)
        trig_states.append(trig)
        o = [x for x in others if x in ("workflow_dispatch", "repository_dispatch", "schedule", "workflow_run", "pull_request_target", "pull_request", "issue_comment")]
        trig_notes.setdefault(why + ("；另外可由 %s 觸發（查無對應執行）" % "、".join(o) if o else ""), []).append(sha[:8])
    for why, shas in trig_notes.items():
        notes.append("%s：%s" % ("、".join(shas) if len(shas) <= 3 else "%d 個中間版本都是" % len(shas), why))
    c, rr, _ = gh.req("/repos/%s/actions/runs" % full, {"per_page": 1})
    total = (rr or {}).get("total_count") if c == 200 else None
    if runs_found:
        verdict = "executed"
    elif total == 0:
        notes.append("這個 repo 完全沒有執行紀錄（也可能全部被刪除，無法用缺號判斷）。")
        verdict = "not_triggered" if all(t is False for t in trig_states) else "no_run"
    else:
        # 只看這個 workflow 檔自己的執行（不分分支 / tag）：tag 觸發的執行不算在分支底下，用分支篩選會誤判成缺號
        wid = None
        c, wf, _ = gh.req("/repos/%s/actions/workflows/%s" % (full, urllib.parse.quote(filename.rsplit("/", 1)[-1])))
        if c == 200 and isinstance(wf, dict):
            wid = wf.get("id")
        try:
            near = gh.pages("/repos/%s/actions/workflows/%s/runs" % (full, wid), {}, maxpages=2) if wid else []
        except _ApiError:
            near = []
        gaps = _run_gaps(near)
        if gaps:
            notes.append("這個 workflow 的執行編號有缺號（%s），可能有紀錄被刪除。" % "、".join("#%d" % n for n in gaps[:10]))
        elif wid and not near:
            notes.append("這個 workflow 沒有任何執行紀錄。")
        verdict = "not_triggered" if all(t is False for t in trig_states) and not gaps else "no_run"
    return {"verdict": verdict, "notes": notes, "runs": runs_found, "mids": [m[:8] for m in mids], "branch": branch}


VERDICT_TEXT = {
    "executed": ("high", "已執行"),
    "not_triggered": ("medium", "沒有被執行"),
    "no_run": ("high", "沒有執行紀錄，但無法排除"),
    "unknown": ("high", "無法判斷"),
}


def _apply_assessment(st, key, res, now):
    with _st_lock:
        a = st["alerts"].get(key)
        if not a:
            return
        sev, label = VERDICT_TEXT.get(res["verdict"], VERDICT_TEXT["unknown"])
        base_detail = (a.get("detail") or "").split("\n判斷：", 1)[0]
        base_title = re.sub(r"（判斷：[^）]*）$", "", a.get("title", ""))
        lines = ["判斷：" + label] + ["・" + n for n in res["notes"]]
        if res["runs"]:
            lines += ["・中間版本觸發的執行："] + ["  " + r for r in res["runs"][:10]]
        if res["verdict"] == "executed":
            lines.append("・這個 repo 讀得到的機密要當作已外洩。")
        elif res["verdict"] == "not_triggered":
            lines.append("・仍要確認 push 者帳號是否被盜；組織 audit log（Settings → Audit log，搜尋 action:workflows）可以確認沒有被刪除的執行。")
        else:
            lines.append("・到組織 audit log（Settings → Audit log）搜尋 repo:%s action:workflows，確認有沒有被刪除的執行。" % key.split("|")[1])
        a.update(severity=sev, title=base_title + "（判斷：%s）" % label, detail=base_detail + "\n" + "\n".join(lines),
                 assess={"verdict": res["verdict"], "at": now})


def reassess_flipflops(gh, st, owner_key, now, limit=30):
    """補判斷還沒判斷過的「改了又還原」警示（包含功能上線前就存在的）。回傳判斷了幾筆。"""
    todo = [k for k, a in st["alerts"].items() if a.get("rule") == "gh-wf-flipflop" and a.get("owner") == owner_key and not a.get("assess")]
    n = 0
    for key in todo[:limit]:
        if gh.low():
            break
        a = st["alerts"][key]
        _, full, filename = key.split("|", 2)
        m = re.search(r"/compare/([0-9a-f]+)\.\.\.([0-9a-f]+)", a.get("path") or "")
        if not m:
            continue
        try:
            res = assess_midversions(gh, full, filename, m.group(1), m.group(2))
        except _ApiError as e:
            res = {"verdict": "unknown", "notes": ["查詢失敗：%s" % e], "runs": []}
        _apply_assessment(st, key, res, now)
        n += 1
    return n


def _scan_runs(gh, st, owner_key, repo, rst, since, now):
    """這段時間的 workflow 執行：可疑 commit 是否被執行、執行紀錄是否被刪除。"""
    full = repo["full_name"]
    try:
        runs = gh.pages("/repos/%s/actions/runs" % full, {"created": ">=" + _iso(since - 600)}, maxpages=5)
    except _ApiError:
        return 0
    created = 0
    bad = rst.get("bad_shas", {})
    # 直接讀「當次執行的那個版本」的 workflow 檔來掃：事件 API 會漏（分支刪掉後連 push 事件都可能不見），
    # 但用執行時的 commit 還讀得到檔案內容，可以確定實際跑的是不是惡意版本。同一個檔案 + commit 只讀一次。
    seen_wf = rst.setdefault("wf_scanned", {})
    for r in runs:
        path, sha = r.get("path") or "", r.get("head_sha") or ""
        if not path.startswith(".github/workflows/") or not sha or sha in bad:
            continue
        k = path + "@" + sha
        if k not in seen_wf:
            if gh.low():
                break
            hits = [h for h in scan_workflow_text(_file_text(gh, full, path.split("@")[0], sha)) if h[1] == "high"]
            seen_wf[k] = [now, "；".join(h[0] for h in hits)]
        if seen_wf[k][1]:
            bad[sha] = now
            r["_why"] = seen_wf[k][1]
    rst["bad_shas"] = bad
    for k in [k for k, v in seen_wf.items() if now - v[0] > 7 * 86400]:
        seen_wf.pop(k, None)
    alerted = rst.setdefault("alerted_runs", {})
    hit = [r for r in runs if r.get("head_sha") in bad and str(r.get("id")) not in alerted]
    for r in hit:
        alerted[str(r.get("id"))] = now
    for k in [k for k, v in alerted.items() if now - v > 40 * 86400]:
        alerted.pop(k, None)
    if hit:
        prev_a = st["alerts"].get("gh-run-executed|%s" % full) or {}
        old_shas = re.findall(r"[0-9a-f]{8}", (prev_a.get("detail") or "").split("。")[0])
        old_lines = [l for l in (prev_a.get("evidence") or "").split("\n") if l]
        shas = sorted({r["head_sha"][:8] for r in hit} | set(old_shas))
        lines = ["%s %s（%s，分支 %s，%s，%s 觸發）%s" % (
            _local(_ts(r.get("created_at"))), r.get("name"), r.get("event"), r.get("head_branch"), r.get("conclusion") or r.get("status"),
            (r.get("triggering_actor") or {}).get("login", "?"), ("｜" + r["_why"][:80]) if r.get("_why") else "") for r in hit[:15]]
        lines = lines + [l for l in old_lines if l not in lines]
        created += _alert(st, "gh-run-executed|%s" % full, now, rule="gh-run-executed", severity="high", owner=owner_key,
                          title="%s：可疑的 workflow 已經執行（%d 次）" % (full, len(lines)),
                          path="https://github.com/%s/actions" % full, evidence="\n".join(lines[:30]),
                          detail="被執行的 commit：%s。執行結果是失敗也一樣：惡意步驟通常放在最前面，失敗不代表沒送出去。" % "、".join(shas),
                          why="這個 repo 讀得到的機密（repo、environment、所有開放給它的組織機密）與當次的 GITHUB_TOKEN 都要當作已外洩。",
                          fix="1. 立刻輪替這個 repo 讀得到的所有機密（先雲端金鑰與資料庫密碼）。\n2. 撤銷 push 者的 token 與 OAuth 授權，請他檢查自己的電腦。\n"
                              "3. 用雲端的稽核紀錄（AWS CloudTrail 等）查這段時間之後有沒有異常使用。")
    # 執行紀錄被刪除：同一個 workflow 的 run_number 應該連續
    seen = rst.setdefault("run_max", {})
    by = {}
    for r in runs:
        by.setdefault(str(r.get("workflow_id")), set()).add(int(r.get("run_number") or 0))
    for wid, nums in by.items():
        prev = seen.get(wid)
        top = max(nums)
        if prev is not None and top > prev:
            missing = [n for n in range(prev + 1, top) if n not in nums]
            if missing:
                name = next((r.get("name") for r in runs if str(r.get("workflow_id")) == wid), wid)
                created += _alert(st, "gh-run-deleted|%s|%s" % (full, wid), now, rule="gh-run-deleted", severity="medium",
                                  owner=owner_key, title="%s：「%s」有 %d 筆執行紀錄不見了" % (full, name, len(missing)),
                                  path="https://github.com/%s/actions" % full,
                                  detail="執行編號 %s 不見了（只有有寫入權限的人能刪除執行紀錄）。" % "、".join("#%d" % n for n in missing[:20]),
                                  why="刪除執行紀錄可以把惡意 workflow 的 log 蓋掉。",
                                  fix="到組織的 audit log 搜尋 workflows.delete_workflow_run，確認是誰刪的。")
        seen[wid] = max(top, prev or 0)
    return created


def _scan_repo(gh, st, owner_key, repo, ost, since, now):
    full = repo["full_name"]
    rst = ost.setdefault("repos", {}).setdefault(full, {})
    last_id = int(rst.get("last_event", 0))
    try:
        evs = gh.pages("/repos/%s/events" % full, {}, maxpages=3,
                       stop=lambda e: int(e.get("id", 0)) <= last_id or _ts(e.get("created_at")) < since - 600)
    except _ApiError:
        return 0
    evs = [e for e in evs if int(e.get("id", 0)) > last_id and _ts(e.get("created_at")) >= since - 600]
    evs.sort(key=lambda e: int(e["id"]))
    created = 0
    for ev in evs:
        typ, actor = ev.get("type"), (ev.get("actor") or {}).get("login", "?")
        pl, t = ev.get("payload") or {}, _ts(ev.get("created_at"))
        if typ == "PushEvent":
            created += _scan_push(gh, st, owner_key, repo, ev, rst, now)
        elif typ == "PullRequestEvent" and pl.get("action") == "opened":
            pr = pl.get("pull_request") or {}
            st["recent"].append({"o": owner_key, "a": actor, "k": "pr", "r": full, "t": t, "title": (pr.get("title") or "")[:120]})
        elif typ == "MemberEvent" and pl.get("action") == "added":
            m = (pl.get("member") or {}).get("login", "?")
            created += _alert(st, "gh-member|%s|%s" % (full, m), now, rule="gh-member", severity="medium", owner=owner_key,
                              title="%s：新增協作者 %s" % (full, m), path="https://github.com/%s/settings/access" % full,
                              detail="%s 由 %s 加入。" % (_local(t), actor), why="攻擊者拿到權限後常加自己的帳號當協作者，token 被撤銷後還能回來。",
                              fix="確認認得 %s；不認得就移除，並檢查 %s 的帳號。" % (m, actor))
        elif typ == "PublicEvent":
            created += _alert(st, "gh-public|%s" % full, now, rule="gh-public", severity="high", owner=owner_key,
                              title="%s：repo 被改成公開" % full, path="https://github.com/" + full,
                              detail="%s 由 %s 改成公開。" % (_local(t), actor), why="私有程式碼與 commit 歷史裡的機密會被任何人看到。",
                              fix="不是刻意公開就立刻改回私有，並把歷史裡出現過的機密全部輪替。")
        rst["last_event"] = max(int(rst.get("last_event", 0)), int(ev["id"]))
    created += _scan_runs(gh, st, owner_key, repo, rst, since, now)
    for k in [k for k, v in (rst.get("bad_shas") or {}).items() if now - v > 7 * 86400]:
        rst["bad_shas"].pop(k, None)
    return created


# ---------------------------------------------------------------------------------------------- 跨 repo 的集體行為
def _mass(st, owner_key, now):
    rec = [r for r in st["recent"] if r["o"] == owner_key and now - r["t"] < 7200]
    created = 0
    by_wf, by_pr = {}, {}
    for r in rec:
        if BOT_RE.search(r["a"]):
            continue
        if r["k"] == "push" and r.get("wf"):
            by_wf.setdefault(r["a"], set()).add(r["r"])
        if r["k"] == "pr":
            by_pr.setdefault((r["a"], r.get("title", "")), set()).add(r["r"])
    org = owner_key.split("/", 1)[1]
    for a, repos in by_wf.items():
        if len(repos) >= 3:
            created += _alert(st, "gh-mass-wf|%s|%s|%s" % (owner_key, a, time.strftime("%Y%m%d", time.localtime(now))), now,
                              rule="gh-mass-wf", severity="high", owner=owner_key,
                              title="%s：%s 在 2 小時內改了 %d 個 repo 的 workflow" % (org, a, len(repos)),
                              path="https://github.com/" + org, evidence="\n".join(sorted(repos)[:40]),
                              why="同一個帳號短時間內大量修改 workflow，很可能是 token 外流後的自動化攻擊。",
                              fix="立刻確認 %s 本人有沒有在做這件事；不是的話先把他移出組織 / 撤銷 token，再逐一檢查這些 repo。" % a)
    for (a, title), repos in by_pr.items():
        if len(repos) >= 5:
            created += _alert(st, "gh-mass-pr|%s|%s|%s" % (owner_key, a, title[:60]), now, rule="gh-mass-pr", severity="high",
                              owner=owner_key, title="%s：%s 在 2 小時內對 %d 個 repo 開了同樣的 PR（%s）" % (org, a, len(repos), title[:60]),
                              path="https://github.com/pulls?q=is%%3Apr+author%%3A%s+org%%3A%s" % (a, org),
                              evidence="\n".join(sorted(repos)[:40]),
                              why="攻擊者常先對所有 repo 開一個無害的 PR，探測哪些 repo 有寫入權限。",
                              fix="確認 %s 本人有沒有在做這件事；不是的話撤銷他的權限，關掉這些 PR、刪掉 PR 的分支。" % a)
    st["recent"] = [r for r in st["recent"] if now - r["t"] < 6 * 3600]
    return created


# ---------------------------------------------------------------------------------------------- 每天一次的設定稽核
def _audit(gh, st, owner_key, owner, is_org, repos, ost, now):
    created = 0
    base = ost.setdefault("audit", {})
    first = not base
    org_url = "https://github.com/" + owner

    def diff_set(name, cur, rule, sev, title_fn, why, fix, url):
        nonlocal created
        old = set(base.get(name) or [])
        if name in base and not first:
            for x in sorted(set(cur) - old):
                created += _alert(st, "%s|%s|%s" % (rule, owner, x), now, rule=rule, severity=sev, owner=owner_key,
                                  title=title_fn(x), path=url, why=why, fix=fix)
        base[name] = sorted(cur)

    if is_org:
        try:
            diff_set("members", [m["login"] for m in gh.pages("/orgs/%s/members" % owner, maxpages=10)],
                     "gh-org-member", "medium", lambda x: "%s：組織新增成員 %s" % (owner, x),
                     "攻擊者拿到 admin 權限後會加自己的帳號，token 被撤銷後還能回來。", "確認認得這個帳號。", org_url + "/people")
        except _ApiError:
            pass
        try:
            diff_set("outside", [m["login"] for m in gh.pages("/orgs/%s/outside_collaborators" % owner, maxpages=10)],
                     "gh-org-outside", "medium", lambda x: "%s：新增外部協作者 %s" % (owner, x),
                     "外部協作者不在組織的成員管理裡，容易被忽略。", "確認認得這個帳號、確認他能存取哪些 repo。", org_url + "/people")
        except _ApiError:
            pass
        try:
            secs = gh.pages("/orgs/%s/actions/secrets" % owner, maxpages=5)
            allv = [s["name"] for s in secs if s.get("visibility") == "all"]
            key = "gh-posture-secrets|%s" % owner
            if allv:
                _alert(st, key, now, rule="gh-posture-secrets", severity="low", owner=owner_key,
                       title="%s：%d 個組織機密開放給所有 repo" % (owner, len(allv)), path=org_url + "/settings/secrets/actions",
                       evidence="、".join(allv[:30]),
                       why="任何一個 repo 的 workflow 被改，就能拿到這些機密。", fix="改成 Selected repositories，只開給真正需要的 repo；雲端金鑰改用 OIDC。")
            else:
                st["alerts"].pop(key, None)
        except _ApiError:
            pass
    vis = {r["full_name"]: r.get("private") for r in repos}
    old_vis = base.get("private") or {}
    for full, priv in vis.items():
        if old_vis.get(full) is True and priv is False:
            created += _alert(st, "gh-public|%s" % full, now, rule="gh-public", severity="high", owner=owner_key,
                              title="%s：repo 被改成公開" % full, path="https://github.com/" + full,
                              why="私有程式碼與 commit 歷史裡的機密會被任何人看到。", fix="不是刻意公開就改回私有，並輪替歷史裡的機密。")
    base["private"] = vis
    unprotected, hooks, keys = [], {}, {}

    def one(r):
        if r.get("archived") or gh.low():
            return
        full = r["full_name"]
        code, b, _ = gh.req("/repos/%s/branches/%s" % (full, urllib.parse.quote(r.get("default_branch") or "main", safe="")))
        if code == 200 and isinstance(b, dict) and not b.get("protected"):
            unprotected.append(full)
        if (r.get("permissions") or {}).get("admin"):
            c1, hs, _ = gh.req("/repos/%s/hooks" % full)
            if c1 == 200 and isinstance(hs, list):
                hooks[full] = sorted("%s" % (h.get("config") or {}).get("url", "?") for h in hs)
            c2, ks, _ = gh.req("/repos/%s/keys" % full)
            if c2 == 200 and isinstance(ks, list):
                keys[full] = sorted("%s%s" % (k.get("title", "?"), "（可寫入）" if not k.get("read_only") else "") for k in ks)
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(one, repos))
    unprotected.sort()
    for name, cur, rule, label in (("hooks", hooks, "gh-hook", "webhook"), ("keys", keys, "gh-deploykey", "deploy key")):
        old = base.get(name)
        if old is not None:
            for full, items in cur.items():
                for x in sorted(set(items) - set(old.get(full, []))):
                    if full not in old:
                        continue        # 這次才有權限讀到的 repo 當作基準
                    created += _alert(st, "%s|%s|%s" % (rule, full, x), now, rule=rule, severity="high" if rule == "gh-hook" else "medium",
                                      owner=owner_key, title="%s：新增 %s（%s）" % (full, label, x[:80]),
                                      path="https://github.com/%s/settings/%s" % (full, "hooks" if rule == "gh-hook" else "keys"),
                                      why="webhook 會把每次 push 的內容送到外部；可寫入的 deploy key 能繞過帳號直接 push。",
                                      fix="確認是誰加的、要送到哪裡；不認得就刪除。")
        base[name] = dict(old or {}, **cur)
    key = "gh-posture-protect|%s" % owner_key
    if unprotected:
        _alert(st, key, now, rule="gh-posture-protect", severity="low", owner=owner_key,
               title="%s：%d 個 repo 的預設分支沒有保護" % (owner, len(unprotected)), path=org_url,
               evidence="\n".join(unprotected[:40]),
               why="有寫入權限的人（或外流的 token）能直接 push 到預設分支、修改 workflow，不需要任何人審核。",
               fix="用組織的 ruleset 一次套用：禁止直接 push、要求 PR 審核、.github/workflows 加 CODEOWNERS。")
        st["alerts"][key].update(title="%s：%d 個 repo 的預設分支沒有保護" % (owner, len(unprotected)),
                                 evidence="\n".join(unprotected[:40]))
    else:
        st["alerts"].pop(key, None)
    base["at"] = now
    return created


# ---------------------------------------------------------------------------------------------- 主流程
def _repos(gh, owner, login, is_org, since):
    if is_org:
        path, params = "/orgs/%s/repos" % owner, {"type": "all", "sort": "pushed", "direction": "desc"}
    elif owner.lower() == login.lower():
        path, params = "/user/repos", {"affiliation": "owner", "sort": "pushed", "direction": "desc"}
    else:
        path, params = "/users/%s/repos" % owner, {"sort": "pushed", "direction": "desc"}
    stop = (lambda r: _ts(r.get("pushed_at")) < since - 600) if since else None
    return gh.pages(path, params, maxpages=20, stop=stop)


def poll(cfg, force_audit=False, progress=None):
    """檢查一輪。回傳 {"new": 新警示數, "errors": [...], ...}。同一時間只跑一個。"""
    if not _lock.acquire(blocking=False):
        return {"busy": True}
    try:
        gw = cfg.get("github_watch") or {}
        st = _load()
        now = time.time()
        new, errors, summary = 0, [], []
        for acc in gw.get("accounts") or []:
            login = acc.get("login", "")
            if not acc.get("enabled", True) or not NAME_RE.match(login):
                continue
            tok = _token(login)
            if not tok:
                errors.append("%s：拿不到 token（先執行 gh auth login，或設定 GH_TOKEN_%s）" % (login, re.sub(r"\W", "_", login).upper()))
                continue
            gh = GH(tok)
            for owner in acc.get("owners") or []:
                if not NAME_RE.match(owner):
                    continue
                key = "%s/%s" % (login, owner)
                ost = st["owners"].setdefault(key, {})
                if progress:
                    progress("GitHub 監控", key)
                try:
                    if "is_org" not in ost:
                        code, u, _ = gh.req("/users/" + owner)
                        if code != 200:
                            raise _ApiError(code, u)
                        ost["is_org"] = (u or {}).get("type") == "Organization"
                    since = ost.get("last_poll") or now - FIRST_LOOKBACK_H * 3600
                    audit_due = force_audit or now - (ost.get("audit") or {}).get("at", 0) > AUDIT_EVERY_H * 3600
                    repos = _repos(gh, owner, login, ost["is_org"], None if audit_due else since)
                    changed = [r for r in repos if _ts(r.get("pushed_at")) >= since - 600]
                    n0 = new
                    ost.setdefault("repos", {})
                    for r in changed:
                        ost["repos"].setdefault(r["full_name"], {})

                    def one(r):
                        return 0 if gh.low() else _scan_repo(gh, st, key, r, ost, since, now)
                    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
                        new += sum(ex.map(one, changed))
                    if gh.low():
                        errors.append("%s：API 額度快用完，剩下的下次再檢查" % key)
                    new += _mass(st, key, now)
                    if audit_due and not gh.low():
                        new += _audit(gh, st, key, owner, ost["is_org"], repos, ost, now)
                    if not gh.low():
                        reassess_flipflops(gh, st, key, now)
                    if not gh.low():
                        n_ok = autoresolve(gh, st, key, now)
                        if n_ok:
                            summary.append("%s：自動確認 %d 筆警示已處理完畢" % (key, n_ok))
                    if not gh.low():
                        ost["last_poll"] = now
                    ost["last_ok"] = now
                    ost["repos_seen"] = len(repos) if audit_due else ost.get("repos_seen", len(repos))
                    ost.pop("error", None)
                    summary.append("%s：%d 個 repo 有新動態，新警示 %d" % (key, len(changed), new - n0))
                except _ApiError as e:
                    ost["error"] = str(e)
                    errors.append("%s：%s" % (key, e))
                except (OSError, ValueError) as e:
                    ost["error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
                    errors.append("%s：%s" % (key, ost["error"]))
        for k in [k for k, a in st["alerts"].items() if now - a.get("last", 0) > ALERT_KEEP_DAYS * 86400]:
            st["alerts"].pop(k, None)
        active = {"%s/%s" % (a.get("login"), o) for a in gw.get("accounts") or [] for o in a.get("owners") or []}
        for k in [k for k in st["owners"] if k not in active]:
            st["owners"].pop(k, None)
        st["status"] = {"at": now, "new": new, "errors": errors, "summary": summary}
        _save(st)
        return st["status"]
    finally:
        _lock.release()


# ---------------------------------------------------------------------------------------------- 處理狀態（自動檢查 + 手動標記）
# 手動標記存在另一個檔案：輪詢執行緒會整份重寫 ghwatch.json，分開存才不會被蓋掉。
# 標記綁定當時警示的 last；之後同一個 key 又有新事件（last 變大），標記自動失效、警示重新出現。
MARKS = os.path.join(DATA, "ghwatch_marks.json")
RESOLVE_RECHECK_H = 6
AUTO_CALL_BUDGET = 1500        # 每輪自動檢查最多用多少 API 呼叫，避免把額度吃光
MANUAL_ONLY = {"gh-run-executed": "已經執行過：機密要當作已外洩。輪替這個 repo 讀得到的機密後，請手動標記「已處理」。",
               "gh-run-deleted": "執行紀錄被刪除無法自動確認，請到組織 audit log 確認後手動標記。",
               "gh-org-member": "請確認這個成員是否應該在組織裡，再手動標記。",
               "gh-org-outside": "請確認這個外部協作者是否應該存在，再手動標記。",
               "gh-hook": "請確認這個 webhook 的目的地，再手動標記。",
               "gh-deploykey": "請確認這把 deploy key 的用途，再手動標記。"}


def load_marks():
    try:
        with open(MARKS, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_marks(m):
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    tmp = MARKS + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(m, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, MARKS)


def mark(key, kind, note=""):
    """kind：fixed（已處理）/ false_positive（誤判）/ reopen（撤銷標記）。回傳 (成功, 訊息)。"""
    st = _load()
    a = st["alerts"].get(key)
    m = load_marks()
    if kind == "reopen":
        m.pop(key, None)
        save_marks(m)
        if a and a.get("auto_resolved"):
            # 自動判定也一起撤銷，並在下次自動檢查前不再自動判定
            m["__noauto__" + key] = {"at": time.time()}
            save_marks(m)
        return True, "已撤銷標記"
    if not a:
        return False, "找不到這筆警示"
    if kind not in ("fixed", "false_positive"):
        return False, "kind 不正確"
    m[key] = {"kind": kind, "note": str(note or "")[:300], "at": time.time(), "alert_last": a.get("last", 0),
              "title": a.get("title", "")[:200]}
    m.pop("__noauto__" + key, None)
    save_marks(m)
    return True, "已標記"


def alert_state(key, a, marks):
    """回傳 (狀態, 資訊)：狀態是 None（未處理）/ manual / auto。"""
    m = marks.get(key)
    if m and a.get("last", 0) <= m.get("alert_last", 0) + 1:
        return "manual", m
    r = a.get("auto_resolved")
    if r and a.get("last", 0) <= r.get("alert_last", 0) + 1 and ("__noauto__" + key) not in marks:
        return "auto", r
    return None, None


_PAT_VER = hashlib.sha1("".join(p[2].pattern for p in WF_PATTERNS).encode()).hexdigest()[:10]


def _repo_wf_scan(gh, st, full):
    """所有分支的 .github/workflows 目前的內容有沒有可疑寫法。回傳 (分支清單, [(分支, 檔案, [規則])]) 或 None（讀取失敗）。
    同樣內容（blob sha）只掃一次。"""
    if st.get("blob_scan_ver") != _PAT_VER:
        st["blob_scan"], st["blob_scan_ver"] = {}, _PAT_VER
    cache = st["blob_scan"]
    try:
        names = [b.get("name") for b in gh.pages("/repos/%s/branches" % full, maxpages=3)]
    except _ApiError:
        return None
    bad = []
    for b in names:
        c, lst, _ = gh.req("/repos/%s/contents/.github/workflows" % full, {"ref": b})
        if c == 404:
            continue
        if c != 200 or not isinstance(lst, list):
            return None
        for f in lst:
            if f.get("type") != "file" or not re.search(r"\.ya?ml$", f.get("name", "")):
                continue
            sha = f.get("sha", "")
            if sha not in cache:
                c2, blob, _ = gh.req("/repos/%s/git/blobs/%s" % (full, sha))
                if c2 != 200 or not isinstance(blob, dict):
                    return None
                try:
                    text = base64.b64decode(blob.get("content", "")).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    text = ""
                cache[sha] = sorted({h[0] for h in scan_workflow_text(text) if h[1] == "high"})
            if cache[sha]:
                bad.append((b, f.get("path", ""), cache[sha]))
    if len(cache) > 20000:
        for k in list(cache)[:5000]:
            cache.pop(k, None)
    return names, bad


def _bad_text(bad, limit=5):
    return "；".join("%s：%s（%s）" % (b, p, "、".join(r)) for b, p, r in bad[:limit]) + ("…" if len(bad) > limit else "")


def _check_one(gh, st, key, a, scans):
    """回傳 (是否已處理, 說明)。None 表示這次無法判斷。"""
    rule = a.get("rule", "")
    parts = key.split("|")
    full = parts[1] if len(parts) > 1 and "/" in parts[1] else ""

    def scan():
        if full not in scans:
            scans[full] = _repo_wf_scan(gh, st, full)
        return scans[full]

    if rule in MANUAL_ONLY and rule != "gh-run-executed":
        return False, MANUAL_ONLY[rule]
    if rule == "gh-run-executed":
        # 用目前的規則重新掃當次執行的 workflow；規則修正後（例如排除本機 IP）誤判會在這裡被清掉
        shas = re.findall(r"[0-9a-f]{8}", (a.get("detail") or "").split("。")[0])
        any_hit = False
        for sh in shas:
            c, cm, _ = gh.req("/repos/%s/commits/%s" % (full, sh))
            if c != 200:
                return None
            c, rr, _ = gh.req("/repos/%s/actions/runs" % full, {"head_sha": cm["sha"], "per_page": 20})
            if c != 200:
                return None
            for r in (rr or {}).get("workflow_runs") or []:
                path = (r.get("path") or "").split("@")[0]
                if path.startswith(".github/workflows/") and \
                        any(h[1] == "high" for h in scan_workflow_text(_file_text(gh, full, path, cm["sha"]))):
                    any_hit = True
        if shas and not any_hit:
            return True, "用目前的規則重新檢查當次執行的 workflow，沒有可疑內容（判定為誤判）。"
        return False, MANUAL_ONLY[rule]
    if rule == "gh-wf-exfil":
        r = scan()
        if r is None:
            return None
        names, bad = r
        if not bad:
            return True, "已檢查全部 %d 個分支，workflow 都沒有可疑內容（攻擊用的分支已刪除、內容已還原）。" % len(names)
        return False, "仍有 %d 個分支 / 檔案含可疑內容：%s" % (len(bad), _bad_text(bad))
    if rule == "gh-wf-branch":
        branch = parts[2]
        c, _, _ = gh.req("/repos/%s/branches/%s" % (full, urllib.parse.quote(branch, safe="")))
        if c == 404:
            return True, "分支 %s 已刪除。" % branch
        if c != 200:
            return None
        r = scan()
        if r is None:
            return None
        bad = [x for x in r[1] if x[0] == branch]
        if not bad:
            return True, "分支 %s 還在，但 workflow 沒有可疑內容。" % branch
        return False, "分支 %s 還在，而且含可疑內容：%s" % (branch, _bad_text(bad))
    if rule in ("gh-wf-flipflop", "gh-wf-direct"):
        if rule == "gh-wf-flipflop" and (a.get("assess") or {}).get("verdict") != "not_triggered":
            return False, "中間版本可能已執行，要人工確認。"
        c, repo, _ = gh.req("/repos/%s" % full)
        if c != 200:
            return None
        default = repo.get("default_branch", "main")
        r = scan()
        if r is None:
            return None
        bad = [x for x in r[1] if x[0] == default]
        if not bad:
            return True, ("中間版本沒有被執行，" if rule == "gh-wf-flipflop" else "") + "%s 目前的 workflow 沒有可疑內容。" % default
        return False, "%s 目前的 workflow 仍含可疑內容：%s" % (default, _bad_text(bad))
    if rule == "gh-mass-pr":
        org, actor, title = parts[1].split("/", 1)[-1], parts[2], parts[3] if len(parts) > 3 else ""
        q = 'org:%s is:pr is:open author:%s in:title "%s"' % (org, actor, title.replace('"', ""))
        c, res, _ = gh.req("/search/issues", {"q": q, "per_page": 1})
        if c != 200:
            return None
        n = (res or {}).get("total_count", 0)
        if n == 0:
            return True, "這批 PR 都已關閉。"
        return False, "還有 %d 個 PR 沒有關閉。" % n
    if rule == "gh-mass-wf":
        repos = [x for x in (a.get("evidence") or "").split("\n") if "/" in x]
        open_ = [k for k, x in st["alerts"].items() if x.get("rule") in ("gh-wf-exfil", "gh-wf-branch", "gh-wf-flipflop", "gh-wf-direct")
                 and k.split("|")[1] in repos and not x.get("auto_resolved")]
        if not open_:
            return True, "這些 repo 的相關警示都已確認處理完畢。"
        return False, "還有 %d 筆相關警示沒有處理完。" % len(open_)
    if rule == "gh-member":
        c, _, _ = gh.req("/repos/%s/collaborators/%s" % (full, parts[2]))
        if c == 404:
            return True, "%s 已經不是協作者。" % parts[2]
        if c == 204:
            return False, "%s 仍是協作者；確認是應該加的就手動標記。" % parts[2]
        return None
    if rule == "gh-public":
        c, repo, _ = gh.req("/repos/%s" % full)
        if c == 200 and repo.get("private"):
            return True, "已改回私有。"
        return (False, "仍然是公開的。") if c == 200 else None
    return None


def autoresolve(gh, st, owner_key, now, budget=AUTO_CALL_BUDGET):
    """自動確認警示是不是已經處理完（攻擊用的分支已刪、workflow 已還原、PR 已關、協作者已移除…）。
    已處理的標成 auto_resolved；沒處理完的記下原因（check）。每筆 6 小時最多檢查一次。回傳這次判定處理完的筆數。"""
    marks = load_marks()
    start = gh.calls
    scans, done = {}, 0
    todo = []
    for key, a in st["alerts"].items():
        if a.get("owner") != owner_key or a.get("rule", "").startswith("gh-posture"):
            continue
        state, _ = alert_state(key, a, marks)
        if state:
            continue
        chk = a.get("check") or {}
        if now - chk.get("at", 0) < RESOLVE_RECHECK_H * 3600 and chk.get("alert_last") == a.get("last"):
            continue
        todo.append(key)
    # mass-wf 依賴其他警示的結果，放最後
    todo.sort(key=lambda k: st["alerts"][k].get("rule") == "gh-mass-wf")
    for key in todo:
        if gh.low() or gh.calls - start > budget:
            break
        a = st["alerts"][key]
        try:
            res = _check_one(gh, st, key, a, scans)
        except (_ApiError, KeyError, IndexError, TypeError):
            res = None
        if res is None:
            continue
        ok, why = res
        with _st_lock:
            a["check"] = {"at": now, "note": why, "alert_last": a.get("last")}
            if ok and ("__noauto__" + key) not in marks:
                a["auto_resolved"] = {"at": now, "reason": why, "alert_last": a.get("last", 0)}
                done += 1
    return done


# ---------------------------------------------------------------------------------------------- 匯出 Markdown（給人或 AI agent 複審）
RULE_DESC = {
    "gh-wf-exfil": "workflow 內容出現外傳機密的寫法（toJSON(secrets)、裸 IP、外傳服務、讀 runner token / 記憶體等）",
    "gh-wf-direct": "預設分支的 workflow 被直接 push 修改，沒有對應的 PR",
    "gh-wf-branch": "新分支夾帶 workflow 檔",
    "gh-wf-flipflop": "同一個 workflow 檔短時間內被改掉又還原",
    "gh-run-executed": "可疑版本的 workflow 確實被執行過（讀取當次執行的 workflow 檔比對）",
    "gh-run-deleted": "Actions 執行編號出現缺號，可能有執行紀錄被刪除",
    "gh-member": "repo 新增協作者",
    "gh-public": "repo 被改成公開",
    "gh-mass-wf": "同一帳號短時間內修改多個 repo 的 workflow",
    "gh-mass-pr": "同一帳號短時間內對多個 repo 開同樣標題的 PR",
    "gh-org-member": "組織成員變動",
    "gh-org-outside": "外部協作者變動",
    "gh-posture-secrets": "組織機密開放給所有 repo",
    "gh-posture-protect": "預設分支沒有分支保護",
    "gh-hook": "repo 新增 / 變更 webhook",
    "gh-deploykey": "repo 新增 deploy key",
}
_SEV_ZH = {"high": "高", "medium": "中", "low": "低", "info": "資訊"}


def _fence(text):
    text = str(text or "")
    n = 3
    while "`" * n in text:
        n += 1
    return "`" * n + "\n" + text.rstrip("\n") + "\n" + "`" * n


def _iso_local(t):
    return time.strftime("%Y-%m-%d %H:%M %z", time.localtime(t)) if t else "—"


def as_markdown(cfg=None, min_severity="info"):
    """把目前的監控範圍、狀態與所有警示整理成一份可以交給 AI agent 複審的 Markdown。
    只含警示本身（evidence 已遮掉長 token），不含任何 token 或機密值。"""
    st = _load()
    marks = load_marks()
    gw = (cfg or {}).get("github_watch") or {}
    now = time.time()
    lim = _sev_rank(min_severity)
    alerts = sorted(((k, a) for k, a in st["alerts"].items() if _sev_rank(a.get("severity", "info")) <= lim),
                    key=lambda kv: (_sev_rank(kv[1].get("severity")), kv[1].get("rule", ""), kv[1].get("path", "")))
    out = ["# GitHub 監控警示（複審用）", "",
           "- 匯出時間：%s" % _iso_local(now),
           "- 來源：secaudit GitHub 監控（只讀 GitHub API，資料存在本機 data/ghwatch.json）",
           "- 處理狀態：未處理 %d、自動確認已處理 %d、手動標記 %d（每筆明細的「狀態」有原因）" % tuple(
               sum(1 for k, a in alerts if alert_state(k, a, marks)[0] == x) for x in (None, "auto", "manual")),
           "- 警示數：%d（%s）" % (len(alerts), "、".join("%s %d" % (_SEV_ZH[s], sum(1 for _, a in alerts if a.get("severity") == s))
                                                    for s in ("high", "medium", "low", "info")
                                                    if any(a.get("severity") == s for _, a in alerts))),
           ""]
    out += ["## 給複審者的說明", "",
            "這份清單是自動偵測的結果，可能有誤判，也可能漏掉。請逐項判斷：", "",
            "1. **判定**：`真的有問題` / `誤判` / `資訊不足`，並說明理由（引用下面的 detail、evidence，或你自己查到的 commit / run）。",
            "2. **影響範圍**：如果是真的，哪些機密或權限可能已外洩（repo secrets、environment secrets、開放給該 repo 的組織機密、GITHUB_TOKEN 權限）。",
            "3. **處置優先順序**：哪些要馬上處理（例如輪替機密、撤銷 token、還原 workflow），哪些可以排後面。",
            "4. **漏掉的東西**：從這些警示的模式看，還有沒有該查卻沒列出的 repo、帳號或手法。",
            "5. **自動確認是否可信**：標成「自動確認已處理」的，原因寫在「狀態」；請抽查幾筆確認判斷正確"
            "（例如攻擊分支真的已刪除、目前的 workflow 真的乾淨）。注意：痕跡移除不代表機密沒有外洩。", "",
            "可以用 `gh api` 或 GitHub 網頁驗證：每項的「位置」是 GitHub 連結；`gh run view <id> --repo <owner/repo>` 可看執行紀錄，"
            "`gh api repos/<owner/repo>/commits/<sha>/pulls` 可看 commit 是否經過 PR。請不要在回覆裡貼出任何機密值。", ""]
    out += ["## 監控範圍與狀態", ""]
    out.append("- 總開關：%s，每 %s 分鐘檢查一次" % ("開啟" if gw.get("enabled") else "關閉", gw.get("interval_min", 15)))
    for a in gw.get("accounts") or []:
        out.append("- 帳號 `%s`（%s）：%s" % (a.get("login", ""), "啟用" if a.get("enabled", True) else "停用",
                                          "、".join("`%s`" % o for o in a.get("owners") or []) or "（沒有指定）"))
    s = st.get("status") or {}
    out.append("- 上次檢查：%s，新警示 %s 項" % (_iso_local(s.get("at")), s.get("new", 0)))
    for x in s.get("summary") or []:
        out.append("  - %s" % x)
    for x in s.get("errors") or []:
        out.append("  - ⚠️ 錯誤：%s" % x)
    if st["owners"]:
        out += ["", "| 組織 / 帳號 | 類型 | repo 數 | 上次成功 | 上次設定稽核 | 錯誤 |", "|---|---|---|---|---|---|"]
        for k, v in sorted(st["owners"].items()):
            out.append("| %s | %s | %s | %s | %s | %s |" % (k, "組織" if v.get("is_org") else "個人", v.get("repos_seen") or "—",
                                                       _iso_local(v.get("last_ok")), _iso_local((v.get("audit") or {}).get("at")),
                                                       (v.get("error") or "").replace("|", "\\|") or "—"))
    out += ["", "## 偵測規則", "", "| 規則 | 意思 | 本次筆數 |", "|---|---|---|"]
    counts = {}
    for _, a in alerts:
        counts[a.get("rule", "")] = counts.get(a.get("rule", ""), 0) + 1
    for r in sorted(counts, key=lambda r: -counts[r]):
        out.append("| `%s` | %s | %d |" % (r, RULE_DESC.get(r, ""), counts[r]))
    # 同一條規則的「為什麼重要 / 建議處理」通常一樣，只在這裡寫一次，明細裡不同的才另外列
    common = {}
    for r in counts:
        for f in ("why", "fix"):
            vals = collections.Counter(a.get(f) or "" for _, a in alerts if a.get("rule") == r)
            common[(r, f)] = vals.most_common(1)[0][0] if vals else ""
    out += ["", "### 各規則的說明與建議處理", ""]
    for r in sorted(counts, key=lambda r: -counts[r]):
        out += ["#### `%s`" % r, ""]
        if common[(r, "why")]:
            out += ["**為什麼重要**：" + common[(r, "why")], ""]
        if common[(r, "fix")]:
            out += ["**建議處理**：" + common[(r, "fix")], ""]
    repos = {}
    for _, a in alerts:
        m = re.match(r"https://github\.com/([^/]+/[^/#?]+)", a.get("path") or "")
        if m:
            repos.setdefault(m.group(1), []).append(a)
    if repos:
        out += ["", "## 依 repo 彙整", "", "| repo | 高 | 中 | 規則 |", "|---|---|---|---|"]
        for r, lst in sorted(repos.items(), key=lambda kv: (-sum(1 for a in kv[1] if a.get("severity") == "high"), kv[0])):
            out.append("| %s | %d | %d | %s |" % (r, sum(1 for a in lst if a.get("severity") == "high"),
                                                  sum(1 for a in lst if a.get("severity") == "medium"),
                                                  " ".join(sorted({"`%s`" % a.get("rule", "") for a in lst}))))
    tl = timeline_markdown(min_severity)
    if tl:
        out += ["", tl.rstrip()]
    out += ["", "## 警示明細", ""]
    for i, (key, a) in enumerate(alerts, 1):
        out.append("### %d. [%s] %s" % (i, _SEV_ZH.get(a.get("severity"), a.get("severity")), a.get("title", key)))
        out.append("")
        out.append("- ID：`%s`" % key)
        out.append("- 規則：`%s`%s" % (a.get("rule", ""), "（%s）" % RULE_DESC[a["rule"]] if a.get("rule") in RULE_DESC else ""))
        if a.get("owner"):
            out.append("- 組織 / 帳號：%s" % a["owner"])
        if a.get("path"):
            out.append("- 位置：%s" % a["path"])
        out.append("- 第一次 %s，最近 %s，共 %d 次" % (_iso_local(a.get("first")), _iso_local(a.get("last")), a.get("count", 1)))
        stt, info = alert_state(key, a, marks)
        if stt == "auto":
            out.append("- 狀態：✅ 自動確認已處理（%s）：%s" % (_iso_local(info.get("at")), info.get("reason", "")))
        elif stt == "manual":
            out.append("- 狀態：✅ 手動標記為「%s」（%s）：%s" % ({"fixed": "已處理", "false_positive": "誤判"}.get(info.get("kind"), ""),
                                                        _iso_local(info.get("at")), info.get("note") or "沒有備註"))
        else:
            out.append("- 狀態：未處理" + ("。" + a["check"]["note"] if (a.get("check") or {}).get("note") else ""))
        if a.get("detail"):
            out += ["", a["detail"].strip()]
        if a.get("evidence"):
            out += ["", "證據：", "", _fence(a["evidence"])]
        if a.get("why") and a["why"] != common.get((a.get("rule"), "why")):
            out += ["", "**為什麼重要**：" + a["why"]]
        if a.get("fix") and a["fix"] != common.get((a.get("rule"), "fix")):
            out += ["", "**建議處理**：" + a["fix"]]
        out.append("")
    if not alerts:
        out.append("目前沒有警示。")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------------------------- 時間軸
RULE_SHORT = {
    "gh-wf-exfil": "外傳寫法", "gh-wf-direct": "直接改 workflow", "gh-wf-branch": "新分支帶 workflow",
    "gh-wf-flipflop": "改了又還原", "gh-run-executed": "已執行", "gh-run-deleted": "紀錄被刪",
    "gh-member": "新協作者", "gh-public": "變公開", "gh-mass-wf": "大量改 workflow", "gh-mass-pr": "大量開 PR",
    "gh-org-member": "成員變動", "gh-org-outside": "外部協作者", "gh-posture-secrets": "機密開放範圍",
    "gh-posture-protect": "分支保護", "gh-hook": "webhook", "gh-deploykey": "deploy key",
}
_TS_RE = re.compile(r"^\s*(\d\d)-(\d\d) (\d\d):(\d\d)[ ，,]?\s*(.*)$")
_ACTOR_RES = (re.compile(r"由 ([A-Za-z0-9][\w.-]*(?:\[bot\])?) "), re.compile(r"，([A-Za-z0-9][\w.-]*(?:\[bot\])?) 觸發"),
              re.compile(r"（([A-Za-z0-9][\w.-]*(?:\[bot\])?)）"))


def _event_epoch(mo, d, h, mi, ref):
    """detail 裡的時間只有「月-日 時:分」（本機時區），年份用偵測時間推回去。"""
    y = time.localtime(ref).tm_year
    for yy in (y, y - 1):
        try:
            t = time.mktime((yy, mo, d, h, mi, 0, 0, 0, -1))
        except (OverflowError, ValueError):
            continue
        if t <= ref + 86400:
            return t
    return ref


def timeline(min_severity="info"):
    """把所有警示拆成一個個有時間的事件（push、執行、PR…），由舊到新排序。
    沒有事件時間的警示（例如設定稽核）用偵測時間，並標成 detected。"""
    st = _load()
    marks = load_marks()
    lim = _sev_rank(min_severity)
    ev = []
    for key, a in st["alerts"].items():
        state = alert_state(key, a, marks)[0]
        if _sev_rank(a.get("severity", "info")) > lim:
            continue
        m = re.match(r"https://github\.com/([^/]+/[^/#?]+)", a.get("path") or "")
        repo = m.group(1) if m else (a.get("owner") or "").split("/")[-1]
        org = (a.get("owner") or "").split("/")[-1] or repo.split("/")[0]
        base = dict(key=key, org=org, state=state or "", rule=a.get("rule", ""), label=RULE_SHORT.get(a.get("rule"), a.get("rule", "")),
                    severity=a.get("severity", "info"), repo=repo, path=a.get("path", ""), title=a.get("title", ""))
        found = False
        for src in (a.get("detail") or "", a.get("evidence") or ""):
            for line in src.split("\n"):
                mm = _TS_RE.match(line)
                if not mm:
                    continue
                found = True
                text = mm.group(5).strip() or a.get("title", "")
                actor = next((r.search(text).group(1) for r in _ACTOR_RES if r.search(text)), "")
                ev.append(dict(base, t=_event_epoch(*map(int, mm.groups()[:4]), ref=a.get("first") or time.time()),
                               text=text, actor=actor, detected=False))
        if not found:
            ev.append(dict(base, t=a.get("first", 0), text=a.get("title", ""), actor="", detected=True))
    # 「直接改 workflow」這類事件的文字沒有帳號；同一個 repo、前後 2 分鐘內有帳號的事件就借用
    known = [(e["repo"], e["t"], e["actor"]) for e in ev if e["actor"]]
    for e in ev:
        if not e["actor"] and not e["detected"]:
            e["actor"] = next((a for r, t, a in known if r == e["repo"] and abs(t - e["t"]) <= 120), "")
    ev.sort(key=lambda e: (e["t"], _sev_rank(e["severity"])))
    return ev


def timeline_markdown(min_severity="info"):
    ev = [e for e in timeline(min_severity) if not e["detected"]]
    if not ev:
        return ""
    out = ["## 時間軸（事件發生時間，本機時區）", "",
           "由舊到新。同一筆警示可能拆成多個事件（例如多次執行）。只列有事件時間的項目；設定稽核類的警示見下方明細。", ""]
    day = None
    for e in ev:
        d = time.strftime("%Y-%m-%d (%a)", time.localtime(e["t"]))
        if d != day:
            out += ["", "### " + d, "", "| 時間 | 嚴重度 | repo | 類型 | 帳號 | 內容 |", "|---|---|---|---|---|---|"]
            day = d
        out.append("| %s | %s | %s | %s | %s | %s |" % (time.strftime("%H:%M", time.localtime(e["t"])), _SEV_ZH.get(e["severity"], ""),
                                                      e["repo"], e["label"], e["actor"] or "—",
                                                      e["text"].replace("|", "\\|")[:200]))
    return "\n".join(out) + "\n"
