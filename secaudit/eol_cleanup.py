"""修復動作「🧹 移除停止維護的舊版本」：已經停止維護（EOL）的執行環境，確定沒有在用就移除。

和「升級執行環境」的差別：那個只做同一版本線的修補版升級；EOL 的版本線不會再有新版本，只能跨版本線升級（要逐一確認相容）
或移除。這裡只做移除，而且移除前先找引用：
- 專案裡的版本設定（.nvmrc、.python-version、venv 的 pyvenv.cfg、environment.yml、rust-toolchain、composer.json、global.json…）
- PM2 服務、LaunchAgents、shell 設定檔（~/.zshrc 等）裡指到這個版本的路徑
找到引用的預設不勾選並列出在哪裡。系統內建、移不掉的（macOS 的 Ruby、Xcode 的 Python、conda base）只在說明裡交代。

移除方式（都可以還原）：
- Homebrew / rustup / conda 用各自的指令移除；conda 環境移除前先 conda env export 存一份套件清單
- 其他資料夾搬到垃圾桶（~/.Trash/secaudit-eol-<日期>/）；/usr/local 底下的要管理者密碼（系統密碼視窗），搬完把擁有者改回你，
  清空垃圾桶時才不會卡住
"""
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import time

from .core import HOME, home_rel

CONDA = os.path.join(HOME, "miniconda3")
BACKUP = os.path.join(HOME, "conda-env-backups")
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", ".next", "__pycache__", "site-packages",
             "Pods", "DerivedData", ".gradle", ".cache"}
PIN_FILES = {".nvmrc", ".node-version", ".python-version", "pyvenv.cfg", "environment.yml", "environment.yaml",
             "rust-toolchain", "rust-toolchain.toml", "composer.json", "global.json", ".tool-versions", "Pipfile",
             "Makefile", "Procfile", "ecosystem.config.js", "ecosystem.config.cjs", "docker-compose.yml"}
SCRIPT_EXT = (".sh", ".zsh", ".bash", ".csproj", ".command")
SHELL_RC = [os.path.join(HOME, f) for f in (".zshrc", ".zprofile", ".zshenv", ".bash_profile", ".bashrc", ".profile")]
PRODUCT = {"go": "Go", "php": "PHP", "python": "Python", "nodejs": "Node.js", "rust": "Rust", "dotnet": ".NET", "ruby": "Ruby"}


def _project_roots():
    from .actions import REPORTS, _read
    roots = set()
    for f in glob.glob(os.path.join(REPORTS, "*.json")):
        for it in (_read(f, {}).get("projects") or {}).get("items") or []:
            r = it.get("root")
            if r and os.path.isdir(r):
                roots.add(r)
    # 巢狀的專案只留最上層，避免重複走訪
    out = []
    for r in sorted(roots):
        if not any(r.startswith(o + os.sep) for o in out):
            out.append(r)
    return out


def _pin_files(roots, depth=4):
    """專案裡可能指定版本的檔案：[(路徑, 內容)]。只讀小檔案，跳過套件 / 建置資料夾。"""
    out = []
    for root in roots:
        base = root.rstrip(os.sep).count(os.sep)
        for dp, dns, fns in os.walk(root):
            if dp.count(os.sep) - base >= depth:
                dns[:] = []
            dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.endswith(".app")]
            for fn in fns:
                if fn in PIN_FILES or fn.endswith(SCRIPT_EXT):
                    p = os.path.join(dp, fn)
                    try:
                        if os.path.getsize(p) > 200_000:
                            continue
                        with open(p, encoding="utf-8", errors="replace") as fh:
                            out.append((p, fh.read()))
                    except OSError:
                        continue
    return out


def _services():
    """PM2 服務、LaunchAgents、shell 設定檔：[(說明, 文字)]。"""
    out = []
    try:
        r = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=20)
        for p in json.loads(r.stdout or "[]"):
            e = p.get("pm2_env") or {}
            out.append(("PM2 服務「%s」" % p.get("name"), " ".join(str(e.get(k, "")) for k in
                                                              ("pm_exec_path", "exec_interpreter", "pm_cwd", "args"))))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    for p in glob.glob(os.path.join(HOME, "Library", "LaunchAgents", "*.plist")):
        try:
            with open(p, "rb") as fh:
                out.append(("LaunchAgent %s" % os.path.basename(p), fh.read(100_000).decode("utf-8", "replace")))
        except OSError:
            pass
    for p in SHELL_RC:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for i, ln in enumerate(fh, 1):
                    if not ln.lstrip().startswith("#"):
                        out.append(("%s 第 %d 行" % (home_rel(p), i), ln))
        except OSError:
            pass
    return out


def _mm(v):
    return ".".join(v.split(".")[:2])


def _refs(x, pins, svcs):
    """這個版本被誰引用：[說明]。"""
    prod, ver, path, where = x["product"], x["version"], x["path"], x["where"]
    mm, major = _mm(ver), ver.split(".")[0]
    hits = []
    needles = [path]
    if x["source"] == "Homebrew":
        f = where[5:]
        needles += ["/opt/homebrew/opt/%s" % f, "/usr/local/opt/%s" % f, "/Cellar/%s/" % f]
    if prod == "python" and where.startswith("conda "):
        name = where[6:]
        needles.append("envs/%s" % name)
    hits += [d for d, t in svcs if any(n in t for n in needles)]
    for p, t in pins:
        fn, rel = os.path.basename(p), home_rel(p)
        if any(n in t for n in needles):
            hits.append(rel)
        elif prod == "nodejs" and fn in (".nvmrc", ".node-version") and re.match(r"\s*v?%s(\.|\s|$)" % major, t):
            hits.append(rel)
        elif prod == "python" and fn == ".python-version" and t.strip().startswith(mm) and x["source"] == "Homebrew":
            hits.append(rel)
        elif prod == "python" and where.startswith("conda ") and fn.startswith("environment.y") and \
                re.search(r"(?m)^name:\s*%s\s*$" % re.escape(where[6:]), t):
            hits.append(rel)
        elif prod == "python" and where.startswith("conda ") and \
                re.search(r"(conda|source)\s+activate\s+%s\b" % re.escape(where[6:]), t):
            hits.append(rel)
        elif prod == "rust" and fn.startswith("rust-toolchain") and re.search(r"\b%s(\.\d+)?\b" % re.escape(mm), t):
            hits.append(rel)
        elif prod == "php" and fn == "composer.json":
            try:
                c = str((json.loads(t).get("require") or {}).get("php", ""))
            except (ValueError, AttributeError):
                c = ""
            # ^7.4、~8.0、7.4.*：只能用這條版本線；>=7.4 這類新版也可以，不算
            if re.search(r"(?:^|[\s|^~=])%s(?:\.|\s|$|\*)" % re.escape(mm), c) and ">" not in c:
                hits.append("%s（php %s）" % (rel, c))
        elif prod == "dotnet" and (fn == "global.json" and re.search(r'"version"\s*:\s*"%s\.' % major, t) or
                                   fn.endswith(".csproj") and "net%s.0" % major in t):
            hits.append(rel)
        elif prod == "go" and where.startswith("~/sdk/") and os.path.basename(path) in t:
            hits.append(rel)        # 腳本直接呼叫 go1.24.12 這類指令
    seen = []
    for h in hits:
        if h not in seen:
            seen.append(h)
    return seen


def _env_info(path):
    """conda 環境最後一次裝 / 更新套件的日期與大小，讓人判斷還有沒有在用。"""
    try:
        last = time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(os.path.join(path, "conda-meta", "history"))))
    except OSError:
        last = "?"
    try:
        kb = int(subprocess.run(["du", "-sk", path], capture_output=True, text=True, timeout=60).stdout.split()[0])
        size = "%.1f GB" % (kb / 1048576) if kb > 1048576 else "%d MB" % (kb / 1024)
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        size = "?"
    return "最後一次安裝 / 更新套件：%s，佔用 %s" % (last, size)


def _trash_dir():
    d = os.path.join(HOME, ".Trash", "secaudit-eol-" + time.strftime("%Y%m%d"))
    os.makedirs(d, exist_ok=True)
    return d


def _step(x, refs, extra=None):
    prod = PRODUCT.get(x["product"], x["product"])
    s = {"id": "eol:%s:%s" % (x["product"], x["where"]), "group": prod, "default": not refs and not x.get("default"),
         "label": "%s %s（%s）" % (prod, x["version"], x["where"]),
         "detail": "%s 停止維護" % x.get("eol", "?")}
    if x.get("default"):
        s["detail"] += "；⚠️ 這是目前的預設版本，移除前先改用新版"
    if refs:
        s["detail"] += "；⚠️ 還有地方在用，預設不勾選：%s" % "、".join(refs[:6]) + ("…等 %d 處" % len(refs) if len(refs) > 6 else "")
    else:
        s["detail"] += "；沒有找到專案、PM2 服務或 shell 設定在用"
    s.update(extra or {})
    return s


def plan():
    from .actions import BREW_ENV, DATA, _read
    from .runtimes import discover, eol_data, find_cycle
    cache = _read(os.path.join(DATA, "cache.json"), {}).get("osv", {})
    today = datetime.date.today().isoformat()
    items = []
    for x in discover(cache.get("runtime_versions", {})):
        cy = find_cycle(eol_data(x["product"], cache, online=False), x["version"]) or {}
        e = cy.get("eol")
        if e is True or (isinstance(e, str) and e <= today):
            items.append(dict(x, eol=e if isinstance(e, str) else "已"))
    pins, svcs = _pin_files(_project_roots()), _services()
    steps, keep = [], []
    trash = os.path.join(HOME, ".Trash", "secaudit-eol-" + time.strftime("%Y%m%d"))
    for x in items:
        src, where, path = x["source"], x["where"], x["path"]
        if src == "系統" or where == "conda base":
            keep.append(x)
            continue
        refs = _refs(x, pins, svcs)
        if src == "Homebrew":
            f = where[5:]
            steps.append(_step(x, refs, {"kind": "cmd", "argv": ["brew", "uninstall", f], "env": BREW_ENV,
                                         "detail2": "brew uninstall %s（其他套件還依賴它時 Homebrew 會拒絕，不會硬刪）" % f}))
        elif src == "conda" and where.startswith("conda "):
            name = where[6:]
            conda = os.path.join(CONDA, "bin", "conda")
            bk = os.path.join(BACKUP, "%s-%s.yml" % (name, time.strftime("%Y%m%d")))
            steps.append(_step(x, refs, {"kind": "conda-remove", "env_name": name, "conda": conda, "backup": bk,
                                         "detail2": "先把套件清單存到 %s（要重建時 conda env create -f 這個檔案），再 conda env remove -n %s" % (
                                             home_rel(bk), name)}))
            steps[-1]["detail"] += "；" + _env_info(path)
        elif src == "rustup":
            tc = os.path.basename(path)
            steps.append(_step(x, refs, {"kind": "cmd", "argv": [os.path.join(HOME, ".cargo", "bin", "rustup"), "toolchain", "uninstall", tc],
                                         "detail2": "rustup toolchain uninstall %s" % tc}))
        elif src == "nvm":
            steps.append(_step(x, refs, {"kind": "trash", "paths": [path],
                                         "detail2": "把 %s 搬到垃圾桶（%s）" % (home_rel(path), home_rel(trash))}))
            if x.get("default"):
                steps[-1]["detail"] += "（先用「⬆️ 升級執行環境」的 nvm alias default 換掉預設）"
        elif where.startswith("~/sdk/"):
            ps = [path] + [p for p in [os.path.join(HOME, "go", "bin", os.path.basename(path))] if os.path.lexists(p)]
            steps.append(_step(x, refs, {"kind": "trash", "paths": ps,
                                         "detail2": "把 %s 搬到垃圾桶" % "、".join(home_rel(p) for p in ps)}))
        elif path in ("/usr/local/go",) or path.startswith("/usr/local/share/dotnet/shared/"):
            ps = [path] + (["/etc/paths.d/go"] if path == "/usr/local/go" and os.path.exists("/etc/paths.d/go") else [])
            steps.append(_step(x, refs, {"kind": "admin-trash", "paths": ps,
                                         "detail2": "需要管理者密碼（會跳出系統密碼視窗）：把 %s 搬到垃圾桶，並把擁有者改回你" % "、".join(ps)}))
        else:
            keep.append(x)
    for s in steps:
        s["detail"] += "；做法：" + s.pop("detail2")
    # 只有一個預設 php、node 的情況：shell 設定檔裡的那行 PATH 也要一起拿掉
    notes = ["只會移除勾選的版本。找到引用的（專案版本設定、PM2 服務、LaunchAgents、~/.zshrc 等）預設不勾選，"
             "列出在哪裡；先把那些地方改成新版，或確認那個專案已經不用了再勾。",
             "引用是用專案裡的版本設定檔和指令路徑找的，找不到不代表 100% 沒在用（例如手動輸入的指令）。"
             "移除都可以還原：資料夾在垃圾桶（清空前都拿得回來）、conda 環境有套件清單、Homebrew / rustup 可以重新安裝。",
             "要換成新版本線（例如 PHP 8.0 → 8.4、Python 3.8 → 3.14）請用各工具自己安裝，並在專案裡測試；這個動作不會自動跨版本升級。"]
    if keep:
        notes.append("移除不了、也不需要處理的：%s。這些是系統或 conda 自己的，只要不拿來跑專案就好，可以在報告標記為已確認無害。" % "、".join(
            "%s %s（%s）" % (PRODUCT.get(x["product"], x["product"]), x["version"], x["where"]) for x in keep))
    order = list(PRODUCT.values())
    steps.sort(key=lambda s: (order.index(s["group"]) if s["group"] in order else 99, not s["default"], s["label"]))
    return {"title": "移除停止維護的舊版本", "report": "", "steps": steps, "notes": notes,
            "reason": "執行 secaudit 修復：移除 %d 個停止維護的執行環境版本" % len(steps)}


def _allowed(p):
    rp = os.path.realpath(p)
    return (rp.startswith(os.path.join(HOME, ".nvm", "versions", "node") + os.sep) or
            rp.startswith(os.path.join(HOME, "sdk", "go")) or
            re.fullmatch(re.escape(os.path.join(HOME, "go", "bin")) + r"/go1\.\d+(\.\d+)?", rp) is not None)


def trash(s):
    d = _trash_dir()
    done, errs = [], []
    for p in s["paths"]:
        if not _allowed(p):
            errs.append("略過（不在允許範圍）：" + home_rel(p))
            continue
        if not os.path.lexists(p):
            continue
        dst = os.path.join(d, os.path.basename(p))
        if os.path.lexists(dst):
            dst += "-" + time.strftime("%H%M%S")
        try:
            shutil.move(p, dst)
            done.append(home_rel(p))
        except OSError as e:
            errs.append("%s：%s" % (home_rel(p), e))
    return not errs, ("已搬到垃圾桶：%s" % "、".join(done) if done else "沒有東西要搬") + ("\n" + "\n".join(errs) if errs else "")


def admin_trash(s):
    ps = [p for p in s["paths"] if p == "/usr/local/go" or p == "/etc/paths.d/go" or
          re.fullmatch(r"/usr/local/share/dotnet/shared/Microsoft\.[A-Za-z.]+/\d+\.\d+\.\d+", p)]
    if len(ps) != len(s["paths"]):
        return False, "略過：路徑不在允許範圍"
    ps = [p for p in ps if os.path.lexists(p)]
    if not ps:
        return True, "已經不存在"
    d = _trash_dir()
    sub = os.path.join(d, "admin-" + time.strftime("%H%M%S"))
    q = lambda v: "'" + v.replace("'", "'\\''") + "'"
    sh = "/bin/mkdir -p %s && /bin/mv %s %s/ && /usr/sbin/chown -R %d %s" % (
        q(sub), " ".join(q(p) for p in ps), q(sub), os.getuid(), q(sub))
    script = 'do shell script "%s" with administrator privileges' % sh.replace("\\", "\\\\").replace('"', '\\"')
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=300)
    if r.returncode:
        return False, "沒有完成（%s）" % ((r.stderr or "").strip()[-200:] or "取消了密碼視窗")
    return True, "已搬到垃圾桶 %s：%s" % (home_rel(sub), "、".join(ps))


def conda_remove(s):
    from .actions import _run_cmd
    name = s["env_name"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name == "base":
        return False, "略過：環境名稱不正確"
    os.makedirs(BACKUP, mode=0o700, exist_ok=True)
    ok, out = _run_cmd([s["conda"], "env", "export", "-n", name, "-f", s["backup"]], timeout=600)
    if not ok or not os.path.isfile(s["backup"]):
        return False, "套件清單匯出失敗，沒有移除：\n" + out[-1500:]
    ok, out2 = _run_cmd([s["conda"], "env", "remove", "-n", name, "-y"], timeout=1200)
    return ok, ("套件清單：%s\n" % home_rel(s["backup"])) + out2[-2000:]
