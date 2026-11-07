"""閒置專案：把報告裡的問題依「所在專案」分組，判斷專案最近有沒有在用。

最後活動時間取下列最新的一個（都不會修改專案裡的任何東西）：
  - 最後一次 commit 的時間、.git/logs/HEAD（commit / checkout / reset 都會更新）
  - 專案裡檔案與資料夾的修改時間（略過 node_modules、.git、虛擬環境、建置輸出等工具產生的內容，以及 .DS_Store）
不看存取時間（macOS 的 atime 不可靠，掃描、備份、Spotlight 都會碰到）。
有程式的工作目錄在專案裡（終端機、編輯器、dev server 開著）就算「使用中」。
"""
import os
import re
import subprocess
import time

from .core import HOME, PRUNE_DIRS, home_rel, is_dataless

MARKERS = ("package.json", "go.mod", "Cargo.toml", "pyproject.toml", "requirements.txt", "setup.py", "Gemfile",
           "composer.json", "pom.xml", "build.gradle", "Package.swift", "pubspec.yaml", "deno.json", "mix.exs")
# 工具產生、不代表「你在改這個專案」的資料夾
NOISE_DIRS = PRUNE_DIRS | {"dist", "build", "out", "target", "coverage", ".parcel-cache", ".svelte-kit", ".expo",
                           ".angular", ".dart_tool", ".terraform", "vendor", "tmp", "logs", ".idea", ".vscode",
                           ".github", ".circleci"}
# 工具（套件升級、secaudit 的修復動作、1Password 搬移）常會自動改動的檔案：改了也不代表你在開發這個專案
TOOL_TOUCHED = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "go.sum", "go.mod", "Cargo.lock",
                "poetry.lock", "Pipfile.lock", "Gemfile.lock", "composer.lock", "uv.lock", ".gitignore", ".npmrc",
                ".DS_Store", ".tool-versions", ".nvmrc", ".python-version",
                # CI 設定與 secaudit 自己的處理紀錄：搬機密、改 CI 也會動到，不代表你在開發這個專案
                ".drone.yml", ".drone.yaml", ".gitlab-ci.yml", ".gitlab-ci.yaml", ".travis.yml", "Jenkinsfile",
                "azure-pipelines.yml", "bitbucket-pipelines.yml", "secaudit-處理紀錄.md"}
# 判斷「最後一次真的改程式的 commit」時排除的路徑（同上：CI、機密範本、lockfile、secaudit 紀錄）
GIT_MAINT_EXCLUDE = [":(exclude,glob)**/%s" % x for x in (
    ".github/**", ".circleci/**", ".drone.yml", ".drone.yaml", ".gitlab-ci.y*ml", ".travis.yml", "Jenkinsfile",
    "*.tpl", ".env*", ".gitignore", ".npmrc", "*lock*", "go.sum", "go.mod", "Cargo.lock", "secaudit-*.md")]
WALK_CAP = 60000          # 每個專案最多看幾個項目（超過就以目前看到的為準）
# 雲端硬碟（iCloud、Google Drive…）：git 指令會讀檔案內容，碰到「僅限線上」的檔案就會觸發下載，所以只看修改時間
CLOUD_MARKS = ("/Library/Mobile Documents/", "/Library/CloudStorage/")


def in_cloud(p):
    return any(m in p for m in CLOUD_MARKS)


def tool_dir(p):
    """家目錄底下的隱藏資料夾（~/.lmstudio、~/.move…）是工具自己管理的，不當成你的專案。"""
    rp = os.path.realpath(p)
    home = os.path.realpath(HOME)
    return rp.startswith(home + os.sep) and os.path.relpath(rp, home).split(os.sep)[0].startswith(".")


def _remote_from_config(root):
    p = os.path.join(root, ".git", "config")
    try:
        if is_dataless(os.lstat(p)):
            return ""
        with open(p, encoding="utf-8", errors="replace") as fh:
            txt = fh.read(65536)
    except OSError:
        return ""
    m = re.search(r'\[remote "origin"\][^\[]*?url\s*=\s*(\S+)', txt)
    return re.sub(r"(://)[^/@\s]+@", r"\1", m.group(1)) if m else ""
DEFAULT_DAYS = 30


def _git(root, *args, timeout=15):
    try:
        r = subprocess.run(["git", "--no-optional-locks", "-C", root] + list(args), capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0"))
        return r.returncode == 0, r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, ""


def _cut_vendor(p):
    """node_modules / vendor / 虛擬環境裡的檔案：從那一層往上找專案，不要把套件本身當成專案。"""
    parts = p.split(os.sep)
    for i, x in enumerate(parts):
        if x in PRUNE_DIRS or x == "vendor":
            return os.sep.join(parts[:i]) or p
    return p


def project_root(path, stop=()):
    """檔案所在的專案資料夾：最近的 git 根目錄；不在 git 裡就用最近一個有專案設定檔（package.json…）的資料夾。
    到家目錄、/Volumes/磁碟、掃描範圍的根目錄就停（那些是放很多專案的資料夾，不是專案）。"""
    p = _cut_vendor(os.path.realpath(os.path.expanduser(path)))
    d = p if os.path.isdir(p) else os.path.dirname(p)
    hard = {os.path.realpath(HOME), "/", "/Volumes"} | {os.path.realpath(s) for s in stop}
    marker = ""
    while d and d not in hard and not re.match(r"^/Volumes/[^/]+$", d):
        if os.path.exists(os.path.join(d, ".git")):
            return d
        if not marker and any(os.path.isfile(os.path.join(d, m)) for m in MARKERS):
            marker = d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return marker


def cwd_users(roots):
    """哪些專案資料夾裡有程式正在當工作目錄（lsof 一次查全部）：{root: [程式名稱]}。"""
    out = {r: [] for r in roots}
    if not roots:
        return out
    try:
        txt = subprocess.run(["lsof", "-a", "-d", "cwd", "-u", str(os.getuid()), "-Fcn"], capture_output=True, text=True,
                             timeout=30, stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.TimeoutExpired):
        return out
    cmd = ""
    for line in txt.splitlines():
        if line.startswith("c"):
            cmd = line[1:]
        elif line.startswith("n"):
            cwd = line[1:]
            for r in roots:
                if (cwd == r or cwd.startswith(r + os.sep)) and cmd not in out[r]:
                    out[r].append(cmd)
    return out


def activity(root, quick=False):
    """專案的最後活動時間與狀態。quick：只算最後活動時間（不查 remote / 未提交 / 未推送）。"""
    best, what = 0.0, ""
    files = dataless = dataless_bytes = 0
    capped = False
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in NOISE_DIRS and not d.endswith(".egg-info")]
        for n in fns:        # 只看檔案：資料夾的修改時間在裡面新增 / 刪除任何東西（包括工具產生的）時都會變
            if n in TOOL_TOUCHED or n.startswith(".env") or n.endswith(".tpl"):
                continue
            files += 1
            try:
                st = os.lstat(os.path.join(dp, n))
            except OSError:
                continue
            if is_dataless(st):
                dataless += 1
                dataless_bytes += st.st_size
            if st.st_mtime > best:
                best, what = st.st_mtime, os.path.join(dp, n)
        if files > WALK_CAP:
            capped = True
            break
    info = {"root": root, "display": home_rel(root), "files_seen": files, "capped": capped, "dataless": dataless,
            "dataless_bytes": dataless_bytes,
            "git": False}
    cloud = in_cloud(root)
    info["cloud"] = cloud
    if os.path.exists(os.path.join(root, ".git")) and not cloud:
        # git 專案：沒有改動的檔案內容就等於某個 commit，修改時間會被 checkout / reset / rebase 改掉，不可信。
        # 改成只看「和 git 不一樣」的檔案（沒 commit 的修改、新檔案）的修改時間，再加上最後一次真的改程式的 commit
        ok, st = _git(root, "status", "--porcelain", "-z", "--untracked-files=normal", timeout=30)
        if ok:
            best, what = 0.0, ""
            for ent in st.split("\0"):
                rel = ent[3:] if len(ent) > 3 else ""
                if not rel:
                    continue
                p = os.path.join(root, rel)
                cands = [p]
                if os.path.isdir(p):           # 整個新資料夾：看裡面的檔案（有上限）
                    cands = []
                    for dp, dns, fns in os.walk(p):
                        dns[:] = [x for x in dns if x not in NOISE_DIRS]
                        cands += [os.path.join(dp, f) for f in fns]
                        if len(cands) > 2000:
                            break
                for c in cands:
                    n = os.path.basename(c)
                    if n in TOOL_TOUCHED or n.startswith(".env") or n.endswith(".tpl"):
                        continue
                    try:
                        m = os.lstat(c).st_mtime
                    except OSError:
                        continue
                    if m > best:
                        best, what = m, c
    if os.path.exists(os.path.join(root, ".git")):
        info["git"] = True
        # 最後一次「真的改程式」的 commit：只動 CI、機密範本、lockfile 的維護 commit 不算。
        # 不看 checkout / rebase / reset 這類 git 操作（工具或修復動作也會做，不代表你在開發）
        ok, ct = (False, "") if cloud else _git(root, "log", "-1", "--format=%ct", "--", "." , *GIT_MAINT_EXCLUDE)
        if ok and ct.isdigit() and int(ct) > best:
            best, what = float(ct), "最後一次 commit"
    if info["git"] and not quick and cloud:
        info["remote"] = _remote_from_config(root)      # 只讀已下載的 .git/config，不跑 git 指令
        info["dirty"] = info["unpushed"] = None
        info["has_upstream"] = True
    elif info["git"] and not quick:
        ok, remote = _git(root, "remote", "get-url", "origin")
        info["remote"] = re.sub(r"(://)[^/@\s]+@", r"\1", remote) if ok else ""
        ok, st = _git(root, "status", "--porcelain", timeout=15)     # iCloud 裡的大專案可能很慢
        info["dirty"] = len(st.splitlines()) if ok else None
        ok, ahead = _git(root, "rev-list", "--count", "@{u}..HEAD")
        info["unpushed"] = int(ahead) if ok and ahead.isdigit() else None
        info["has_upstream"] = ok
    info["last_ts"] = int(best)
    info["last"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(best)) if best else ""
    info["last_what"] = what if what.startswith(("最後", "git")) else ("修改了 " + os.path.relpath(what, root) if what else "")
    info["idle_days"] = int((time.time() - best) // 86400) if best else None
    return info


def cloud_only(root):
    """整個資料夾（包括 node_modules 等）有幾個「僅限線上」的檔案、合計多大。只用 lstat，不會觸發下載。"""
    n = size = 0
    for dp, dns, fns in os.walk(root):
        for f in fns:
            try:
                st = os.lstat(os.path.join(dp, f))
            except OSError:
                continue
            if is_dataless(st):
                n += 1
                size += st.st_size
    return n, size


def foreign_owned(root, limit=3):
    """資料夾裡不屬於你的檔案（例如用 sudo 產生、屬於 root 的檔案）。hdiutil create -srcfolder 遇到這種檔案
    會等系統管理員授權，畫面上看不到視窗，就會一直卡住。只用 lstat，回傳 (數量, 前幾個的相對路徑與擁有者)。"""
    import pwd
    me, n, sample = os.getuid(), 0, []
    for dp, dns, fns in os.walk(root):
        for x in dns + fns:
            p = os.path.join(dp, x)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if st.st_uid != me:
                n += 1
                if len(sample) < limit:
                    try:
                        who = pwd.getpwuid(st.st_uid).pw_name
                    except KeyError:
                        who = str(st.st_uid)
                    sample.append("%s（%s）" % (os.path.relpath(p, root), who))
    return n, sample


def cloud_download(root, progress=None):
    """把專案裡「僅限線上」的檔案下載到這台電腦（讀第一個 byte 就會觸發 iCloud / File Provider 下載）。
    8 個同時下載，每個檔案最多等 2 分鐘、重試 3 次。回傳還沒下載到的檔案清單。
    注意：這個 walk 不略過 node_modules 等資料夾，封存要整個資料夾都在本機。"""
    from concurrent.futures import ThreadPoolExecutor
    todo = []
    for dp, dns, fns in os.walk(root):
        for n in fns:
            p = os.path.join(dp, n)
            try:
                if is_dataless(os.lstat(p)):
                    todo.append(p)
            except OSError:
                pass
    if not todo:
        return []
    try:
        subprocess.run(["brctl", "download", root], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        pass

    def fetch(p):
        for _ in range(3):
            try:
                subprocess.run(["head", "-c", "1", p], capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
                if not is_dataless(os.lstat(p)):
                    return True
            except subprocess.TimeoutExpired:
                continue
            except OSError:
                return False
        return False

    bad, done = [], 0
    with ThreadPoolExecutor(8) as ex:
        for p, ok in zip(todo, ex.map(fetch, todo)):
            done += 1
            if not ok:
                bad.append(p)
            if progress and done % 20 == 0:
                progress(done, len(todo))
    return bad


def size_of(root):
    try:
        out = subprocess.run(["du", "-sk", root], capture_output=True, text=True, timeout=300,
                             stdin=subprocess.DEVNULL).stdout.split()
        return int(out[0]) * 1024 if out and out[0].isdigit() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _paths(f):
    out = []
    for x in (f.get("path") or "").split("；"):
        x = x.split(" 等 ")[0].split("（")[0].strip()
        if x:
            out.append(x)
    return out


def summarize(findings, targets, days=None):
    """報告用：有問題的專案清單（含近期還在用的），閒置的排前面。"""
    if days is None:
        from .app import load_config
        days = load_config().get("idle_project_days", DEFAULT_DAYS)
    stop = [t if isinstance(t, str) else t["path"] if isinstance(t, dict) else t.path for t in targets or []]
    groups = {}
    for f in findings:
        if f.get("scope") != "walk" or f.get("severity") == "info":
            continue
        for p in _paths(f):
            r = project_root(p, stop)
            if r and not tool_dir(r):
                g = groups.setdefault(r, {"counts": {"high": 0, "medium": 0, "low": 0}, "titles": []})
                g["counts"][f["severity"]] = g["counts"].get(f["severity"], 0) + 1
                if f["title"] not in g["titles"]:
                    g["titles"].append(f["title"])
    users = cwd_users(list(groups))
    out = []
    for r, g in groups.items():
        if not os.path.isdir(r):
            continue
        a = activity(r)
        a.update(counts=g["counts"], titles=g["titles"][:5], in_use=users.get(r, []))
        a["idle"] = a["idle_days"] is not None and a["idle_days"] >= days and not a["in_use"]
        if a["idle"]:
            a["size"] = size_of(r)
        out.append(a)
    out.sort(key=lambda a: (not a["idle"], -(a["idle_days"] or 0)))
    return {"days": days, "items": out}


def human_size(n):
    if n is None:
        return "?"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return ("%.0f %s" if u in ("B", "KB") else "%.1f %s") % (n, u)
        n /= 1024.0


def git_note(a):
    if not a.get("git"):
        return "不是 git 專案（DMG 是唯一的副本）"
    bits = ["remote %s" % a["remote"] if a.get("remote") else "⚠️ 沒有 remote（DMG 是唯一的副本）"]
    if a.get("cloud"):
        bits.append("在雲端硬碟裡，沒有檢查未提交 / 未推送（避免觸發下載）")
    if a.get("dirty"):
        bits.append("%d 個檔案沒有 commit" % a["dirty"])
    if a.get("unpushed"):
        bits.append("%d 個 commit 沒有 push" % a["unpushed"])
    elif a.get("remote") and not a.get("has_upstream"):
        bits.append("目前分支沒有追蹤 remote")
    return "、".join(bits)
