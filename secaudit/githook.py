"""git pull / clone 時的檢查：全域 git hook（core.hooksPath）呼叫這裡，只看這次拉下來的改動。

  post-merge    → git pull（merge）          檢查 ORIG_HEAD..HEAD
  post-rewrite  → git pull --rebase          檢查 ORIG_HEAD..HEAD
  post-checkout → git clone（舊 HEAD 全 0）  檢查整個工作目錄裡會被自動執行的檔案

要找的東西（都是「拉下來之後會自己跑起來」的位置）：
  - CI：.github/workflows、action.yml 的新增內容（沿用 ghwatch 的規則：toJSON(secrets)、連到裸 IP、外傳服務…）
  - 「改了又還原」：這次拉下來的 commit 裡有改過、但最後內容沒變的檔案（workflow 的話是高風險）
  - 套件安裝時自動執行：package.json 新增 preinstall / install / postinstall / prepare
  - 開資料夾就執行：.vscode/tasks.json 的 "runOn": "folderOpen"
  - git hook 管理工具：.husky/、.githooks/、lefthook.yml、.pre-commit-config.yaml 的新增內容
  - 套件來源：.npmrc / .yarnrc.yml / pip.conf 改了 registry
發現問題時：終端機印出警告、跳 macOS 通知、記到 data/githook.jsonl（secaudit 報告的「GitHub 監控」會列出）。
hook 本身不會擋下 pull（post-* hook 也擋不了），任何錯誤都不影響 git 的結果。
"""
import json
import os
import re
import subprocess
import sys
import time

if __package__ in (None, ""):          # 直接用 python3 secaudit/githook.py 執行（hook 走這條路，啟動比較快）
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from secaudit.ghwatch import WF_PATH_RE, scan_workflow_text
else:
    from .ghwatch import WF_PATH_RE, scan_workflow_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SECAUDIT_DATA", os.path.join(ROOT, "data"))
LOG = os.path.join(DATA, "githook.jsonl")
HOOK_DIR = os.path.expanduser("~/.secaudit/git-hooks")
HOOKS = ("post-merge", "post-rewrite", "post-checkout")
ZERO = "0" * 40
MARK = "# secaudit git hook"

AUTO_RUN = [   # (路徑 regex, 說明, 嚴重度, 新增內容要符合的 regex；None = 有改就算)
    (re.compile(r"(?:^|/)package\.json$"), "套件安裝時自動執行的腳本", "medium",
     re.compile(r'"(?:preinstall|install|postinstall|prepare|preuninstall)"\s*:')),
    (re.compile(r"(?:^|/)\.vscode/tasks\.json$"), "VS Code 開啟資料夾就執行的工作", "high", re.compile(r'"runOn"\s*:\s*"folderOpen"')),
    (re.compile(r"^(?:\.husky/(?!_/).+|\.githooks/.+|lefthook\.ya?ml|\.pre-commit-config\.yaml)$"), "git hook 管理工具的設定", "medium", None),
    (re.compile(r"(?:^|/)(?:\.npmrc|\.yarnrc(?:\.yml)?|pip\.conf|\.pypirc)$"), "套件來源設定", "medium",
     re.compile(r"registry|index-url|extra-index-url|npmRegistryServer|_authToken", re.I)),
]


def _git(*args, cwd=None):
    r = subprocess.run(["git"] + list(args), capture_output=True, text=True, timeout=30, cwd=cwd)
    return r.stdout if r.returncode == 0 else ""


def _added(old, new, path):
    out = _git("diff", "-U0", "--no-color", old, new, "--", path)
    return "\n".join(l[1:] for l in out.splitlines() if l.startswith("+") and not l.startswith("+++"))


def check(old, new, cwd=None):
    """回傳 [{"severity","title","detail","evidence"}]。old 為空 / 全 0 時檢查整個 tree。"""
    cwd = cwd or os.getcwd()
    whole = not old or old == ZERO or not _git("rev-parse", "--verify", "-q", old + "^{commit}", cwd=cwd)
    os.chdir(cwd)
    if whole:
        files = [l for l in _git("ls-tree", "-r", "--name-only", new).splitlines()]
        changed = {f: "A" for f in files}
    else:
        if _git("rev-parse", old) == _git("rev-parse", new):
            return []
        changed = {}
        for l in _git("diff", "--name-status", "--no-renames", old, new).splitlines():
            parts = l.split("\t")
            if len(parts) >= 2:
                changed[parts[-1]] = parts[0][:1]
    out = []

    def text_of(f):
        if whole:
            return _git("show", "%s:%s" % (new, f))
        return _added(old, new, f)

    for f, status in changed.items():
        if status == "D":
            continue
        if WF_PATH_RE.match(f):
            hits = scan_workflow_text(text_of(f))
            if hits:
                sev = "high" if any(h[1] == "high" for h in hits) else "medium"
                out.append({"severity": sev, "title": "workflow 有可疑內容：%s" % f,
                            "detail": "、".join(sorted({h[0] for h in hits})),
                            "evidence": "\n".join("%s｜%s" % (h[0], h[2]) for h in hits[:6])})
            elif not whole:
                out.append({"severity": "low", "title": "這次拉下來的改動有動到 CI：%s" % f, "detail": "看一下改了什麼：git diff %s %s -- %s" % (old[:10], new[:10], f), "evidence": ""})
            continue
        for rx, label, sev, need in AUTO_RUN:
            if rx.search(f):
                txt = text_of(f)
                m = need.search(txt) if need else (txt.strip() and re.search(r"\S", txt))
                if m:
                    line = txt[txt.rfind("\n", 0, m.start()) + 1:].split("\n", 1)[0].strip()[:140]
                    if whole and "folderOpen" not in label:
                        sev = "low"         # clone 下來本來就有的（例如 husky 的 prepare）多半正常，只列出來
                    out.append({"severity": sev, "title": "%s：%s" % (label, f), "detail": "%s的內容%s。" % (label, "新增或改變" if not whole else "存在"),
                                "evidence": line})
                break
    # 改了又還原：commit 範圍內被改過、但最後結果沒變的檔案
    if not whole:
        touched = set()
        for l in _git("log", "--no-merges", "--name-only", "--format=", "%s..%s" % (old, new)).splitlines():
            if l.strip():
                touched.add(l.strip())
        flip = sorted(f for f in touched - set(changed) if f)
        if flip:
            wf = [f for f in flip if WF_PATH_RE.match(f)]
            commits = _git("log", "--no-merges", "--format=%h %an %ad %s", "--date=format:%m-%d %H:%M", "%s..%s" % (old, new), "--", *flip[:20])
            out.append({"severity": "high" if wf else "low", "title": "改了又還原：%s" % "、".join((wf or flip)[:5]),
                        "detail": "這次拉下來的 commit 裡改過這些檔案，但最後內容跟原本一樣。%s" % (
                            "workflow 改了又還原是 CI 供應鏈攻擊用來偷機密、再把痕跡蓋掉的手法：到 GitHub Actions 看中間那個版本有沒有被執行。" if wf else ""),
                        "evidence": commits.strip()[:800]})
    return out


def _notify(title, msg):
    try:
        subprocess.run(["osascript", "-e", 'display notification %s with title %s sound name "Basso"' % (
            json.dumps(msg[:200]), json.dumps(title[:80]))], timeout=5, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def _record(repo, remote, hook, old, new, items):
    try:
        os.makedirs(DATA, mode=0o700, exist_ok=True)
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": time.time(), "repo": repo, "remote": remote, "hook": hook, "old": old, "new": new,
                                 "items": items}, ensure_ascii=False) + "\n")
    except OSError:
        pass


def load_recent(days=14):
    out = []
    try:
        with open(LOG, encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if time.time() - r.get("t", 0) < days * 86400:
                    out.append(r)
    except OSError:
        pass
    return out


def run_hook(hook, argv):
    """hook 進入點。回傳要不要接著跑 repo 自己的同名 hook（一律要）。"""
    old, new = "", "HEAD"
    if hook in ("post-merge", "post-rewrite"):
        if hook == "post-rewrite" and (argv[:1] or [""])[0] != "rebase":
            return
        old = _git("rev-parse", "-q", "--verify", "ORIG_HEAD").strip()
    elif hook == "post-checkout":
        if len(argv) < 3 or argv[0] != ZERO or argv[2] != "1":
            return          # 只看 clone（舊 HEAD 全 0）；一般切換分支不檢查
        old = ZERO
    else:
        return
    new = _git("rev-parse", "HEAD").strip()
    if not new:
        return
    items = check(old, new)
    items = [i for i in items if i["severity"] != "low"] + [i for i in items if i["severity"] == "low"]
    if not items:
        return
    top = _git("rev-parse", "--show-toplevel").strip()
    remote = _git("config", "--get", "remote.origin.url").strip()
    serious = [i for i in items if i["severity"] in ("high", "medium")]
    if serious:
        _record(top, re.sub(r"//[^/@]+@", "//", remote), hook, old, new, serious)
    red, yel, dim, end = "\033[1;31m", "\033[1;33m", "\033[2m", "\033[0m"
    sys.stderr.write("\n%s🛡 secaudit：這次 %s 拉下來的改動有 %d 項要注意%s（%s）\n" % (
        red if serious else dim, "clone" if old == ZERO else "pull", len(items), end, os.path.basename(top)))
    for i in items:
        c = red if i["severity"] == "high" else yel if i["severity"] == "medium" else dim
        sys.stderr.write("  %s[%s]%s %s\n" % (c, {"high": "高", "medium": "中", "low": "低"}[i["severity"]], end, i["title"]))
        if i.get("detail"):
            sys.stderr.write("      %s\n" % i["detail"])
        for ln in (i.get("evidence") or "").splitlines()[:6]:
            sys.stderr.write("      %s%s%s\n" % (dim, ln, end))
    if serious:
        sys.stderr.write("  %s在確認之前，先不要執行 npm install、打開 VS Code 或推 tag 觸發 CI。%s\n\n" % (yel, end))
        _notify("secaudit：%s 有可疑改動" % os.path.basename(top), "；".join(i["title"] for i in serious[:3]))


# ---------------------------------------------------------------------------------------------- 安裝 / 移除
HOOK_TMPL = """#!/bin/sh
%s（自動產生；移除：python3 %s/audit.py git-hooks --uninstall）
# 先做 secaudit 檢查（不會擋下 git），再接著跑 repo 自己的同名 hook，原本的 hook 行為不變。
hook=$(basename "$0")
if [ -z "$SECAUDIT_SKIP_HOOK" ]; then
  /usr/bin/env python3 "%s" "$hook" "$@" </dev/null || true
fi
%s
gd=$(git rev-parse --git-common-dir 2>/dev/null)
if [ -n "$gd" ] && [ -x "$gd/hooks/$hook" ]; then exec "$gd/hooks/$hook" "$@"; fi
exit 0
"""


def install(chain_prev=True):
    """設定全域 core.hooksPath。原本已經有全域 hooksPath 時，改成在我們的 hook 裡接著執行它。回傳說明文字。"""
    prev = _git("config", "--global", "--get", "core.hooksPath").strip()
    if prev and os.path.realpath(os.path.expanduser(prev)) == os.path.realpath(HOOK_DIR):
        prev = ""
    os.makedirs(HOOK_DIR, exist_ok=True)
    prev_line = ""
    if prev and chain_prev:
        prev_line = 'if [ -x "%s/$hook" ]; then "%s/$hook" "$@" || exit $?; fi' % (prev, prev)
        with open(os.path.join(HOOK_DIR, ".previous-hooksPath"), "w") as fh:
            fh.write(prev)
    me = os.path.abspath(__file__)
    for h in HOOKS:
        p = os.path.join(HOOK_DIR, h)
        with open(p, "w") as fh:
            fh.write(HOOK_TMPL % (MARK, ROOT, me, prev_line))
        os.chmod(p, 0o755)
    subprocess.run(["git", "config", "--global", "core.hooksPath", HOOK_DIR], check=True)
    return "已設定全域 git hook：%s%s" % (HOOK_DIR, "（原本的 %s 會接著執行）" % prev if prev else "")


def uninstall():
    prev = ""
    try:
        with open(os.path.join(HOOK_DIR, ".previous-hooksPath")) as fh:
            prev = fh.read().strip()
    except OSError:
        pass
    cur = _git("config", "--global", "--get", "core.hooksPath").strip()
    if cur and os.path.realpath(os.path.expanduser(cur)) == os.path.realpath(HOOK_DIR):
        if prev:
            subprocess.run(["git", "config", "--global", "core.hooksPath", prev], check=True)
        else:
            subprocess.run(["git", "config", "--global", "--unset", "core.hooksPath"], check=False)
    return "已移除全域 git hook%s" % ("，還原成 %s" % prev if prev else "")


def status():
    """給報告用：hook 有沒有裝、哪些 repo 自己設了 core.hooksPath（全域 hook 不會在那些 repo 執行）。"""
    cur = _git("config", "--global", "--get", "core.hooksPath").strip()
    ok = bool(cur) and os.path.realpath(os.path.expanduser(cur)) == os.path.realpath(HOOK_DIR) and all(
        os.path.exists(os.path.join(HOOK_DIR, h)) for h in HOOKS)
    return {"installed": ok, "hooksPath": cur}


if __name__ == "__main__":
    try:
        run_hook(sys.argv[1] if len(sys.argv) > 1 else "", sys.argv[2:])
    except Exception as e:          # hook 絕對不能讓 git 失敗
        sys.stderr.write("secaudit git hook 錯誤（不影響 git）：%s: %s\n" % (type(e).__name__, str(e)[:200]))
    sys.exit(0)
