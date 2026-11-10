"""B. 機密與憑證檢查。"""
import base64
import os
import re
import stat

from .core import (HOME, Finding, is_fixture_path, ScanContext, file_fingerprint, home_rel, lstat_safe, mask, mode_str,
                   group_or_world_readable, read_text)
from .rules import SECRET_RULES, GENERIC_ASSIGN, is_placeholder

CAT = "機密與憑證"


_WEAK_PW = {"postgres", "password", "pass", "root", "admin", "secret", "example", "test", "changeme", "mysql", "redis",
            "guest", "user", "dev", "local", "123456", "pw"}
# 主機名稱後面可能直接接著程式碼的符號（例如 shell 的 ${DB:-postgres://…@localhost:5436}、markdown 的反引號）
_LOCAL_HOST = re.compile(r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|db|database|postgres|mysql|redis|mongo|mongodb)(?::\d+)?(?:[/?#}`'\",;)\]\s]|$)", re.I)
_DB_PARTS = re.compile(r"^([\w+.-]+://)([^:/@]+):([^@]+)@(.*)$")


def _db_url(raw):
    """資料庫連線字串：回傳 (是否略過, severity, 遮罩後的證據)。範例 / 變數佔位不算；本機弱帳密降為 low。"""
    m = _DB_PARTS.match(raw)
    if not m:
        return False, "high", mask(raw)
    scheme, user, pw, rest = m.groups()
    if is_placeholder(pw) or re.match(r"^[%$]|^\*+$", pw):
        return True, "", ""
    local = bool(_LOCAL_HOST.match(rest))
    # 連到本機 / docker 內部主機的帳密只在開發環境有效，外人連不到 → 低風險（仍列出，提醒別沿用到正式環境）
    sev = "low" if local else "high"
    return False, sev, "%s%s:****@%s" % (scheme, user, rest[:60])


def _random_enough(v: str) -> bool:
    """真的 API 金鑰是隨機字元：一定同時有大寫、小寫和數字。"""
    body = v.split("-", 2)[-1] if v.startswith(("sk-proj-", "sk-svcacct-", "sk-ant-")) else v[3:]
    return bool(re.search(r"[A-Z]", body) and re.search(r"[a-z]", body) and re.search(r"\d", body))


FAKE_RUNS = ("abcdefghij", "0123456789", "1234567890", "qwertyuiop", "xxxxxxxxxx", "aaaaaaaaaa", "deadbeefdeadbeef")


def looks_fake(v: str) -> bool:
    """手打的測試 / 範例值：一長串連續的字母或數字。真的金鑰是隨機的，不會出現這種序列。"""
    low = v.lower()
    return any(r in low for r in FAKE_RUNS)


def find_secrets(text: str, generic: bool = False):
    """回傳 {rule_id: (名稱, severity, [行號], 第一個遮罩值)}。"""
    hits = {}
    for rid, name, rx, sev in SECRET_RULES:
        for m in rx.finditer(text):
            if rid in ("openai-key", "anthropic-key") and not _random_enough(m.group(0)):
                continue     # 例如網址裡的「nvidia-sk-hynix-…」：全小寫的單字串，不是金鑰
            if looks_fake(m.group(0)):
                continue     # 明顯是手打的測試值（abcdefgh、0123456789…），不是真的金鑰
            ev = "（私鑰內容不顯示）" if rid == "private-key" else mask(m.group(0))
            s = sev
            if rid == "db-url":
                skip, s, ev = _db_url(m.group(0))
                if skip:
                    continue
            elif rid == "jdbc-password":
                ev = re.sub(r"((?:password|pwd)=)[^;&\s'\"]+", r"\1****", m.group(0), flags=re.I)[:90]
            ln = text.count("\n", 0, m.start()) + 1
            h = hits.setdefault(rid, [name, s, [], ev])
            if s == "high":
                h[1] = "high"            # 同一種機密只要有一處是高風險，整體算高風險
            h[2].append(ln)
    if generic:
        for m in GENERIC_ASSIGN.finditer(text):
            key, val = m.group(1), m.group(2)
            if is_placeholder(val) or val.lower() in ("true", "false", "null", "none"):
                continue
            ln = text.count("\n", 0, m.start()) + 1
            h = hits.setdefault("plain-assign", ["明文機密變數", "medium", [], "%s=%s" % (key, mask(val))])
            h[2].append(ln)
    return hits


def report_secrets(ctx: ScanContext, path: str, text: str, category: str = CAT,
                   generic: bool = False, context_note: str = ""):
    for rid, (name, sev, lns, ev) in find_secrets(text, generic).items():
        shown = ", ".join(str(n) for n in lns[:5]) + (" …" if len(lns) > 5 else "")
        ctx.add(Finding(
            rule="secret-" + rid, severity=sev, category=category,
            title="發現%s%s" % (name, context_note),
            path=home_rel(path), detail="共 %d 處，行號：%s" % (len(lns), shown), evidence=ev,
            why="明文機密一旦被任何程式（包括被 prompt injection 操控的 AI 代理）讀到就會外洩。",
            fix="到服務後台撤銷並重新產生此金鑰，改存 1Password，檔案中改用 op:// 引用。",
        ))


CLOUD_MARKERS = ("/Library/Mobile Documents/", "/Library/CloudStorage/", "/Dropbox/")


def _git_state(path):
    """回傳 'tracked'（已提交到 git）、'untracked'（在 git 專案裡但沒提交）或 ''（不在 git 專案裡）。"""
    import subprocess
    from .core import safe_env
    d = os.path.dirname(path)
    while d and d != os.path.dirname(d):
        if os.path.isdir(os.path.join(d, ".git")):
            try:
                r = subprocess.run(["git", "-C", d, "ls-files", "--error-unmatch", "--", os.path.relpath(path, d)],
                                   capture_output=True, text=True, timeout=10, env=safe_env())
            except (OSError, subprocess.TimeoutExpired):
                return ""
            return "tracked" if r.returncode == 0 else "untracked"
        d = os.path.dirname(d)
    return ""


CODE_EXTS = {".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".java", ".kt", ".rb", ".php", ".cs",
             ".swift", ".c", ".cc", ".cpp", ".h", ".sh", ".zsh", ".bash", ".ini", ".toml", ".yml", ".yaml", ".sql", ".vue",
             ".svelte", ".dart", ".scala", ".ex", ".exs", ".gradle", ".tf", ".hcl", ".json", ".xml", ".plist"}


# 已知 App 憑證檔的具體建議（家目錄相對路徑的開頭 → 建議）
APP_CRED_HINTS = {
    ".aws/": "AWS 長期 Access Key 建議改用 1Password 的 AWS shell plugin（op plugin init aws，執行 aws 時用 Touch ID 取用），"
             "或 AWS SSO（aws configure sso，短期憑證）；確認能用之後再刪掉 credentials 裡的金鑰。",
    ".anydesk/": "這是 AnyDesk 自己產生的裝置金鑰，AnyDesk 沒有提供改存別處的方式，保留即可。",
    ".lmstudio/": "這是 LM Studio Hub 的登入憑證，App 自己管理，保留即可。",
}
# App 自己產生、自己管理，沒有改存別處的方式：權限正確又沒同步到雲端時，只列為「資訊」（沒有要處理的事）
APP_CRED_KEEP = (".anydesk/", ".lmstudio/")
# 不再使用時怎麼讓服務端撤銷金鑰（沒列到的用一般說法：從 App 裡登出 / 解除綁定）
APP_CRED_REVOKE = {
    ".aws/": "到 AWS 主控台 IAM → 使用者 → 安全憑證，把這把 Access Key（AKIA 開頭）先停用、確認沒有東西壞掉後刪除，再從 credentials 移除那個 profile。",
}
_NOT_CRED_EXT = {".md", ".rst", ".txt", ".html", ".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".java",
                 ".kt", ".rb", ".php", ".cs", ".swift", ".c", ".cc", ".cpp", ".h", ".sh", ".vue", ".svelte", ".dart", ".scala"}


def _app_cred_hint(path):
    """家目錄隱藏資料夾裡（~/.aws、~/.anydesk…）的設定 / 憑證檔 → 回傳具體建議（沒有就回傳 ""）；不是 App 憑證檔回傳 None。
    套件快取、擴充功能裡的檔案和原始碼 / 文件不算（那些是範例）。"""
    from .projects import tool_dir
    if not tool_dir(path) or os.path.splitext(path)[1].lower() in _NOT_CRED_EXT or \
            re.search(r"/(?:node_modules|vendor|site-packages|\.cargo/registry|extensions)/", path):
        return None
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(HOME)) + ("/" if os.path.isdir(path) else "")
    return next((h for k, h in APP_CRED_HINTS.items() if rel.startswith(k)), "")


def _app_revoke(path):
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(HOME)) + ("/" if os.path.isdir(path) else "")
    return next((h for k, h in APP_CRED_REVOKE.items() if rel.startswith(k)),
                "從 App 裡登出 / 解除綁定再移除，讓服務端撤銷這把金鑰。")


def report_file_secrets(ctx: ScanContext, path: str, text: str):
    """遍歷到的一般檔案：同一個檔案裡的所有機密彙整成一筆，附上處理方式。"""
    hits = find_secrets(text)
    if not hits:
        return
    order = {"high": 0, "medium": 1, "low": 2}
    sev = min((h[1] for h in hits.values()), key=lambda s: order.get(s, 9))
    kinds = sorted(hits.values(), key=lambda h: order.get(h[1], 9))
    detail = "；".join("%s %d 處（第 %s 行，%s）" % (n, len(l), ", ".join(map(str, l[:4])) + ("…" if len(l) > 4 else ""), ev)
                      for n, s, l, ev in kinds)
    git = _git_state(path)
    cloud = any(c in path for c in CLOUD_MARKERS)
    notes = []
    fixture = is_fixture_path(path)
    if fixture:
        sev = "low"
        notes.append("位在測試／範例／第三方套件目錄，多半是假資料；確認不是真的金鑰即可標記無害")
    if git == "tracked":
        notes.append("⚠️ 這個檔案已經提交到 git：就算刪掉，機密仍留在 git 歷史，push 過的話也在遠端")
        if sev == "medium":
            sev = "high"
    elif git == "untracked":
        notes.append("在 git 專案裡但沒有提交，請確認它在 .gitignore 裡")
    if cloud:
        notes.append("⚠️ 位在雲端硬碟，已經同步到雲端")
    rel = home_rel(path)
    fix = ("① 改存 1Password：用 scripts/op-store.sh 或 1Password App 建立項目，原本的值改成 op:// 引用；"
           "整份文件要保留的話，可用 op document create '%s' --vault Personal 存成 1Password 文件。"
           "② 只是要封存：hdiutil create -encryption AES-256 -stdinpass -srcfolder '%s' -volname secrets ~/Secure/secrets.dmg"
           "（密碼存 1Password），確認能開啟後刪除原檔並清空垃圾桶。"
           "③ 這些機密如果曾經外流（提交到 git、同步到雲端、分享過），先到各服務撤銷並更換。" % (path, os.path.dirname(path)))
    if git == "tracked":
        fix += "④ 從 git 歷史移除：git filter-repo --invert-paths --path '%s'（會改寫歷史，先和團隊確認）。" % os.path.relpath(path, os.path.dirname(path))
    code = os.path.splitext(path)[1].lower() in CODE_EXTS
    if sev == "low":
        fix = ("多半是測試資料、範例或本機開發用帳密：確認後在報告標記為已確認無害即可；正式環境不要沿用同一組帳密。"
               "如果其實是真的機密，再照下面處理：" + fix)
    elif code or git == "tracked":
        # 程式碼 / 已提交的檔案：封存刪檔會讓專案壞掉，也清不掉 git 歷史，真正的處理是撤銷 + 改讀環境變數
        fix = ("① 到服務後台撤銷並更換這個機密%s。"
               "② 程式改成從環境變數讀取，新值放進 .env.tpl 的 op:// 引用，執行時由 1Password 注入（可以用修復動作「🧷 寫死的機密 → 1Password + .env.tpl」）。"
               "不要把整個檔案封存或刪除：%s。" % (
                   "（已提交到 git，歷史裡永遠有舊值）" if git == "tracked" else "",
                   "這是程式碼／設定檔，刪掉專案就無法執行" if code else "已提交到 git，刪掉也清不掉歷史")) + \
              ("③ 從 git 歷史移除（選擇性）：git filter-repo --invert-paths --path '%s'（會改寫歷史，先和團隊確認）。" %
               os.path.relpath(path, os.path.dirname(path)) if git == "tracked" else "")
    app = _app_cred_hint(path) if not fixture and git != "tracked" else None
    if app is not None:
        # App / 工具自己的憑證檔：程式每次執行都直接讀它，搬走 / 封存會讓 App 壞掉；要處理的是權限，或改用 App 提供的安全登入方式
        st = lstat_safe(path)
        loose = bool(st and group_or_world_readable(st))
        rel_h = os.path.relpath(os.path.realpath(path), os.path.realpath(HOME))
        if not loose and not cloud and rel_h.startswith(APP_CRED_KEEP):
            sev = "info"
        elif not loose and sev == "high":
            sev = "medium"
        notes.insert(0, "App / 工具自己的憑證檔（權限 %s%s）" % (mode_str(st) if st else "?", "，其他使用者可讀" if loose else "，只有你可讀"))
        fix = ("這是 App 自己會讀的憑證檔，不要搬進 1Password 後刪除、也不要封存：刪掉 App 就找不到、無法運作。"
               "① %s"
               "② %s"
               "③ 確認是你在用的 App 後，在報告標記為已確認無害（檔案內容改變時標記會自動失效）。"
               "④ 不再使用：%s" % (
                   "權限過寬，先改成只有你可讀：chmod 600 '%s'（或用修復動作「🔏 私鑰與 App 憑證檔權限」）。" % path if loose
                   else "權限已經是只有你可讀，這部分不用處理。",
                   app or "如果這個 App 支援用 1Password、系統鑰匙圈或短期憑證登入，改用那種方式，就不需要把長期金鑰放在檔案裡。",
                   _app_revoke(path)))
    ctx.inv("散落的機密檔案", rel, "%s | %s" % (",".join(sorted(hits)), file_fingerprint(path)))
    ctx.add(Finding(
        rule="file-secrets", severity=sev, category=CAT,
        title="檔案裡寫死了 %d 種機密：%s" % (len(hits), "、".join(h[0] for h in kinds[:3]) + ("…" if len(kinds) > 3 else "")),
        path=rel, detail=detail + ("　｜　" + "；".join(notes) if notes else ""),
        why="寫死在文件或程式裡的連線字串、token 會被備份、同步、複製到別的專案，也會被任何讀得到檔案的程式（包括 AI 助手）看到。",
        fix=fix))


def check_env_file(ctx: ScanContext, path: str):
    text = read_text(path, ctx)
    if text is None:
        return
    has_real = any(not is_placeholder(m.group(2)) for m in GENERIC_ASSIGN.finditer(text)) or \
        any(rx.search(text) for _, _, rx, _ in SECRET_RULES)
    if not has_real:
        return
    ctx.add(Finding(
        rule="plaintext-env", severity="medium", category=CAT,
        title="明文 .env 檔案", path=home_rel(path),
        detail="檔案內有看起來是真實值的機密變數。",
        why="明文 .env 會讓機密一直留在磁碟上，被任何程式（包括被操控的 AI 代理）讀到就會外洩。",
        fix="確認 1Password 已有對應項目後刪除此檔，改用 1Password（.env.tpl + op inject / op run）等密碼管理工具注入。",
    ))
    report_secrets(ctx, path, text, generic=True)


def check_private_key_file(ctx: ScanContext, path: str):
    st = lstat_safe(path)
    if st is None or not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024:
        return
    text = read_text(path, ctx, limit=64 * 1024)
    if not text or "PRIVATE KEY" not in text:
        return
    encrypted = key_is_encrypted(text)
    in_ssh = path.startswith(os.path.join(HOME, ".ssh") + os.sep)
    fixture = is_fixture_path(path)
    if group_or_world_readable(st):
        ctx.add(Finding(
            rule="key-perm", severity="low" if fixture else "high", category=CAT, title="私鑰權限過寬",
            path=home_rel(path), detail="目前權限 %s，其他使用者可讀。" % mode_str(st),
            why="私鑰應只有自己可讀。", fix="chmod 600 '%s'" % path))
    if encrypted is False:
        ctx.add(Finding(
            rule="key-unencrypted", severity="low" if fixture else ("medium" if in_ssh else "high"), category=CAT,
            title="私鑰沒有密碼保護" + ("（測試／範例／第三方套件目錄）" if fixture else "" if in_ssh else "（且不在 ~/.ssh）"),
            path=home_rel(path),
            why="沒有密碼保護的私鑰，被複製走就能直接使用。",
            fix="ssh-keygen -p -f '%s'（加上密碼），或改用 1Password SSH Agent。" % path))


def key_is_encrypted(text: str):
    if "ENCRYPTED" in text:
        return True
    m = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END", text, re.S)
    if m:
        try:
            raw = base64.b64decode("".join(m.group(1).split()))
        except Exception:
            return None
        magic = b"openssh-key-v1\x00"
        if raw.startswith(magic):
            n = int.from_bytes(raw[len(magic):len(magic) + 4], "big")
            cipher = raw[len(magic) + 4:len(magic) + 4 + n]
            return cipher != b"none"
        return None
    if re.search(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", text):
        return False
    return None


CRED_FILES = [
    # (路徑, 說明, 純文字儲存是否本身就是問題)
    ("~/.git-credentials", "git 明文帳密", True),
    ("~/.netrc", "netrc 明文帳密", True),
    ("~/.aws/credentials", "AWS 憑證", False),
    ("~/.npmrc", "npm token", False),
    ("~/.pypirc", "PyPI 憑證", False),
    ("~/.docker/config.json", "Docker 登入資訊", False),
    ("~/.config/gh/hosts.yml", "GitHub CLI token", False),
    ("~/.kube/config", "Kubernetes 憑證", False),
    ("~/.codex/auth.json", "Codex 登入憑證", False),
    ("~/.config/gcloud/application_default_credentials.json", "gcloud ADC 憑證", False),
]


def check_credential_files(ctx: ScanContext):
    ctx.report("機密與憑證", "憑證檔")
    for p, desc, always_bad in CRED_FILES:
        path = os.path.expanduser(p)
        st = lstat_safe(path)
        if st is None:
            continue
        if group_or_world_readable(st):
            ctx.add(Finding(
                rule="cred-perm", severity="medium", category=CAT, title="%s 權限過寬" % desc,
                path=p, detail="目前權限 %s。" % mode_str(st),
                why="其他使用者或服務帳號可以讀取。", fix="chmod 600 %s" % p))
        text = read_text(path, ctx) or ""
        if always_bad and text.strip():
            ctx.add(Finding(
                rule="cred-plaintext", severity="high", category=CAT, title="%s" % desc, path=p,
                why="帳號密碼以明文存在檔案中。",
                fix="改用 macOS 鑰匙圈：git config --global credential.helper osxkeychain，然後刪除此檔。"))
        if p.endswith("docker/config.json") and '"auth"' in text and "credsStore" not in text:
            ctx.add(Finding(
                rule="docker-plain-auth", severity="medium", category=CAT,
                title="Docker 登入資訊以 base64 明文儲存", path=p,
                why="base64 不是加密，任何人都能還原帳密。",
                fix='在 config.json 設定 "credsStore": "osxkeychain" 後重新 docker login。'))
        if p.endswith(".npmrc") and "_authToken" in text and "${" not in text:
            ctx.add(Finding(
                rule="npm-token", severity="medium", category=CAT, title="npm token 明文存在 ~/.npmrc",
                path=p, why="npm token 被盜可以發佈惡意套件版本（供應鏈攻擊）。",
                fix="改用環境變數 ${NPM_TOKEN} 引用，並在 npmjs.com 啟用 2FA 與限制 token 權限。"))


def _socket_owners(d):
    """{socket 路徑: 使用它的程式（ps 顯示的指令）}；只看 d 底下的 socket。"""
    import subprocess
    from .core import safe_env
    out = {}
    try:
        txt = subprocess.run(["lsof", "-nP", "-U", "-F", "pn"], capture_output=True, text=True, timeout=15, env=safe_env()).stdout
    except (OSError, subprocess.TimeoutExpired):
        return out
    pid = None
    for line in txt.splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("n") and line[1:].startswith(d + "/") and pid and line[1:] not in out:
            try:
                cmd = subprocess.run(["ps", "-o", "command=", "-p", pid], capture_output=True, text=True, timeout=5,
                                     env=safe_env()).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                cmd = ""
            out[line[1:]] = cmd
    return out


def check_ssh_dir(ctx: ScanContext):
    ctx.report("機密與憑證", "~/.ssh")
    d = os.path.join(HOME, ".ssh")
    st = lstat_safe(d)
    if st is None:
        return
    if stat.S_IMODE(st.st_mode) & 0o077:
        ctx.add(Finding(rule="ssh-dir-perm", severity="medium", category=CAT, title="~/.ssh 資料夾權限過寬",
                        path="~/.ssh", detail="目前權限 %s。" % mode_str(st), fix="chmod 700 ~/.ssh"))
    try:
        names = os.listdir(d)
    except OSError:
        return
    owners = None
    for n in names:
        p = os.path.join(d, n)
        st_n = lstat_safe(p)
        if st_n is not None and stat.S_ISSOCK(st_n.st_mode):
            if owners is None:
                owners = _socket_owners(d)
            # OpenSSH 先綁在「路徑.隨機字串」再改名，lsof 看到的常是改名前的名稱
            who = owners.get(p) or next((v for k, v in owners.items() if k.startswith(p + ".")), "")
            # ssh 連線共用（ControlMaster）的 socket：每次 ssh 連線都會新建、斷線就消失
            # （例如 Warp 終端機的 SSH 會在 ~/.ssh 用隨機數字建一個），不放進清單，免得每次連線都被當成新增
            if re.match(r"^ssh: .* \[mux\]$", who):
                continue
            ctx.inv("~/.ssh 檔案", n, "socket owner=%s" % (who.split()[0] if who else "（沒有程式在使用，可能是殘留）"))
            continue
        ctx.inv("~/.ssh 檔案", n, file_fingerprint(p))
        if n.endswith(".pub") or n in ("known_hosts", "known_hosts.old", "config", "authorized_keys"):
            continue
        check_private_key_file(ctx, p)
    ak = os.path.join(d, "authorized_keys")
    text = read_text(ak, ctx)
    if text:
        keys = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
        import hashlib
        for k in keys:
            parts = k.split()
            ktype = next((x for x in parts if x.startswith(("ssh-", "ecdsa-", "sk-"))), "?")
            body = parts[parts.index(ktype) + 1] if ktype in parts and parts.index(ktype) + 1 < len(parts) else k
            comment = " ".join(parts[parts.index(ktype) + 2:]) if ktype in parts else ""
            opts = parts[0] if ktype in parts and parts.index(ktype) > 0 else ""
            ctx.inv("authorized_keys 公鑰", "%s %s（%s）" % (ktype, comment[:40] or "無註解", hashlib.sha256(body.encode()).hexdigest()[:12]),
                    ("選項：" + opts[:80]) if opts else "present")
            if re.search(r"command=|environment=|permitopen=", opts):
                ctx.add(Finding(rule="ssh-key-command", severity="high", category=CAT,
                                title="authorized_keys 中有附帶指令或環境變數的公鑰", path="~/.ssh/authorized_keys",
                                evidence=opts[:80], why="攻擊者常用 command= 讓登入時自動執行後門。",
                                fix="確認這把公鑰的來源，不認得就刪除該行。"))
        ctx.add(Finding(
            rule="ssh-authorized-keys", severity="low" if keys else "info", category=CAT,
            title="authorized_keys 有 %d 把公鑰可登入本機" % len(keys), path="~/.ssh/authorized_keys",
            detail="；".join(k.split()[-1][:40] for k in keys[:10]),
            why="攻擊者常在這裡加一把自己的公鑰當後門。請確認每一把都是你認得的。",
            fix="刪除不認得的行；若沒開遠端登入，可以整個清空。"))
    n_keys = len([l for l in (text or "").splitlines() if l.strip() and not l.startswith("#")])
    check_ssh_config(ctx, d)
    check_remote_login(ctx, n_keys)


# ~/.ssh/config 裡可以夾帶指令或開通道的設定：(指令, 風險, 說明)
SSH_RISKY = {
    "proxycommand": ("medium", "每次連線前會先執行這個指令（正常用途：跳板機、cloudflared、AWS SSM）"),
    "localcommand": ("high", "連線成功後在你的電腦上執行這個指令（要搭配 PermitLocalCommand yes 才會生效）"),
    "permitlocalcommand": ("medium", "允許 LocalCommand 執行指令"),
    "remoteforward": ("medium", "把遠端主機的連接埠轉回你的電腦（反向通道：別人可以從那台主機連進你的電腦）"),
    "dynamicforward": ("low", "在你的電腦開一個 SOCKS 代理"),
    "localforward": ("low", "把你電腦的連接埠轉到遠端"),
    "knownhostscommand": ("medium", "驗證主機時執行指令"),
}
SSH_CMD_BAD = re.compile(r"\b(?:curl|wget|nc|ncat|socat|bash\s+-c|sh\s+-c|zsh\s+-c|python[\d.]*\s+-c|perl\s+-e|osascript|base64)\b|/tmp/|/private/tmp/|/Users/Shared/")


def check_ssh_config(ctx: ScanContext, d):
    """分析 ~/.ssh/config（含 Include 進來的檔案）：會執行指令或開通道的設定逐行列出，內容一改就會在變動裡標 ⚠️。"""
    import glob
    files, seen = [os.path.join(d, "config")], set()
    while files:
        p = files.pop(0)
        if p in seen or not os.path.isfile(p):
            continue
        seen.add(p)
        text = read_text(p, ctx) or ""
        host = "（全部主機）"
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(\w+)\s*=?\s*(.*)$", line)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2).strip()
            if key in ("host", "match"):
                host = line[:80]
                if key == "match" and re.search(r"\bexec\b", val, re.I):
                    _ssh_cfg_finding(ctx, p, i, line, "medium", "Match exec：比對主機時會執行指令", host)
                continue
            if key == "include":
                for pat in val.split():
                    pat = os.path.expanduser(pat)
                    files += sorted(glob.glob(pat if os.path.isabs(pat) else os.path.join(d, pat)))
                continue
            if key in SSH_RISKY:
                if key == "permitlocalcommand" and val.lower() != "yes":
                    continue
                sev, why = SSH_RISKY[key]
                if SSH_CMD_BAD.search(val):
                    sev = "high"
                    why += "；⚠️ 指令裡有下載工具、shell、暫存資料夾這類常見於後門的寫法"
                _ssh_cfg_finding(ctx, p, i, line, sev, why, host)


def _mask_tokens(t):
    """只遮罩看起來像金鑰 / token 的長字串（20 個字以上的英數混合），其他保持可讀。"""
    return re.sub(r"[A-Za-z0-9_\-+/=]{20,}", lambda m: m.group(0)[:4] + "****" + m.group(0)[-4:], t)


def _ssh_cfg_finding(ctx, p, i, line, sev, why, host):
    rel = home_rel(p)
    mask = _mask_tokens
    ctx.inv("~/.ssh/config 指令", "%s:%d %s" % (rel, i, mask(line)[:160]), host)
    ctx.add(Finding(rule="ssh-config-" + line.split()[0].lower()[:20], severity=sev, category=CAT,
                    title="%s 有 %s 設定" % (rel, line.split()[0]), path=rel,
                    detail="第 %d 行（%s）：%s\n%s" % (i, host, mask(line)[:300], why),
                    why="~/.ssh/config 可以讓每次 ssh 連線自動執行指令或開通道，攻擊者會用它植入後門、把你的電腦接到他的主機。",
                    fix="確認這一行是你自己加的、知道它的用途；不認得就刪除，並檢查最近有沒有不明的 ssh 連線。"))


def check_remote_login(ctx: ScanContext, n_keys=0):
    """macOS「遠端登入」（SSH 伺服器）有沒有開：看有沒有程式在聽 TCP 22。從關閉變成開啟會在變動裡標 ⚠️。"""
    import subprocess
    try:
        out = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    on = any(re.search(r"[.:]22\s+\S+\s+LISTEN\b", l) for l in out.splitlines())
    ctx.inv("遠端登入（SSH 伺服器）", "狀態", "開啟" if on else "關閉")
    if on:
        ctx.add(Finding(rule="remote-login-on", severity="medium" if n_keys else "low", category=CAT,
                        title="遠端登入（SSH 伺服器）是開著的" + ("，而且 authorized_keys 有 %d 把公鑰" % n_keys if n_keys else ""),
                        path="系統設定 → 一般 → 共享 → 遠端登入",
                        detail="有程式在聽 TCP 22，別人可以用 SSH 連進這台電腦%s。" % ("（authorized_keys 裡的公鑰不需要密碼）" if n_keys else ""),
                        why="遠端登入加上一把不認得的公鑰，就是一個完整的後門；沒有在用的話建議關掉。",
                        fix="不需要時到「系統設定 → 一般 → 共享」關閉「遠端登入」；需要的話確認 authorized_keys 每一把都認得。"))

