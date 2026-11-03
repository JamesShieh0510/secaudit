"""B. 機密與憑證檢查。"""
import base64
import os
import re
import stat

from .core import (HOME, Finding, ScanContext, file_fingerprint, home_rel, lstat_safe, mask, mode_str,
                   group_or_world_readable, read_text)
from .rules import SECRET_RULES, GENERIC_ASSIGN, is_placeholder

CAT = "機密與憑證"


def find_secrets(text: str, generic: bool = False):
    """回傳 {rule_id: (名稱, severity, [行號], 第一個遮罩值)}。"""
    hits = {}
    lines = None
    for rid, name, rx, sev in SECRET_RULES:
        for m in rx.finditer(text):
            if lines is None:
                lines = text
            ln = text.count("\n", 0, m.start()) + 1
            ev = "（私鑰內容不顯示）" if rid == "private-key" else mask(m.group(0))
            h = hits.setdefault(rid, [name, sev, [], ev])
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
    if group_or_world_readable(st):
        ctx.add(Finding(
            rule="key-perm", severity="high", category=CAT, title="私鑰權限過寬",
            path=home_rel(path), detail="目前權限 %s，其他使用者可讀。" % mode_str(st),
            why="私鑰應只有自己可讀。", fix="chmod 600 '%s'" % path))
    if encrypted is False:
        ctx.add(Finding(
            rule="key-unencrypted", severity="medium" if in_ssh else "high", category=CAT,
            title="私鑰沒有密碼保護" + ("" if in_ssh else "（且不在 ~/.ssh）"),
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
    for n in names:
        p = os.path.join(d, n)
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
