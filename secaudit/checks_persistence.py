"""C. 開機自動執行（持久化）檢查：LaunchAgents/Daemons、crontab、shell 啟動檔。"""
import os
import plistlib
import re
import subprocess

from .core import HOME, Finding, ScanContext, file_fingerprint, home_rel, read_text, safe_env, truncate
from .rules import SUSPICIOUS_CMDS
from .checks_secrets import report_secrets

CAT = "開機自動執行"

LAUNCH_DIRS = [
    ("~/Library/LaunchAgents", "使用者 LaunchAgent"),
    ("/Library/LaunchAgents", "全域 LaunchAgent"),
    ("/Library/LaunchDaemons", "LaunchDaemon（root 權限）"),
]
ODD_LOCATIONS = re.compile(r"^(?:/tmp/|/private/tmp/|/private/var/tmp/|/var/tmp/|/Users/Shared/)|/Downloads/|/\.[^/]+/[^/]+$")
SHELLS = {"sh", "bash", "zsh", "python", "python3", "osascript", "perl", "ruby", "node"}


def _signature(path: str) -> str:
    """回傳 'apple' / '<Team ID>' / 'unsigned' / 'missing'。"""
    if not os.path.exists(path):
        return "missing"
    try:
        r = subprocess.run(["codesign", "-dv", "--verbose=2", path], capture_output=True, text=True, timeout=10, env=safe_env())
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    out = r.stderr
    if r.returncode != 0:
        return "unsigned"
    m = re.search(r"TeamIdentifier=(\S+)", out)
    if "Authority=Software Signing" in out or "Authority=Apple Mac OS Application Signing" in out:
        return "apple"
    if m and m.group(1) != "not":
        return m.group(1)
    return "adhoc"


def check_launch_items(ctx: ScanContext):
    for d, label in LAUNCH_DIRS:
        base = os.path.expanduser(d)
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        ctx.report(CAT, label)
        for n in names:
            if not n.endswith(".plist"):
                continue
            p = os.path.join(base, n)
            try:
                with open(p, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                ctx.add(Finding(rule="launch-unparsable", severity="low", category=CAT, title="無法解析的 %s" % label,
                                path=home_rel(p), fix="手動檢查此檔。"))
                continue
            args = [str(a) for a in (pl.get("ProgramArguments") or [])]
            prog = str(pl.get("Program") or (args[0] if args else ""))
            cmdline = " ".join(args) if args else prog
            disabled = bool(pl.get("Disabled"))
            sig = _signature(prog) if prog.startswith("/") else "unknown"
            ctx.inv(label, n, "%s | sig=%s | %s%s" % (truncate(cmdline, 160), sig, file_fingerprint(p), " | disabled" if disabled else ""))

            sev, reasons = "info", []
            if ODD_LOCATIONS.search(prog):
                sev, reasons = "high", reasons + ["執行檔放在暫存、共享、下載或隱藏資料夾"]
            if sig == "missing":
                sev = max_sev(sev, "low")
                reasons.append("執行檔不存在（可能是移除不完全的殘留）")
            elif sig in ("unsigned", "adhoc"):
                sev = max_sev(sev, "low")
                reasons.append("執行檔沒有開發者簽章")
            if os.path.basename(prog) in SHELLS or os.path.basename(args[0] if args else "") in SHELLS:
                reasons.append("透過直譯器執行腳本")
                sev = max_sev(sev, "low")
            for rid, rx, s, desc in SUSPICIOUS_CMDS:
                if rx.search(cmdline):
                    sev = max_sev(sev, s)
                    reasons.append(desc)
            ctx.add(Finding(
                rule="launch-item", severity=sev, category=CAT,
                title="%s：%s%s" % (label, pl.get("Label", n), "（已停用）" if disabled else ""),
                path=home_rel(p), detail="；".join(reasons) or "簽章：%s" % sig, evidence=truncate(cmdline, 160),
                why="開機或登入時自動執行，是惡意程式最常用的常駐方式。請確認每一項你都認得。",
                fix="不認得：launchctl bootout gui/$(id -u) '%s' 後刪除 plist（/Library 底下需要 sudo）。" % p))


def max_sev(a: str, b: str) -> str:
    order = ["info", "low", "medium", "high"]
    return a if order.index(a) >= order.index(b) else b


def check_crontab(ctx: ScanContext):
    ctx.report(CAT, "crontab")
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10, env=safe_env())
    except (OSError, subprocess.TimeoutExpired):
        return
    lines = [l for l in r.stdout.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    for l in lines:
        ctx.inv("crontab", truncate(l, 160), "present")
        sev, reason = "info", "定時自動執行的工作，請確認是你設定的。"
        for rid, rx, s, desc in SUSPICIOUS_CMDS:
            if rx.search(l):
                sev, reason = s, desc
                break
        ctx.add(Finding(rule="cron", severity=sev, category=CAT, title="crontab 排程", evidence=truncate(l),
                        why=reason, fix="crontab -e 移除不認得的行。"))


SHELL_RC = ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.zlogin", "~/.bashrc", "~/.bash_profile",
            "~/.profile", "~/.config/fish/config.fish", "/etc/zshrc", "/etc/zprofile", "/etc/profile"]


def check_shell_rc(ctx: ScanContext):
    ctx.report(CAT, "shell 啟動檔")
    for p in SHELL_RC:
        path = os.path.expanduser(p)
        text = read_text(path, ctx)
        if text is None:
            continue
        ctx.inv("shell 啟動檔", p, file_fingerprint(path))
        for rid, rx, sev, desc in SUSPICIOUS_CMDS:
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[ln - 1] if ln - 1 < len(text.splitlines()) else ""
                ctx.add(Finding(rule="rc-" + rid, severity=sev, category=CAT,
                                title="%s 第 %d 行：%s" % (p, ln, desc), path=p, evidence=truncate(line),
                                why="每開一個終端機就會執行；也會影響 AI 代理開出的 shell。",
                                fix="確認是你加的；不是就刪除該行並追查來源。"))
                break
        report_secrets(ctx, path, text, category="機密與憑證", generic=True, context_note="（shell 啟動檔）")
