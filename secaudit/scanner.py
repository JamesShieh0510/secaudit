"""掃描流程：固定位置檢查（system）+ 遍歷目標資料夾（walk）+ 連網查詢（online）。"""
import json
import os
import socket
import stat
import time

from . import checks_ai, checks_browser, checks_resources, checks_persistence, checks_secrets, checks_threats, runtimes, supply_chain
from .core import HOME, PRUNE_DIRS, ScanContext, Target, is_dataless
from .rules import (AI_INSTRUCTION_FILES, CONTENT_EXTS, CONTENT_NAMES, ENV_FILE_RE, ENV_SAFE_SUFFIX,
                    PRIVATE_KEY_NAMES)

SELF_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# 家目錄底下另外處理、或內容不需要遍歷的位置
HOME_PRUNE_ABS = {os.path.join(HOME, p) for p in (
    "Library", ".claude", ".codex", ".cursor", ".vscode", ".npm", ".Trash", ".local/share", ".docker",
    ".ollama", "go/pkg", "miniconda3", "anaconda3", ".conda", ".pyenv", ".rustup", ".cargo", ".gradle",
    ".m2", ".android", ".cocoapods", ".gem", ".bundle", ".nvm", ".bun", ".deno", ".ssh", ".orbstack",
    # 工具自己管理的安裝目錄 / 本機叢集憑證（不是你的專案）
    "google-cloud-sdk", "sdk", ".minikube",
)}


def default_targets():
    """家目錄 + 偵測到的雲端硬碟（預設不勾）+ /Volumes 底下的外接/網路磁碟（預設不勾）。"""
    ts = [Target(HOME, "家目錄（不含 ~/Library 與雲端硬碟）", "home", True)]
    icloud = os.path.join(HOME, "Library", "Mobile Documents", "com~apple~CloudDocs")
    if os.path.isdir(icloud):
        ts.append(Target(icloud, "iCloud Drive", "cloud", False))
    cs = os.path.join(HOME, "Library", "CloudStorage")
    if os.path.isdir(cs):
        for n in sorted(os.listdir(cs)):
            p = os.path.join(cs, n)
            if os.path.isdir(p) and not n.startswith("."):
                ts.append(Target(p, n.replace("-", " ", 1), "cloud", False))
    try:
        for n in sorted(os.listdir("/Volumes")):
            p = os.path.join("/Volumes", n)
            if os.path.ismount(p) and os.path.realpath(p) != "/":
                ts.append(Target(p, "磁碟：" + n, "volume", False))
    except OSError:
        pass
    return ts


def walk_target(ctx: ScanContext, t: Target, lockfiles: list, ransom=None, pins=None):
    seen = 0
    is_home = os.path.realpath(t.path) == os.path.realpath(HOME)
    for dp, dns, fns in os.walk(t.path, onerror=lambda e: ctx.stats.__setitem__("errors", ctx.stats["errors"] + 1)):
        if ctx.cancel.is_set():
            return
        keep = []
        for d in dns:
            full = os.path.join(dp, d)
            if d in PRUNE_DIRS or (is_home and full in HOME_PRUNE_ABS) or os.path.islink(full):
                continue
            base = os.path.basename(dp)
            # AI 代理的暫時 worktree（專案的複本）、Go 模組快取（含備份碟裡的）、secaudit 自己的報告
            if (d == "worktrees" and base == ".claude") or (d == "mod" and base == "pkg") or full == SELF_DATA:
                continue
            keep.append(d)
        dns[:] = keep
        ctx.stats["dirs_seen"] += 1
        if ctx.stats["dirs_seen"] % 200 == 0:
            ctx.report("掃描 " + t.label, dp)
        for fn in fns:
            seen += 1
            ctx.stats["files_seen"] += 1
            if seen > ctx.max_files_per_target:
                ctx.report("掃描 " + t.label, "已達檔案數上限，停止此目標")
                return
            p = os.path.join(dp, fn)
            if ransom is not None:
                ransom.feed(dp, fn)
            check_file(ctx, p, lockfiles, pins)

def check_file(ctx: ScanContext, p: str, lockfiles: list, pins=None):
    """單一檔案的所有內容檢查（完整掃描逐檔呼叫；重新檢查舊報告時也只對問題檔案呼叫這裡）。"""
    dp, fn = os.path.split(p)
    ext = os.path.splitext(fn)[1].lower()
    if pins is not None and runtimes.is_pin_file(fn):
        pins.append(p)      # 版本檔另外收集，不影響下面原本的檢查
    try:
        if ENV_FILE_RE.match(fn) and not fn.endswith(ENV_SAFE_SUFFIX):
            checks_secrets.check_env_file(ctx, p)
        elif PRIVATE_KEY_NAMES.match(fn):
            checks_secrets.check_private_key_file(ctx, p)
        elif fn in AI_INSTRUCTION_FILES:
            checks_ai.check_ai_instruction_file(ctx, p)
        elif fn == ".mcp.json":
            checks_ai.analyze_mcp_file(ctx, p)
        elif fn in ("settings.json", "settings.local.json") and os.path.basename(dp) == ".claude":
            checks_ai.check_claude_settings_file(ctx, p)
        elif fn in supply_chain.LOCKFILES:
            lockfiles.append(p)
        elif ext in CONTENT_EXTS or fn in CONTENT_NAMES or (not ext and not fn.startswith(".")):
            # 沒有副檔名的檔案（例如 notes、prod-config）只看 256KB 以下的純文字檔；二進位檔 read_text 會略過
            text = checks_secrets.read_text(p, ctx) if (ext or fn in CONTENT_NAMES) else \
                checks_secrets.read_text(p, ctx, limit=256 * 1024)
            if text:
                checks_secrets.report_file_secrets(ctx, p, text)
    except Exception:  # 單一檔案出錯不影響整體掃描
        ctx.stats["errors"] += 1


def pruned_by_rules(path: str) -> bool:
    """這個路徑在目前的規則下，完整掃描根本不會走到（被排除的資料夾）。"""
    parts = path.split(os.sep)
    for i, d in enumerate(parts[:-1]):
        base = parts[i - 1] if i else ""
        full = os.sep.join(parts[:i + 1])
        # 不看 HOME_PRUNE_ABS：雲端硬碟目標本來就在 ~/Library 底下
        if d in PRUNE_DIRS or full == SELF_DATA or \
                (d == "worktrees" and base == ".claude") or (d == "mod" and base == "pkg"):
            return True
    return False


def _check_secure_settings(ctx):
    """封存機密檔案的目的地（vault、DMG 資料夾）決定機密被送去哪裡：繞過 Web UI 直接改設定檔也要出現 ⚠️ 變動。"""
    from .app import load_config
    cfg = load_config()
    ctx.inv("secaudit 封存設定", "1Password vault", str(cfg.get("secure_vault", "")))
    ctx.inv("secaudit 封存設定", "DMG 資料夾", str(cfg.get("secure_dir", "")))


def _check_auth_keys(ctx):
    """把授權修復動作用的 YubiKey 列進清單快照：新增 / 更換金鑰會變成 ⚠️ 變動（不論是不是從 Web UI 改的）。"""
    import hashlib
    from .app import DATA, _read
    for k in _read(os.path.join(DATA, "webauthn.json"), {}).get("keys", []):
        ctx.inv("secaudit 授權金鑰", "%s（%s）" % (k.get("name", ""), str(k.get("id", ""))[:12]),
                hashlib.sha256(str(k.get("pem", "")).encode()).hexdigest()[:16])
    roots = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yubico_fido_roots.pem")
    try:
        with open(roots, "rb") as fh:
            ctx.inv("secaudit 授權金鑰", "Yubico 根憑證（yubico_fido_roots.pem）", hashlib.sha256(fh.read()).hexdigest()[:16])
    except OSError:
        ctx.inv("secaudit 授權金鑰", "Yubico 根憑證（yubico_fido_roots.pem）", "檔案不存在")


def run_scan(targets, mode="full", cache=None, progress=None, cancel=None, online=True):
    """mode: full = 全部；quick = 只做固定位置檢查（給常駐程式頻繁執行）。"""
    cache = cache if cache is not None else {}
    ctx = ScanContext(targets=[t for t in targets if t.enabled], progress=progress)
    if cancel is not None:
        ctx.cancel = cancel
    started = time.time()

    ctx.scope = "system"
    for fn in (checks_ai.check_mcp, checks_ai.check_claude_settings, checks_ai.check_global_instruction_files,
               checks_ai.check_skills, checks_ai.check_telegram,
               checks_persistence.check_launch_items, checks_persistence.check_crontab, checks_persistence.check_shell_rc,
               checks_secrets.check_credential_files, checks_secrets.check_ssh_dir, checks_browser.check_browsers,
               checks_threats.check_odd_executables, checks_threats.check_ransom_quick,
               checks_resources.check_resources):
        if ctx.cancel.is_set():
            break
        fn(ctx)
    if not ctx.cancel.is_set():
        checks_ai.check_transcripts(ctx, cache.setdefault("transcripts", {}))
        _check_auth_keys(ctx)
        _check_secure_settings(ctx)

    lockfiles = []
    ransom = checks_threats.RansomTracker()
    pins = []
    if mode == "full":
        ctx.scope = "walk"
        for t in ctx.targets:
            if ctx.cancel.is_set():
                break
            if not os.path.isdir(t.path):
                ctx.report("略過", "%s 不存在或未掛載" % t.path)
                continue
            ctx.report("掃描 " + t.label, t.path)
            walk_target(ctx, t, lockfiles, ransom, pins)

    if mode == "full":
        ctx.scope = "walk"
        ransom.report(ctx)

    if online and not ctx.cancel.is_set():
        ctx.scope = "online"
        osv = cache.setdefault("osv", {})
        runtimes.check_installed(ctx, osv, online=True)
        supply_chain.check_global_npm(ctx, osv)
        if mode == "full":
            ctx.scope = "walk"   # 專案相依套件、專案指定版本跟著 walk 結果比對
            supply_chain.check_dependencies(ctx, lockfiles, osv)
            runtimes.check_project_pins(ctx, pins, osv, online=True)

    ctx.report("完成", "")
    return {
        "version": 1,
        "host": socket.gethostname(),
        "mode": mode,
        "cancelled": ctx.cancel.is_set(),
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_sec": round(time.time() - started, 1),
        "targets": [{"path": t.path, "label": t.label, "kind": t.kind} for t in ctx.targets] if mode == "full" else [],
        "scopes": ["system"] + (["walk"] if mode == "full" else []) + (["online"] if online else []),
        "stats": ctx.stats,
        "findings": [f.to_dict() for f in ctx.findings],
        "inventory": ctx.inventory,
    }



def _system_checks(ctx, cache):
    for fn in (checks_ai.check_mcp, checks_ai.check_claude_settings, checks_ai.check_global_instruction_files,
               checks_ai.check_skills, checks_ai.check_telegram,
               checks_persistence.check_launch_items, checks_persistence.check_crontab, checks_persistence.check_shell_rc,
               checks_secrets.check_credential_files, checks_secrets.check_ssh_dir, checks_browser.check_browsers,
               checks_threats.check_odd_executables, checks_threats.check_ransom_quick,
               checks_resources.check_resources):
        if ctx.cancel.is_set():
            return
        fn(ctx)
    checks_ai.check_transcripts(ctx, cache.setdefault("transcripts", {}))
    _check_auth_keys(ctx)
    _check_secure_settings(ctx)


def _old_paths(f):
    """舊報告問題的路徑（套件漏洞會用「；」列出多個專案，最後可能有「等 N 個專案」）。"""
    out = []
    for x in (f.get("path") or "").split("；"):
        x = x.split(" 等 ")[0].split("（")[0].strip()
        if x:
            out.append(os.path.expanduser(x))
    return out


# 重新檢查時：這些規則的問題只能靠完整掃描重新判定（例如要統計整個資料夾樹），沿用舊結果
CARRY_RULES = ("ransom-ext", "ransom-note")


def run_recheck(old, cache=None, progress=None, cancel=None, online=True):
    """針對舊報告提過的問題重新檢查（不重跑整份完整掃描）：
    固定位置全部重跑（很快）；遍歷到的問題只重看那些檔案 / 專案；套用目前的規則。"""
    from .checks_threats import BENIGN_EXT, BENIGN_NAMES
    from .core import is_fixture_path, home_rel
    cache = cache if cache is not None else {}
    ctx = ScanContext(targets=[], progress=progress)
    if cancel is not None:
        ctx.cancel = cancel
    started = time.time()
    ctx.scope = "system"
    ctx.report("重新檢查", "固定位置")
    _system_checks(ctx, cache)

    ctx.scope = "walk"
    files, projects, carried, excluded = set(), set(), [], []
    walk_old = [f for f in old.get("findings", []) + old.get("acknowledged", []) if f.get("scope") == "walk"]
    for f in walk_old:
        rule = f.get("rule", "")
        if rule in CARRY_RULES:
            sample = (f.get("detail") or "").rsplit("例如：", 1)[-1].strip().lower()
            ext = sample.rsplit(".", 1)[-1] if "." in sample else ""
            if sample in BENIGN_NAMES or ext in BENIGN_EXT or is_fixture_path(os.path.expanduser(f.get("path", "")) + "/"):
                excluded.append(f)
            else:
                carried.append(dict(f, detail="（沿用舊報告：這類問題要統計整個資料夾，需完整掃描才能重新確認）" + (f.get("detail") or "")))
            continue
        for p in _old_paths(f):
            if pruned_by_rules(p):
                continue
            if os.path.isdir(p):
                projects.add(p)
            else:
                files.add(p)
    lockfiles, pins = [], []
    for i, p in enumerate(sorted(files)):
        if ctx.cancel.is_set():
            break
        if i % 50 == 0:
            ctx.report("重新檢查檔案", "%d / %d" % (i, len(files)))
        if os.path.isfile(p) and not os.path.islink(p):
            check_file(ctx, p, lockfiles, pins)
    for d in sorted(projects):        # 套件漏洞、專案版本指定：只看專案資料夾第一層的 lockfile / 版本檔
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for fn in names:
            p = os.path.join(d, fn)
            if fn in supply_chain.LOCKFILES or runtimes.is_pin_file(fn):
                check_file(ctx, p, lockfiles, pins)

    if online and not ctx.cancel.is_set():
        osv = cache.setdefault("osv", {})
        ctx.scope = "online"
        runtimes.check_installed(ctx, osv, online=True)
        supply_chain.check_global_npm(ctx, osv)
        ctx.scope = "walk"
        supply_chain.check_dependencies(ctx, sorted(set(lockfiles)), osv)
        runtimes.check_project_pins(ctx, sorted(set(pins)), osv, online=True)
    for f in carried:
        ctx.findings.append(_finding_from_dict(f))
    ctx.report("完成", "")
    return {
        "version": 1, "host": socket.gethostname(), "mode": "recheck", "cancelled": ctx.cancel.is_set(),
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_sec": round(time.time() - started, 1),
        "targets": old.get("targets", []),
        "scopes": ["system", "walk"] + (["online"] if online else []),
        "stats": dict(ctx.stats, rechecked_files=len(files), rechecked_projects=len(projects)),
        "findings": [f.to_dict() for f in ctx.findings],
        "inventory": ctx.inventory,
        "_excluded_carry": [f for f in excluded],
    }


def _finding_from_dict(d):
    from .core import Finding
    import dataclasses
    names = {f.name for f in dataclasses.fields(Finding)}
    return Finding(**{k: v for k, v in d.items() if k in names})
