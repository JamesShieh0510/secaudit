"""掃描流程：固定位置檢查（system）+ 遍歷目標資料夾（walk）+ 連網查詢（online）。"""
import json
import os
import socket
import stat
import time

from . import checks_ai, checks_browser, checks_persistence, checks_secrets, checks_threats, supply_chain
from .core import HOME, PRUNE_DIRS, ScanContext, Target, is_dataless
from .rules import (AI_INSTRUCTION_FILES, CONTENT_EXTS, CONTENT_NAMES, ENV_FILE_RE, ENV_SAFE_SUFFIX,
                    PRIVATE_KEY_NAMES)

# 家目錄底下另外處理、或內容不需要遍歷的位置
HOME_PRUNE_ABS = {os.path.join(HOME, p) for p in (
    "Library", ".claude", ".codex", ".cursor", ".vscode", ".npm", ".Trash", ".local/share", ".docker",
    ".ollama", "go/pkg", "miniconda3", "anaconda3", ".conda", ".pyenv", ".rustup", ".cargo", ".gradle",
    ".m2", ".android", ".cocoapods", ".gem", ".bundle", ".nvm", ".bun", ".deno", ".ssh", ".orbstack",
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


def walk_target(ctx: ScanContext, t: Target, lockfiles: list, ransom=None):
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
            ext = os.path.splitext(fn)[1].lower()
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
                elif ext in CONTENT_EXTS or fn in CONTENT_NAMES:
                    text = checks_secrets.read_text(p, ctx)
                    if text:
                        checks_secrets.report_secrets(ctx, p, text)
            except Exception:  # 單一檔案出錯不影響整體掃描
                ctx.stats["errors"] += 1


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
               checks_threats.check_odd_executables, checks_threats.check_ransom_quick):
        if ctx.cancel.is_set():
            break
        fn(ctx)
    if not ctx.cancel.is_set():
        checks_ai.check_transcripts(ctx, cache.setdefault("transcripts", {}))

    lockfiles = []
    ransom = checks_threats.RansomTracker()
    if mode == "full":
        ctx.scope = "walk"
        for t in ctx.targets:
            if ctx.cancel.is_set():
                break
            if not os.path.isdir(t.path):
                ctx.report("略過", "%s 不存在或未掛載" % t.path)
                continue
            ctx.report("掃描 " + t.label, t.path)
            walk_target(ctx, t, lockfiles, ransom)

    if mode == "full":
        ctx.scope = "walk"
        ransom.report(ctx)

    if online and not ctx.cancel.is_set():
        ctx.scope = "online"
        osv = cache.setdefault("osv", {})
        supply_chain.check_runtimes(ctx, osv)
        supply_chain.check_global_npm(ctx, osv)
        if mode == "full":
            ctx.scope = "walk"   # 專案相依套件跟著 walk 結果比對
            supply_chain.check_dependencies(ctx, lockfiles, osv)

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
