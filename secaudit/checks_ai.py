"""A. AI 工具與 Agent 檢查：MCP、Claude Code 設定、skills/plugins、指令檔、對話紀錄、Telegram channel。"""
import json
import os
import re

from .core import HOME, Finding, ScanContext, file_fingerprint, home_rel, lstat_safe, mask, read_text, truncate
from .rules import (AI_INSTRUCTION_FILES, HIDDEN_CHARS, HIDDEN_CHARS_HIGH, INJECTION_PHRASES, SECRET_RULES,
                    SUSPICIOUS_CMDS, is_placeholder)
from .checks_secrets import find_secrets

CAT = "AI 與 Agent"


def _load_json(path, ctx):
    text = read_text(path, ctx, limit=20 * 1024 * 1024)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


# ---------------------------------------------------------------- MCP
MCP_JSON_SOURCES = [
    ("~/Library/Application Support/Claude/claude_desktop_config.json", "Claude Desktop"),
    ("~/.cursor/mcp.json", "Cursor"),
    ("~/.codeium/windsurf/mcp_config.json", "Windsurf"),
    ("~/.gemini/settings.json", "Gemini CLI"),
    ("~/.config/Code/User/mcp.json", "VS Code"),
    ("~/Library/Application Support/Code/User/mcp.json", "VS Code"),
]
RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}


def analyze_mcp_server(ctx: ScanContext, source: str, name: str, cfg: dict):
    if not isinstance(cfg, dict):
        return
    cmd = str(cfg.get("command", "") or "")
    args = [str(a) for a in (cfg.get("args") or [])]
    url = str(cfg.get("url", "") or cfg.get("serverUrl", "") or "")
    desc = url if url else " ".join([cmd] + args)
    ctx.inv("MCP 伺服器", "%s ▸ %s" % (source, name), truncate(desc, 200))
    where = "%s 的 MCP「%s」" % (source, name)

    base = os.path.basename(cmd)
    if base in RUNNERS or (base in ("pnpm", "yarn", "bun") and "dlx" in args):
        pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "x", "run")]
        pkg = pkgs[0] if pkgs else ""
        pinned = bool(re.search(r".@\d", pkg)) or bool(re.search(r"==\d", pkg))
        if pkg and not pinned:
            ctx.add(Finding(
                rule="mcp-unpinned", severity="medium", category=CAT,
                title="%s 每次啟動都抓最新版套件" % where, path=source, evidence=truncate(desc),
                why="套件維護者帳號被盜或套件被搶注時，下一次啟動就會自動執行惡意版本（供應鏈攻擊）。",
                fix="把版本鎖死，例如 %s@<版本號>，升級時再手動改。" % pkg))
    if re.match(r"^(?:/tmp/|/private/tmp/|/Users/Shared/)", cmd) or "/Downloads/" in cmd:
        ctx.add(Finding(rule="mcp-odd-path", severity="high", category=CAT,
                        title="%s 從可疑位置執行" % where, path=source, evidence=truncate(desc),
                        why="暫存或下載資料夾裡的執行檔很可能是被放進來的。", fix="確認來源，不認得就移除。"))
    if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|\[::1\])", url):
        ctx.add(Finding(rule="mcp-http", severity="medium", category=CAT,
                        title="%s 用未加密的 HTTP 連線" % where, path=source, evidence=url,
                        why="中間人可以竄改工具回應，注入惡意指令給 AI。", fix="改用 https。"))
    for blob_name, blob in (("env", cfg.get("env")), ("headers", cfg.get("headers"))):
        if not isinstance(blob, dict):
            continue
        for k, v in blob.items():
            v = str(v)
            hit = find_secrets(v)
            sensitive_key = re.search(r"key|token|secret|password|auth", k, re.I)
            if hit or (sensitive_key and len(v) >= 12 and not is_placeholder(v)):
                ctx.add(Finding(
                    rule="mcp-inline-secret", severity="high", category=CAT,
                    title="%s 的 %s 直接寫了明文機密" % (where, blob_name), path=source,
                    evidence="%s=%s" % (k, mask(v)),
                    why="這個設定檔會被許多工具讀取、備份或同步，機密容易外洩。",
                    fix="改由 1Password 注入環境變數（op run），設定檔只保留變數名稱。"))
    for a in args:
        if find_secrets(a):
            ctx.add(Finding(rule="mcp-arg-secret", severity="high", category=CAT,
                            title="%s 的啟動參數含有機密" % where, path=source, evidence=mask(a),
                            why="啟動參數可被 ps 指令看到。", fix="改用環境變數傳入。"))


def analyze_mcp_file(ctx: ScanContext, path: str, source: str = ""):
    data = _load_json(path, ctx)
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if isinstance(servers, dict):
        for n, c in servers.items():
            analyze_mcp_server(ctx, source or home_rel(path), n, c)


def check_mcp(ctx: ScanContext):
    ctx.report("AI 與 Agent", "MCP 設定")
    cj = os.path.join(HOME, ".claude.json")
    data = _load_json(cj, ctx)
    if isinstance(data, dict):
        for n, c in (data.get("mcpServers") or {}).items():
            analyze_mcp_server(ctx, "~/.claude.json（全域）", n, c)
        for proj, pv in (data.get("projects") or {}).items():
            if isinstance(pv, dict):
                for n, c in (pv.get("mcpServers") or {}).items():
                    analyze_mcp_server(ctx, "~/.claude.json（%s）" % home_rel(proj), n, c)
    for p, label in MCP_JSON_SOURCES:
        path = os.path.expanduser(p)
        if os.path.exists(path):
            analyze_mcp_file(ctx, path, label)
    # Codex 用 TOML，Python 3.8 沒有 tomllib，用簡單解析
    toml = read_text(os.path.join(HOME, ".codex", "config.toml"), ctx)
    if toml:
        for m in re.finditer(r"^\[mcp_servers\.([^\].]+)\]\s*\n(.*?)(?=^\[(?!mcp_servers\.\1\.)|\Z)", toml, re.M | re.S):
            body = m.group(2)
            cmd = re.search(r'^command\s*=\s*"([^"]*)"', body, re.M)
            args = re.search(r"^args\s*=\s*\[(.*?)\]", body, re.M | re.S)
            url = re.search(r'^url\s*=\s*"([^"]*)"', body, re.M)
            env = dict(re.findall(r'^\s*([A-Za-z_][\w]*)\s*=\s*"([^"]*)"', body.split("[mcp_servers.%s.env]" % m.group(1))[-1], re.M)) \
                if "[mcp_servers.%s.env]" % m.group(1) in body else {}
            analyze_mcp_server(ctx, "~/.codex/config.toml", m.group(1), {
                "command": cmd.group(1) if cmd else "",
                "args": re.findall(r'"([^"]*)"', args.group(1)) if args else [],
                "url": url.group(1) if url else "", "env": env})


# ---------------------------------------------------------------- Claude Code settings
BROAD_ALLOW = re.compile(
    r"^(?:Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\((?:sh|bash|zsh|curl|wget|python3?|node|eval|sudo|rm|ssh|scp|nc|osascript|security|op)(?::\*|\s\*)?\)|WebFetch|Write|Edit|mcp__.*)$")


def check_claude_settings_file(ctx: ScanContext, path: str):
    data = _load_json(path, ctx)
    if not isinstance(data, dict):
        return
    src = home_rel(path)
    ctx.inv("AI 設定檔", src, file_fingerprint(path))
    perms = data.get("permissions") or {}
    allow = perms.get("allow") or []
    for rule in allow:
        ctx.inv("Claude Code 允許清單", "%s ▸ %s" % (src, rule), "allow")
        if BROAD_ALLOW.match(str(rule)):
            ctx.add(Finding(
                rule="cc-broad-allow", severity="medium", category=CAT,
                title="Claude Code 免確認執行：%s" % rule, path=src,
                why="被 prompt injection（例如惡意網頁、README、issue 內容）誘導時，AI 可以不經你確認就執行這類指令。",
                fix="從 permissions.allow 移除，或縮小到特定子指令（例如 Bash(npm test)）。"))
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode in ("bypassPermissions",):
        ctx.add(Finding(rule="cc-bypass", severity="high", category=CAT,
                        title="Claude Code 預設略過所有權限確認", path=src, evidence="defaultMode=%s" % mode,
                        why="任何 prompt injection 都能直接執行指令、讀寫檔案。", fix="移除 defaultMode 或改為 default。"))
    hooks = data.get("hooks") or {}
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            for e in entries if isinstance(entries, list) else []:
                for h in (e.get("hooks") or []) if isinstance(e, dict) else []:
                    cmd = str(h.get("command", ""))
                    ctx.inv("Claude Code hooks", "%s ▸ %s ▸ %s" % (src, event, truncate(cmd, 80)), truncate(cmd, 200))
                    sev, why = "info", "hook 會在每次對應事件自動執行，請確認是你自己設定的。"
                    for rid, rx, s, desc in SUSPICIOUS_CMDS:
                        if rx.search(cmd):
                            sev, why = ("high" if s == "high" else "medium"), "hook 內含可疑行為：%s。" % desc
                            break
                    ctx.add(Finding(rule="cc-hook", severity=sev, category=CAT,
                                    title="Claude Code hook（%s）" % event, path=src, evidence=truncate(cmd),
                                    why=why, fix="不認得就從 settings.json 的 hooks 移除。"))
    for k in ("enabledPlugins",):
        v = data.get(k)
        if isinstance(v, dict):
            for name, on in v.items():
                ctx.inv("已啟用 plugins", "%s ▸ %s" % (src, name), str(on))
    mk = data.get("extraKnownMarketplaces")
    if isinstance(mk, dict):
        for name, v in mk.items():
            ctx.inv("plugin marketplaces", "%s ▸ %s" % (src, name), truncate(json.dumps(v, ensure_ascii=False), 200))
    envs = data.get("env")
    if isinstance(envs, dict):
        for k, v in envs.items():
            if find_secrets(str(v)) or (re.search(r"key|token|secret", k, re.I) and not is_placeholder(str(v)) and len(str(v)) > 12):
                ctx.add(Finding(rule="cc-env-secret", severity="high", category=CAT,
                                title="Claude Code settings 的 env 含明文機密", path=src,
                                evidence="%s=%s" % (k, mask(str(v))), fix="改由 1Password 注入。"))


def check_claude_settings(ctx: ScanContext):
    ctx.report("AI 與 Agent", "Claude Code 設定")
    for p in ("~/.claude/settings.json", "~/.claude/settings.local.json"):
        path = os.path.expanduser(p)
        if os.path.exists(path):
            check_claude_settings_file(ctx, path)
    ip = os.path.expanduser("~/.claude/plugins/installed_plugins.json")
    data = _load_json(ip, ctx)
    if isinstance(data, dict):
        plugins = data.get("plugins", data)
        if isinstance(plugins, dict):
            for name, v in plugins.items():
                ver = ""
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    ver = str(v[0].get("version", "")) + " " + str(v[0].get("gitCommitSha", ""))[:10]
                ctx.inv("已安裝 plugins", name, ver.strip() or "installed")


# ---------------------------------------------------------------- skills / plugins / 指令檔
# 官方 marketplace：說明文件常「引用」攻擊語句當範例，只檢查高風險隱藏字元；
# 內容變動仍會透過快照比對發出警示
TRUSTED_MARKETPLACES = {"claude-plugins-official", "openai-bundled", "openai-primary-runtime"}
SCRIPT_EXTS = {".md", ".sh", ".py", ".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml", ".zsh", ".bash"}
SKILL_ROOTS = [
    ("~/.claude/skills", "Claude skills"), ("~/.claude/commands", "Claude 指令"),
    ("~/.claude/agents", "Claude subagents"), ("~/.claude/plugins/marketplaces", "Claude plugins"),
    ("~/.claude/plugins/cache", "Claude plugins"), ("~/.codex/skills", "Codex skills"),
    ("~/.codex/plugins", "Codex plugins"), ("~/.cursor/rules", "Cursor rules"),
]


def scan_agent_text(ctx: ScanContext, path: str, text: str, kind: str, strict: bool, trusted: bool = False):
    """skills / 指令檔共用：隱藏字元、injection 語句、可疑指令。
    strict=False：文件類檔案，可疑指令降一級。trusted=True：官方 marketplace，只保留高風險隱藏字元。"""
    src = home_rel(path)
    for rx, sev in ((HIDDEN_CHARS_HIGH, "high"), (HIDDEN_CHARS, "medium")):
        hidden = rx.findall(text)
        if not hidden or (trusted and sev != "high"):
            continue
        cps = sorted({"U+%04X" % ord(c) for c in hidden})
        ctx.add(Finding(
            rule="hidden-unicode", severity=sev, category=CAT,
            title="%s 含有 %d 個隱藏字元" % (kind, len(hidden)), path=src, evidence=", ".join(cps[:8]),
            why="人眼看不到、但 AI 讀得到的字元，可能被用來偷藏指令（Unicode tag / 方向控制字元風險最高）。",
            fix="用 cat -v 或編輯器的「顯示不可見字元」檢查；不是你加的就刪除，並追查來源。"))
    if trusted:
        return
    m = INJECTION_PHRASES.search(text)
    if m:
        ctx.add(Finding(rule="injection-phrase", severity="medium", category=CAT,
                        title="%s 含有疑似 prompt injection 語句" % kind, path=src,
                        evidence=truncate(text[max(0, m.start() - 30):m.end() + 30]),
                        why="這類語句試圖讓 AI 違背你的指示或瞞著你行動。", fix="確認內容是否是你寫的。"))
    seen = set()
    for rid, rx, sev, desc in SUSPICIOUS_CMDS:
        mm = rx.search(text)
        if mm and rid not in seen:
            seen.add(rid)
            s = sev if strict else {"high": "medium", "medium": "low", "low": "low"}[sev]
            ctx.add(Finding(rule="agent-" + rid, severity=s, category=CAT,
                            title="%s：%s" % (kind, desc), path=src,
                            evidence=truncate(text[max(0, mm.start() - 20):mm.end() + 40]),
                            why="AI 代理會依照這個檔案行動，等於讓檔案作者能在你的電腦執行這些操作。",
                            fix="閱讀上下文確認用途；來源不明的 skill/plugin 請移除。"))
    for rid, (name, sev, lns, ev) in find_secrets(text).items():
        ctx.add(Finding(rule="secret-" + rid, severity=sev, category=CAT, title="%s 內含%s" % (kind, name),
                        path=src, evidence=ev, detail="行號：%s" % lns[:5], fix="撤銷金鑰並改用 1Password。"))


def check_skills(ctx: ScanContext):
    for root, label in SKILL_ROOTS:
        base = os.path.expanduser(root)
        if not os.path.isdir(base):
            continue
        ctx.report("AI 與 Agent", label)
        for name in sorted(os.listdir(base)):
            ctx.inv(label, name, file_fingerprint(os.path.join(base, name, "SKILL.md"))
                    if os.path.isfile(os.path.join(base, name, "SKILL.md")) else "present")
        for dp, dns, fns in os.walk(base):
            dns[:] = [d for d in dns if d not in ("node_modules", ".git", "__pycache__", ".venv") and not d.startswith("temp_git_")]
            trusted = os.path.relpath(dp, base).split(os.sep)[0] in TRUSTED_MARKETPLACES
            if ctx.cancel.is_set():
                return
            for fn in fns:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in SCRIPT_EXTS:
                    continue
                p = os.path.join(dp, fn)
                text = read_text(p, ctx, limit=512 * 1024)
                if text:
                    is_code = ext not in (".md", ".json", ".yaml", ".yml")
                    scan_agent_text(ctx, p, text, "%s「%s」" % (label, os.path.relpath(p, base).split(os.sep)[0]),
                                    strict=is_code, trusted=trusted)


def check_ai_instruction_file(ctx: ScanContext, path: str):
    text = read_text(path, ctx)
    if text is None:
        return
    ctx.inv("AI 指令檔", home_rel(path), file_fingerprint(path))
    scan_agent_text(ctx, path, text, "AI 指令檔 %s" % os.path.basename(path), strict=False)


def check_global_instruction_files(ctx: ScanContext):
    for p in ("~/.claude/CLAUDE.md", "~/.codex/AGENTS.md", "~/.gemini/GEMINI.md", "~/AGENTS.md", "~/CLAUDE.md"):
        path = os.path.expanduser(p)
        if os.path.isfile(path):
            check_ai_instruction_file(ctx, path)


# ---------------------------------------------------------------- Telegram channel
def check_telegram(ctx: ScanContext):
    path = os.path.expanduser("~/.claude/channels/telegram/access.json")
    data = _load_json(path, ctx)
    if not isinstance(data, dict):
        return
    ctx.report("AI 與 Agent", "Telegram channel")
    policy = data.get("dmPolicy")
    allow = data.get("allowFrom") or []
    groups = data.get("groups") or {}
    pending = data.get("pending") or {}
    ctx.inv("Telegram channel", "dmPolicy", str(policy))
    ctx.inv("Telegram channel", "allowFrom", ",".join(sorted(str(a) for a in allow)))
    ctx.inv("Telegram channel", "groups", ",".join(sorted(groups)) if isinstance(groups, dict) else str(groups))
    src = "~/.claude/channels/telegram/access.json"
    if policy not in ("allowlist", "disabled"):
        ctx.add(Finding(
            rule="tg-policy", severity="high" if policy == "open" else "medium", category=CAT,
            title="Telegram 私訊政策為「%s」" % policy, path=src,
            why="Telegram 訊息會直接變成 Claude 的指令；陌生人能送訊息（或要求配對）就等於能對你的電腦下指令。",
            fix="配對完成後，用 /telegram:access 把 dmPolicy 改成 allowlist。"))
    if len(allow) > 1:
        ctx.add(Finding(rule="tg-allow", severity="low", category=CAT,
                        title="Telegram 有 %d 個帳號可以對 Claude 下指令" % len(allow), path=src,
                        why="每一個帳號都能操作你的電腦。", fix="只保留你自己的帳號。"))
    if isinstance(groups, dict) and groups:
        ctx.add(Finding(rule="tg-groups", severity="medium", category=CAT,
                        title="Telegram 允許 %d 個群組" % len(groups), path=src,
                        why="群組成員都可能對 Claude 下指令。", fix="除非必要，移除群組。"))
    if pending:
        ctx.add(Finding(rule="tg-pending", severity="medium", category=CAT,
                        title="Telegram 有 %d 個待核准的配對請求" % len(pending), path=src,
                        why="有人嘗試與你的 bot 配對；如果不是你，代表 bot 名稱已被他人知道。",
                        fix="不要核准不認得的請求。"))


# ---------------------------------------------------------------- 對話紀錄裡的機密
TRANSCRIPT_ROOTS = [("~/.claude/projects", "Claude Code"), ("~/.claude/history.jsonl", "Claude Code 輸入歷史"),
                    ("~/.claude/paste-cache", "Claude Code 貼上暫存"), ("~/.codex/sessions", "Codex")]
PREFILTER = ("sk-", "AIza", "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
             "xox", "_live_", ":AA", "hf_", "gsk_", "PRIVATE KEY")


def check_transcripts(ctx: ScanContext, cache: dict):
    """掃描 AI 對話紀錄有沒有貼過金鑰。用 (大小, 修改時間) 快取，只重掃有變動的檔案。"""
    ctx.report("AI 與 Agent", "AI 對話紀錄")
    for root, label in TRANSCRIPT_ROOTS:
        base = os.path.expanduser(root)
        files = []
        if os.path.isfile(base):
            files = [base]
        elif os.path.isdir(base):
            for dp, dns, fns in os.walk(base):
                files += [os.path.join(dp, f) for f in fns if f.endswith((".jsonl", ".json", ".txt", ".md")) or "paste" in root]
        for p in files:
            if ctx.cancel.is_set():
                return
            st = lstat_safe(p)
            if st is None or st.st_size > 200 * 1024 * 1024:
                continue
            key = "%s|%d|%d" % (p, st.st_size, int(st.st_mtime))
            if key in cache:
                result = cache[key]
            else:
                result = {}
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            if not any(t in line for t in PREFILTER):
                                continue
                            for rid, (name, sev, lns, ev) in find_secrets(line).items():
                                r = result.setdefault(rid, [name, 0, ev])
                                r[1] += len(lns)
                except OSError:
                    continue
                cache[key] = result
            for rid, (name, count, ev) in result.items():
                if rid == "private-key":
                    ev = "（私鑰內容不顯示）"
                ctx.add(Finding(
                    rule="transcript-" + rid, severity="high", category=CAT,
                    title="%s 對話紀錄中出現 %s" % (label, name), path=home_rel(p),
                    detail="共 %d 次" % count, evidence=ev,
                    why="AI 對話紀錄是明文檔案，會被備份、同步，也可能被其他 AI 工具讀取。貼過的金鑰應視為已外洩。",
                    fix="撤銷並更換此金鑰；之後改用 op:// 引用，不要把機密直接貼給 AI。"))
