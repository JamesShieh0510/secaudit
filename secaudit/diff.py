"""比對兩次掃描的差異，並依規則先標記「需要注意」的變動（不依賴 LLM 判斷）。"""
import os
import re
import subprocess
import time

# 這些區段的「新增或修改」一律標記為需要注意，即使 LLM 說是正常
WATCH_SECTIONS = {
    "MCP 伺服器", "Claude Code hooks", "Claude Code 允許清單", "使用者 LaunchAgent", "全域 LaunchAgent",
    "LaunchDaemon（root 權限）", "crontab", "shell 啟動檔", "Telegram channel", "plugin marketplaces",
    "AI 指令檔", "有漏洞的套件", "瀏覽器擴充功能", "~/.ssh 檔案", "authorized_keys 公鑰", "~/.ssh/config 指令", "遠端登入（SSH 伺服器）",
    "可疑位置的執行檔", "勒索軟體跡象", "secaudit 授權金鑰", "已確認無害項目", "secaudit 封存設定",
}


def _norm(v: str) -> str:
    # 比對時忽略修改時間，只看內容雜湊、大小、權限與指令，避免 App 單純重寫檔案就誤報
    return re.sub(r"mtime=\S+ \S+ ?", "", v or "")


def finding_key(f: dict) -> str:
    return "%s|%s|%s" % (f["rule"], f["path"], re.sub(r"\d+", "#", f["title"]))


def compare(prev_state: dict, result: dict):
    """回傳 (changes, new_state, baseline_scopes)。"""
    prev_inv = prev_state.get("inventory", {})
    prev_find = prev_state.get("findings", {})
    changes, baseline = [], []
    new_state = {"inventory": dict(prev_inv), "findings": dict(prev_find), "updated": result["started"]}
    for scope in result["scopes"]:
        cur_inv = result["inventory"].get(scope, {})
        cur_find = {finding_key(f): f for f in result["findings"]
                    if f.get("scope") == scope and f["severity"] != "info"}
        new_state["inventory"][scope] = cur_inv
        old_scope = prev_find.get(scope, {})
        new_state["findings"][scope] = {k: {"severity": f["severity"], "title": f["title"], "path": f["path"],
                                            "category": f["category"], "fix": (f.get("fix") or "")[:160],
                                            "first_seen": (old_scope.get(k) or {}).get("first_seen") or result["started"]}
                                        for k, f in cur_find.items()}
        if scope not in prev_inv:
            baseline.append(scope)
            continue
        old_inv = prev_inv[scope]
        # 這次才新增的檢查區段/分類（例如工具升級加了新檢查）：當成基準，不算變動
        new_sections = set(cur_inv) - set(old_inv)
        for sec in sorted((set(old_inv) | set(cur_inv)) - new_sections):
            a, b = old_inv.get(sec, {}), cur_inv.get(sec, {})
            for k in sorted(set(a) | set(b)):
                if k not in a:
                    changes.append({"type": "added", "section": sec, "key": k, "new": b[k], "scope": scope})
                elif k not in b:
                    changes.append({"type": "removed", "section": sec, "key": k, "old": a[k], "scope": scope})
                elif _norm(a[k]) != _norm(b[k]):
                    changes.append({"type": "changed", "section": sec, "key": k, "old": a[k], "new": b[k], "scope": scope})
        old_f = prev_find.get(scope, {})
        old_cats = {f.get("category") for f in old_f.values()} | {cur_find[k]["category"] for k in old_f if k in cur_find}
        for k, f in cur_find.items():
            # 資源監控事件（res-）一出現就要通知，不受「新分類當基準」影響
            if k not in old_f and (f["category"] in old_cats or f["rule"].startswith("res-")):
                changes.append({"type": "new_finding", "section": f["category"], "key": f["title"], "severity": f["severity"],
                                "new": "%s %s" % (f["path"], f.get("evidence", "")), "why": f.get("why", ""),
                                "detail": (f.get("detail") or "")[:1200], "scope": scope})
        for k, f in old_f.items():
            if k not in cur_find and not k.startswith("res-"):     # 資源事件 24 小時後自然過期，不算「已解決」
                changes.append({"type": "resolved", "section": "已解決", "key": f["title"], "severity": f["severity"],
                                "old": f["path"], "scope": scope})
    try:
        prev_ts = time.mktime(time.strptime(prev_state.get("updated", ""), "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        prev_ts = 0
    for c in changes:
        if c["type"] == "added" and prev_ts:
            mt = _item_mtime(c)
            if mt and mt < prev_ts - 300:
                # 檔案在上次掃描前就存在，只是這次才被掃到（掃描範圍或規則改了、上次掃描沒跑完）
                c["type"] = "first_seen"
                c["file_mtime"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(mt))
                c["new"] = ("檔案修改時間 %s（早於上次掃描），" % c["file_mtime"]) + (c.get("new") or "")
    for c in changes:
        c["attention"] = (c["type"] in ("added", "changed") and c["section"] in WATCH_SECTIONS) or \
                         (c["type"] == "new_finding" and c.get("severity") in ("high", "medium"))
    return changes, new_state, baseline


def _item_mtime(c):
    """變動項目對應檔案的修改時間：先看清單裡記錄的 mtime，沒有就用項目路徑（「路徑 ▸ 內容」的前半）去查。"""
    m = re.search(r"mtime=(\d{4}-\d\d-\d\d \d\d:\d\d)", c.get("new") or "")
    if m:
        try:
            return time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M"))
        except ValueError:
            pass
    p = (c.get("key") or "").split(" ▸ ")[0].strip()
    if p.startswith("~/"):
        p = os.path.expanduser(p)
    if p.startswith("/"):
        try:
            return os.stat(p).st_mtime
        except OSError:
            return None
    return None


def machine_context() -> dict:
    """偵測當下的環境，幫助判斷「是不是我本人在操作」。"""
    ctx = {"detected_at": time.strftime("%Y-%m-%d %H:%M:%S %A")}
    try:
        from .core import safe_env
        out = subprocess.run(["ioreg", "-c", "IOHIDSystem"], capture_output=True, text=True, timeout=10, env=safe_env()).stdout
        m = re.search(r'"HIDIdleTime" = (\d+)', out)
        if m:
            ctx["user_idle_minutes"] = int(int(m.group(1)) / 1e9 / 60)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ctx


TYPE_LABEL = {"first_seen": "首次掃到", "added": "新增", "removed": "移除", "changed": "修改", "new_finding": "新問題", "resolved": "已解決"}


def changes_to_text(changes, limit=80) -> str:
    lines = []
    for c in changes[:limit]:
        s = "[%s]%s %s ▸ %s" % (TYPE_LABEL[c["type"]], "⚠️" if c["attention"] else "", c["section"], c["key"])
        if c.get("old"):
            s += "\n    舊：" + c["old"][:220]
        if c.get("new"):
            s += "\n    新：" + c["new"][:220]
        if c.get("detail"):
            s += "\n    細節：" + c["detail"][:900].replace("\n", "\n          ")
        lines.append(s)
    if len(changes) > limit:
        lines.append("…另有 %d 項變動" % (len(changes) - limit))
    return "\n".join(lines)
