"""未處理問題的定期提醒。

- 每個問題第一次出現的時間記在 state.json（diff.compare 負責）。
- 每週固定時間送一份「還沒處理」的清單；有高風險超過 escalate_days 天沒處理時，改成每天提醒。
- 漏洞快訊中「影響你專案」的套件也會留在清單裡，直到套件索引顯示已升級（或被掃描結果涵蓋）。
"""
import html
import time

SEV_W = {"high": 3, "medium": 1}
SEV_ICON = {"high": "🟥", "medium": "🟧"}
WEEKDAYS = ["一", "二", "三", "四", "五", "六", "日"]


def _ts(s):
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        try:
            return time.mktime(time.strptime(s[:16], "%Y-%m-%d %H:%M"))
        except (ValueError, TypeError):
            return time.time()


def age_days(first_seen, now=None):
    return int(((now or time.time()) - _ts(first_seen)) // 86400)


def open_items(state, feed_open, pkgindex, now=None):
    """回傳 (清單, 已不適用而應從 feed_open 移除的 key)。"""
    now = now or time.time()
    items = []
    titles = []
    for scope, fs in (state.get("findings") or {}).items():
        for k, f in fs.items():
            if f.get("severity") not in SEV_W:
                continue
            a = age_days(f.get("first_seen") or state.get("updated", ""), now)
            items.append({"kind": "finding", "severity": f["severity"], "title": f["title"], "path": f.get("path", ""),
                          "fix": f.get("fix", ""), "age": a, "since": (f.get("first_seen") or "")[:10]})
            titles.append(f["title"])
    stale = []
    for k, v in (feed_open or {}).items():
        eco, name, ver = k.split("|", 2)
        if ver not in (pkgindex.get("%s|%s" % (eco, name)) or {}):
            stale.append(k)          # 套件已升級或專案已移除
            continue
        if any("%s@%s" % (name, ver) in t for t in titles):
            continue                 # 已經出現在掃描結果裡，不重複列
        sev = "high" if v.get("severity") in ("critical", "high") else "medium"
        items.append({"kind": "feed", "severity": sev, "title": "%s %s@%s：%s" % (eco, name, ver, "、".join(v.get("cves", [])[:3])),
                      "path": "、".join(v.get("projects", [])[:3]), "fix": "升級到 %s" % (v.get("fixed") or "修正版本"),
                      "age": age_days(v.get("first_seen", ""), now), "since": v.get("first_seen", "")[:10]})
    items.sort(key=lambda x: -(SEV_W[x["severity"]] * (x["age"] + 1)))
    return items, stale


def is_escalated(items, cfg):
    return any(x["severity"] == "high" and x["age"] >= int(cfg.get("escalate_days", 7)) for x in items)


def next_time(cfg, escalated, now=None):
    """下一次提醒時間：升級中 → 明天（或今天稍後）的提醒時間；否則 → 下一個指定星期幾。"""
    now = now or time.time()
    hour = int(cfg.get("reminder_hour", 9))
    t = time.localtime(now)
    today = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, hour, 0, 0, 0, 0, -1))
    if escalated:
        return today if today > now else today + 86400
    wd = int(cfg.get("reminder_weekday", 0))
    delta = (wd - t.tm_wday) % 7
    cand = today + delta * 86400
    return cand if cand > now else cand + 7 * 86400


def build_message(items, cfg, web_url="", host=""):
    e = html.escape
    hi = sum(1 for x in items if x["severity"] == "high")
    md = len(items) - hi
    esc_days = int(cfg.get("escalate_days", 7))
    overdue = [x for x in items if x["severity"] == "high" and x["age"] >= esc_days]
    lines = ["📋 <b>%s未處理的安全問題</b>：高 %d、中 %d" % (e(host + " ") if host else "", hi, md)]
    if overdue:
        lines.append("⏰ 有 <b>%d</b> 個高風險超過 %d 天沒處理，處理完之前會<b>每天</b>提醒" % (len(overdue), esc_days))
    else:
        lines.append("（每週%s %02d:00 提醒；高風險超過 %d 天未處理會改成每天提醒）" % (
            WEEKDAYS[int(cfg.get("reminder_weekday", 0))], int(cfg.get("reminder_hour", 9)), esc_days))
    lines.append("")
    for x in items[:15]:
        lines.append("%s <b>[%d 天]</b> %s%s" % (SEV_ICON[x["severity"]], x["age"], "🧯 " if x["kind"] == "feed" else "", e(x["title"][:110])))
        if x.get("fix"):
            lines.append("   → %s" % e(x["fix"][:120]))
    if len(items) > 15:
        lines.append("…另有 %d 項" % (len(items) - 15))
    if web_url:
        lines.append("\n完整清單：%s" % e(web_url))
    return "\n".join(lines)
