"""統計分析：每天的計數（掃描、即時監看、資源事件）與每小時的資源取樣，以及「📈 統計」頁籤用的彙整資料。

資料都在 data/（不進 git）：
  stats_daily.json      {"YYYY-MM-DD": {"計數名稱": 數字}}，保留 400 天
  resource_series.json  [{"t": 整點時間, "cpu": 平均 %, "cpu_max": %, "swap": GB, "pressure": 最高等級}]，保留 14 天
沒有變動的快速掃描、即時監看觸發不會存成報告，所以要另外計數；風險趨勢則直接用報告。
"""
import json
import os
import threading
import time

from .core import home_rel

_lock = threading.Lock()
DAILY_KEEP = 400
SERIES_KEEP = 14 * 24


def _data():
    from .app import DATA
    return DATA


def _load(name, default):
    try:
        with open(os.path.join(_data(), name), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, type(default)) else default
    except (OSError, ValueError):
        return default


def _save(name, obj):
    from .app import _write_private
    _write_private(os.path.join(_data(), name), obj)


def bump(key, n=1, day=None, setval=None):
    """每日計數 +n（或 setval：直接設定成某個值，例如當天最後一次的風險數量）。失敗不影響主流程。"""
    try:
        day = day or time.strftime("%Y-%m-%d")
        with _lock:
            d = _load("stats_daily.json", {})
            ent = d.setdefault(day, {})
            if setval is not None:
                ent[key] = setval
            else:
                ent[key] = ent.get(key, 0) + n
            for k in sorted(d)[:-DAILY_KEEP]:
                del d[k]
            _save("stats_daily.json", d)
    except Exception:
        pass


def scan_group(mode, source):
    if mode in ("full", "recheck"):
        return "full"
    return "watch" if source == "watch" else "quick"


def record_scan(mode, source, counts, changes, attention, duration):
    g = scan_group(mode, source)
    day = time.strftime("%Y-%m-%d")
    bump("scan:%s" % g, day=day)
    bump("scan:%s:changed" % g, 1 if changes else 0, day=day)
    bump("changes:%s" % g, changes, day=day)
    bump("attention:%s" % g, attention, day=day)
    bump("duration:%s" % g, round(duration or 0, 1), day=day)
    bump("risk:%s" % g, day=day, setval={s: counts.get(s, 0) for s in ("high", "medium", "low", "info")})


def record_watch(n_paths, changed):
    bump("watch:trigger")
    bump("watch:paths", n_paths)
    if changed:
        bump("watch:changed")


def record_resource_event(severity):
    bump("res:%s" % severity)


_acc = {"hour": None, "cpu": [], "swap": 0.0, "pressure": 0}


def record_resource_sample(cpu, swap_gb, pressure):
    """每分鐘呼叫；累積到整點才寫一筆（平均 CPU、最高 CPU、最後的 swap、最高記憶體壓力）。"""
    try:
        hour = int(time.time() // 3600 * 3600)
        if _acc["hour"] is not None and hour != _acc["hour"] and _acc["cpu"]:
            with _lock:
                s = _load("resource_series.json", [])
                s.append({"t": _acc["hour"], "cpu": round(sum(_acc["cpu"]) / len(_acc["cpu"]), 1),
                          "cpu_max": round(max(_acc["cpu"]), 1), "swap": round(_acc["swap"], 2), "pressure": _acc["pressure"]})
                _save("resource_series.json", s[-SERIES_KEEP:])
            _acc.update(cpu=[], pressure=0)
        _acc["hour"] = hour
        _acc["cpu"].append(float(cpu or 0))
        _acc["swap"] = float(swap_gb or 0)
        _acc["pressure"] = max(_acc["pressure"], int(pressure or 0))
    except Exception:
        pass


# ---------------------------------------------------------------- 「📈 統計」頁籤的資料
_detail_cache = {}


def _report_detail(name):
    """一份報告的分類統計、供應鏈依專案、未處理天數分布（依檔案修改時間快取）。"""
    from .app import REPORTS, _read
    p = os.path.join(REPORTS, name + ".json")
    try:
        mt = os.path.getmtime(p)
    except OSError:
        return {}
    ent = _detail_cache.get(name)
    if ent and ent[0] == mt:
        return ent[1]
    d = _read(p, {})
    try:
        from . import acks
        d = acks.live_view(d)
    except Exception:
        pass
    fs = d.get("findings", [])
    sev3 = ("high", "medium", "low")
    cats = {}
    for f in fs:
        if f["severity"] in sev3:
            cats.setdefault(f.get("category", "其他"), {s: 0 for s in sev3})[f["severity"]] += 1
    ages = {"0–1 天": {s: 0 for s in sev3}, "2–7 天": {s: 0 for s in sev3}, "8–30 天": {s: 0 for s in sev3},
            "30 天以上": {s: 0 for s in sev3}}
    for f in fs:
        if f["severity"] not in sev3 or f.get("age_days") is None:
            continue
        a = f["age_days"]
        b = "0–1 天" if a <= 1 else "2–7 天" if a <= 7 else "8–30 天" if a <= 30 else "30 天以上"
        ages[b][f["severity"]] += 1
    projects = []
    try:
        from .report import _supply_projects, _sev_rank
        for root, items in sorted(_supply_projects(d).items(), key=lambda kv: _sev_rank(kv[1])[1])[:12]:
            c, _ = _sev_rank(items)
            projects.append({"project": home_rel(root), **c})
    except Exception:
        pass
    out = {"name": name, "started": d.get("started"), "mode": d.get("mode"), "cats": cats, "ages": ages, "projects": projects}
    _detail_cache[name] = (mt, out)
    for k in list(_detail_cache)[:-40]:
        del _detail_cache[k]
    return out


def build(engine, days=30, group="full"):
    from .app import DATA
    since = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400)) if days else "0000"
    reps = [r for r in engine.reports() if (r.get("started") or "")[:10] >= since]
    mine = [r for r in reps if scan_group(r.get("mode"), r.get("source")) == group]
    mine.sort(key=lambda r: r.get("started") or "")
    trend = [{"t": r["started"], "name": r["name"], **{s: (r.get("counts") or {}).get(s, 0) for s in ("high", "medium", "low")}}
             for r in mine]
    daily = _load("stats_daily.json", {})
    # 沒有另存報告的日子（沒有變動的快速掃描）：用當天最後一次掃描的風險數量補點
    have = {t["t"][:10] for t in trend}
    for day in sorted(daily):
        if day < since or day in have:
            continue
        rk = daily[day].get("risk:%s" % group)
        if isinstance(rk, dict):
            trend.append({"t": day + " 23:59:00", "name": "", **{s: rk.get(s, 0) for s in ("high", "medium", "low")}})
    trend.sort(key=lambda x: x["t"])
    latest = mine[-1]["name"] if mine else ""
    det = _report_detail(latest) if latest else {}
    prev = next((t for t in reversed(trend[:-1])), None) if trend else None
    # 依類別的趨勢：最近 16 份這種掃描的報告
    cat_cols = []
    for r in mine[-16:]:
        dd = _report_detail(r["name"])
        cat_cols.append({"t": r["started"], "name": r["name"], "cats": {k: sum(v.values()) for k, v in (dd.get("cats") or {}).items()}})
    days_list = sorted(k for k in daily if k >= since)
    mon = [{"day": k, **{kk: vv for kk, vv in daily[k].items() if not isinstance(vv, dict)}} for k in days_list]
    # 修復動作：每天處理成功的項目數
    fixes = {}
    try:
        with open(os.path.join(DATA, "actions.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    h = json.loads(line)
                except ValueError:
                    continue
                day = (h.get("time") or "")[:10]
                if day < since or not h.get("steps"):
                    continue
                ok = sum(1 for s in h["steps"] if s.get("ok") is True)
                fixes.setdefault(day, {}).setdefault(h.get("action", ""), 0)
                fixes[day][h.get("action", "")] += ok
    except OSError:
        pass
    series = [x for x in _load("resource_series.json", []) if not days or x["t"] >= time.time() - min(days, 14) * 86400]
    return {"group": group, "days": days, "trend": trend, "latest": det, "prev": prev, "cat_cols": cat_cols,
            "monitor": mon, "fixes": [{"day": k, **v} for k, v in sorted(fixes.items())], "resource": series,
            "counts": {"reports": len(mine), "scans_counted": sum(daily.get(k, {}).get("scan:%s" % group, 0) for k in days_list)}}
