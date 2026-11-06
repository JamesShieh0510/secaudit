"""重新檢查舊報告：只針對舊報告提過的問題重新判定，並套用目前的規則。

結果分成：
- 已改善：檔案 / 專案在舊報告之後有變動（修改、刪除、升級），問題不見了
- 規則更新後排除：檔案沒有變動，但目前的規則不再把它算成問題（誤報被修正）
- 風險等級改變：問題還在，但目前的規則給了不同的等級
- 仍存在：問題還在
- 新出現：舊報告沒有、這次重新檢查才看到（通常是固定位置的新變動，或新規則抓到的）
"""
import os
import time

from .diff import finding_key
from .supply_chain import LOCKFILES

MAX_LIST = 3000


def _key2(f):
    """標題可能因為規則更新而改字（例如加上「測試目錄」），所以再用 規則 + 路徑 比對一次。"""
    return "%s|%s" % (f.get("rule", ""), f.get("path", ""))


def _mini(f, **extra):
    d = {k: f.get(k, "") for k in ("rule", "severity", "category", "title", "path")}
    d.update(extra)
    return d


def _paths(f):
    from .scanner import _old_paths
    return _old_paths(f)


def _changed_since(f, ts):
    """舊報告之後，問題指到的檔案 / 專案 lockfile 有沒有被改過或刪掉。沒有路徑的回傳 None（無法判斷）。"""
    ps = _paths(f)
    if not ps:
        return None
    for p in ps:
        try:
            if os.path.isdir(p):
                for fn in os.listdir(p):
                    if fn in LOCKFILES and os.stat(os.path.join(p, fn)).st_mtime > ts:
                        return True
            elif os.stat(p).st_mtime > ts:
                return True
        except OSError:
            return True       # 檔案 / 資料夾不見了也算有變動
    return False


def compare(old, new, excluded_carry=()):
    from .scanner import pruned_by_rules
    try:
        ts = time.mktime(time.strptime(old.get("started", ""), "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        ts = 0
    cur = [f for f in new.get("findings", []) + new.get("acknowledged", []) if f.get("severity") != "info"]
    by_k = {finding_key(f): f for f in cur}
    by_k2 = {}
    for f in cur:
        by_k2.setdefault(_key2(f), f)
    carry_keys = {finding_key(f) for f in excluded_carry}
    out = {"resolved": [], "excluded": [], "reclassified": [], "still": 0, "new": []}
    matched = set()
    for f in old.get("findings", []) + old.get("acknowledged", []):
        if f.get("severity") == "info":
            continue
        k = finding_key(f)
        g = by_k.get(k) or by_k2.get(_key2(f))
        if g is not None:
            matched.add(id(g))
            if g.get("severity") != f.get("severity"):
                out["reclassified"].append(_mini(g, old_severity=f.get("severity", "")))
            else:
                out["still"] += 1
            continue
        if k in carry_keys or (f.get("scope") == "walk" and _paths(f) and all(pruned_by_rules(p) for p in _paths(f))):
            out["excluded"].append(_mini(f, why="位在目前規則不再掃描的資料夾，或屬於已知的誤報"))
            continue
        ch = _changed_since(f, ts)
        if ch is False:
            out["excluded"].append(_mini(f, why="檔案沒有變動，目前的規則不再把它算成問題"))
        else:
            out["resolved"].append(_mini(f, why="舊報告之後檔案有變動或已刪除" if ch else "重新檢查時已不存在"))
    out["new"] = [_mini(f) for f in cur if id(f) not in matched]
    counts = {k: (v if isinstance(v, int) else len(v)) for k, v in out.items()}
    for k in ("resolved", "excluded", "reclassified", "new"):
        out[k] = out[k][:MAX_LIST]
    out["counts"] = counts
    return out
