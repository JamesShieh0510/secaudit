"""重新檢查時，清掉已經不存在的專案 / 檔案留下的資料。

只看「檔案系統上真的不見了」，不看「這次沒掃到」，所以不會因為重新檢查範圍比較小就誤刪：
- 路徑必須是家目錄或 /Volumes 底下的絕對路徑；有萬用字元（*）的去識別化路徑、系統位置都不動
- 外接 / 網路磁碟沒掛載時不算不見（/Volumes/<名稱> 本身要存在）
- 一個問題指到多個專案時，全部都不見了才清掉

清掉的地方：
- state.json 的資料夾掃描問題（比對基準與「第一次出現」時間；不清掉的話提醒和天數會一直算下去）
- acks.json 已確認無害的標記
- touched.json 修復動作改過的檔案紀錄
"""
import os

from .core import HOME


def _gone(p):
    if not p or "*" in p or not os.path.isabs(p):
        return False
    if p.startswith("/Volumes/"):
        parts = p.split(os.sep)
        if len(parts) < 3 or not os.path.ismount(os.sep.join(parts[:3])):
            return False
    elif not (p == HOME or p.startswith(HOME + os.sep)):
        return False
    return not os.path.lexists(p)


def all_gone(paths):
    paths = [os.path.expanduser(p) for p in paths if p]
    return bool(paths) and all(_gone(p) for p in paths)


def finding_gone(f):
    from .scanner import _old_paths
    return all_gone(_old_paths(f))


def prune(data_dir):
    """回傳 {"state": n, "acks": n, "touched": n, "projects": [清掉的專案根目錄（家目錄相對）]}。"""
    from .app import _read, _write_private
    from .core import home_rel
    out = {"state": 0, "acks": 0, "touched": 0, "projects": []}
    roots = set()

    sp = os.path.join(data_dir, "state.json")
    state = _read(sp, {})
    walk = (state.get("findings") or {}).get("walk") or {}
    drop = [k for k, f in walk.items() if isinstance(f, dict) and finding_gone(f)]
    for k in drop:
        roots.add(_root_of(walk.pop(k)))
    if drop:
        _write_private(sp, state)
        out["state"] = len(drop)

    from . import acks
    xs = acks.items()
    keep = [x for x in xs if not (x.get("path", "").startswith("~/") and all_gone([x["path"]]))]
    if len(keep) != len(xs):
        roots.update(_root_of(x) for x in xs if x not in keep)
        acks._save(keep)
        out["acks"] = len(xs) - len(keep)

    tp = os.path.join(data_dir, "touched.json")
    t = _read(tp, {})
    if isinstance(t, dict):
        left = {p: h for p, h in t.items() if not _gone(p)}
        if len(left) != len(t):
            roots.update(_root_of({"path": p}) for p in t if p not in left)
            _write_private(tp, left)
            out["touched"] = len(t) - len(left)

    out["projects"] = sorted(home_rel(r) for r in roots if r)
    return out


def _root_of(f):
    """給人看的「哪個專案」：最上層不存在的那一層資料夾。"""
    from .scanner import _old_paths
    ps = _old_paths(f) if f.get("projects") or "；" in (f.get("path") or "") else [os.path.expanduser(f.get("path", ""))]
    p = ps[0] if ps else ""
    while p and os.path.dirname(p) != p and not os.path.lexists(os.path.dirname(p)):
        p = os.path.dirname(p)
    return p
