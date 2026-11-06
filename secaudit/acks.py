"""「已確認無害」標記。

- 標記會綁定問題的識別鍵（規則 + 路徑 + 標題），指向檔案的問題另外綁定檔案內容的 sha256：
  檔案一被修改，標記自動失效，問題重新出現並發出警示。
- 被標記的問題移到報告的「已確認無害」區塊，不計入風險數量、不進未處理提醒。
- 標記本身也是一種「降低警示」的操作：清單會寫進清單快照（新增 / 移除都是 ⚠️ 變動），
  data/acks.json 有即時監看，Web UI 新增標記時也會發 Telegram。避免惡意程式把自己的警示偷偷標成無害。
"""
import hashlib
import os
import stat
import time

from .app import DATA, REPORTS, _read, _write_private
from .diff import finding_key

STORE = os.path.join(DATA, "acks.json")
MAX_HASH_BYTES = 50 * 1024 * 1024


def file_sha(display_path):
    """問題路徑若是一般檔案（不是 symlink），回傳內容的 sha256；否則回傳空字串（只用識別鍵比對）。"""
    p = os.path.expanduser((display_path or "").split("（")[0].strip())
    try:
        st = os.lstat(p)
    except (OSError, ValueError):
        return ""
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_HASH_BYTES:
        return ""
    h = hashlib.sha256()
    try:
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def items():
    return _read(STORE, {}).get("items", [])


def _save(xs):
    _write_private(STORE, {"items": xs})


def add_from_report(report_name, key, note=""):
    """從某份報告中找到這個問題並標記。只接受報告裡真的存在的問題，不能預先標記不存在的東西。
    回傳 (成功, 訊息, 標記內容)。"""
    if not report_name.replace("-", "").isdigit():
        return False, "報告名稱不正確", None
    d = _read(os.path.join(REPORTS, report_name + ".json"), {})
    f = next((x for x in d.get("findings", []) if finding_key(x) == key and x.get("severity") != "info"), None)
    if not f:
        return False, "在這份報告裡找不到這個問題（可能已經解決或報告已過期）", None
    entry = {"key": key, "rule": f.get("rule", ""), "title": f.get("title", ""), "path": f.get("path", ""),
             "severity": f.get("severity", ""), "category": f.get("category", ""), "sha": file_sha(f.get("path", "")),
             "note": str(note or "")[:200], "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    xs = [x for x in items() if x["key"] != key] + [entry]
    _save(xs)
    return True, "", entry


def remove(key):
    xs = items()
    left = [x for x in xs if x["key"] != key]
    _save(left)
    return len(left) != len(xs)


def apply(result):
    """掃描結束、比對之前呼叫：把已確認無害（而且檔案內容沒變）的問題移出 findings。"""
    acks = {x["key"]: x for x in items()}
    inv = result.setdefault("inventory", {}).setdefault("system", {})
    inv["已確認無害項目"] = {"%s ▸ %s" % (x.get("title", "")[:80], x.get("path", "")[:80]):
                         "sha=%s | %s" % ((x.get("sha") or "-")[:16], x.get("time", "")) for x in acks.values()}
    if not acks:
        result.setdefault("acknowledged", [])
        return
    keep, moved = [], []
    for f in result.get("findings", []):
        a = acks.get(finding_key(f)) if f.get("severity") != "info" else None
        if not a:
            keep.append(f)
            continue
        if a.get("sha") and file_sha(f.get("path", "")) != a["sha"]:
            # 標記後檔案被改過：標記失效，問題照常列出並加註
            f["detail"] = ("⚠️ 這個問題在 %s 被標記為無害，但檔案內容之後被修改，標記已失效，請重新確認。" % a.get("time", "")) + \
                          ((" ／ " + f["detail"]) if f.get("detail") else "")
            keep.append(f)
            continue
        f = dict(f, ack={"time": a.get("time", ""), "note": a.get("note", "")})
        moved.append(f)
    result["findings"] = keep
    result["acknowledged"] = moved


def live_view(payload):
    """看報告時套用「現在」的標記：報告存檔後才標記的問題移到已確認無害，取消標記的移回來。
    不改報告檔本身，只回傳新的一份（給 Web UI 顯示用）。"""
    import copy
    d = copy.deepcopy(payload)
    pool = list(d.get("findings") or [])
    for f in d.get("acknowledged") or []:
        f = dict(f)
        f.pop("ack", None)
        pool.append(f)
    d["findings"] = pool
    d["acknowledged"] = []
    apply(d)
    return d
