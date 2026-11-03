"""設定、狀態保存、掃描排程與警示。Web UI 與常駐排程在同一個程序裡，共用一把鎖。"""
import json
import os
import threading
import time
import traceback

from . import notify, report
from .core import Target
from .diff import compare, machine_context
from .scanner import default_targets, run_scan
from .sop import build_sop

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SECAUDIT_DATA", os.path.join(ROOT, "data"))
REPORTS = os.path.join(DATA, "reports")

DEFAULT_CONFIG = {
    "quick_interval_min": 15,       # 快速掃描（固定位置 + 對話紀錄）頻率
    "full_scan_hour": 3,            # 每天幾點做完整掃描（遍歷資料夾 + 套件漏洞）
    "online": True,                 # 查 OSV.dev / endoflife.date
    "llm_enabled": True,
    "ollama_host": "https://ollama.com",
    "ollama_model": "gpt-oss:120b",
    "web_port": 8765,
    "notify_baseline": True,
    "vulnfeed_hours": 6,            # 漏洞快訊頻率（小時），0 = 關閉
    "watch_enabled": True,          # 關鍵位置即時監看
    "watch_interval_sec": 10,        # 第一次建立基準時也通知一次
    "max_reports": 60,
    "targets": [],                  # [{path,label,kind,enabled}]，空的時候用預設
}


def _write_private(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def load_config():
    """優先順序：Web UI 存過的設定（data/config.json）> 環境變數 OLLAMA_HOST / OLLAMA_MODEL > 預設值。"""
    cfg = dict(DEFAULT_CONFIG)
    for k, env in (("ollama_host", "OLLAMA_HOST"), ("ollama_model", "OLLAMA_MODEL")):
        if os.environ.get(env):
            v = os.environ[env].strip()
            if k == "ollama_host" and not v.startswith(("http://", "https://")):
                v = "http://" + v          # Ollama 慣例允許只寫 127.0.0.1:11434
            cfg[k] = v
    cfg.update(_read(os.path.join(DATA, "config.json"), {}))
    return cfg


def normalize_host(v: str) -> str:
    """接受 http(s)://主機[:port]，或簡寫的 主機:port。不合法時丟出 ValueError。"""
    import re
    v = (v or "").strip().rstrip("/")
    if v and not v.startswith(("http://", "https://")):
        v = "http://" + v
    if not re.match(r"^https?://(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?$", v):
        raise ValueError("格式應為 http://主機:port，例如 http://127.0.0.1:11434 或 https://ollama.com")
    return v


def save_config(cfg):
    _write_private(os.path.join(DATA, "config.json"), cfg)


def load_targets(cfg=None):
    """預設目標（家目錄、偵測到的雲端硬碟、/Volumes）與使用者設定合併。"""
    cfg = cfg or load_config()
    saved = {t["path"]: t for t in cfg.get("targets", [])}
    out = []
    for t in default_targets():
        if t.path in saved:
            t.enabled = bool(saved[t.path].get("enabled", t.enabled))
        out.append(t)
    known = {t.path for t in out}
    for p, t in saved.items():
        if p not in known:
            out.append(Target(p, t.get("label") or os.path.basename(p) or p, t.get("kind", "custom"), bool(t.get("enabled", True))))
    return out


class Engine:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.status = {"running": False, "mode": "", "phase": "", "current": "", "started": "", "last_report": "",
                       "last_error": "", "last_changes": 0, "next_quick": "", "next_full": ""}
        os.makedirs(REPORTS, mode=0o700, exist_ok=True)

    def _progress(self, phase, current):
        self.status["phase"], self.status["current"] = phase, current[-160:]

    def scan(self, mode="full", notify_user=True, source="manual", online=None, trigger=None):
        if not self.lock.acquire(blocking=False):
            return None
        try:
            self.cancel.clear()
            cfg = load_config()
            self.status.update(running=True, mode=mode, phase="準備中", current="", started=time.strftime("%H:%M:%S"), last_error="")
            cache = _read(os.path.join(DATA, "cache.json"), {})
            result = run_scan(load_targets(cfg), mode=mode, cache=cache, progress=self._progress,
                              cancel=self.cancel, online=cfg.get("online", True) if online is None else online)
            _write_private(os.path.join(DATA, "cache.json"), cache)
            result["settings"] = self.settings_snapshot(cfg, mode, source, notify_user,
                                                        cfg.get("online", True) if online is None else online, trigger)
            if result["cancelled"]:
                self.status["phase"] = "已取消"
                return None
            state = _read(os.path.join(DATA, "state.json"), {})
            changes, new_state, baseline = compare(state, result)
            summary = ""
            if changes and notify_user:
                self._progress("AI 分析變動", "")
                mctx = machine_context()
                if trigger:
                    mctx["triggered_by_realtime_watch"] = trigger
                summary = notify.llm_summary(changes, mctx, cfg)
            from .core import home_rel
            sop = build_sop(cfg, [{"path": t.path, "display": home_rel(t.path), "label": t.label, "enabled": t.enabled}
                                  for t in load_targets(cfg)])
            name = report.save_reports(result, REPORTS, changes if state else None, summary, sop)
            # 不發通知的手動掃描不更新比對基準，否則變動會被「吃掉」，排程掃描就永遠不會通知
            if notify_user or not state:
                _write_private(os.path.join(DATA, "state.json"), new_state)
            self._prune_reports(cfg.get("max_reports", 60))
            self.status.update(last_report=name, last_changes=len(changes))
            url = "http://127.0.0.1:%d/reports/%s.html" % (cfg["web_port"], name)
            if notify_user and changes:
                msg = notify.build_alert(result["host"], changes, summary, name, url, trigger=trigger)
                if not notify.telegram_send(msg):
                    self._outbox_add(msg)
            elif notify_user and baseline and cfg.get("notify_baseline") and source != "manual":
                hi = sum(1 for f in result["findings"] if f["severity"] == "high")
                notify.telegram_send("🛡 <b>%s</b> 已建立安全基準（%s）\n目前高風險 %d 項，之後只會通知變動。\n%s" % (
                    result["host"], "、".join(baseline), hi, url))
            self.status["phase"] = "完成"
            return name
        except Exception as e:
            self.status["last_error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
            traceback.print_exc()
            return None
        finally:
            self.status["running"] = False
            self.lock.release()

    def run_vulnfeed(self, force=False, lookback_hours=None):
        from .vulnfeed import run_feed
        try:
            self.status["feed_running"] = True
            self.status["feed_msg"] = ""
            r = run_feed(self, load_config(), _read(os.path.join(DATA, "cache.json"), {}), force=force,
                         lookback_hours=lookback_hours)
            self.status["feed_msg"] = "%s 已%s：檢查 %d 筆新公告，影響你 %d 筆、已被利用 %d 筆" % (
                r["time"][11:], "推送到 Telegram" if r.get("sent") else "完成（Telegram 未送出，已放入待送清單）",
                r["fetched"], len(r["affected"]), len(r["kev"]))
            return r
        except Exception as e:
            self.status["last_error"] = "漏洞快訊：%s: %s" % (type(e).__name__, str(e)[:150])
            traceback.print_exc()
        finally:
            self.status["feed_running"] = False

    @staticmethod
    def settings_snapshot(cfg, mode, source, notify_user, online, trigger=None):
        from .core import home_rel
        ts = [t for t in load_targets(cfg) if t.enabled]
        return {
            "mode": mode, "source": source, "notify": bool(notify_user), "online": bool(online),
            "llm": bool(cfg.get("llm_enabled")) and bool(notify_user), "model": cfg.get("ollama_model"),
            "targets": [{"label": t.label, "path": home_rel(t.path), "exists": os.path.isdir(t.path)} for t in ts] if mode == "full" else [],
            "targets_note": "" if mode == "full" else "快速掃描不遍歷資料夾，掃描範圍只套用在完整掃描",
            "trigger": trigger or [],
            "quick_interval_min": cfg.get("quick_interval_min"), "full_scan_hour": cfg.get("full_scan_hour"),
        }

    # ---------------------------------------------------------------- 待送清單：Telegram 送不出去時暫存，之後補送
    def _outbox_add(self, msg):
        box = _read(os.path.join(DATA, "outbox.json"), [])
        box.append({"t": time.strftime("%Y-%m-%d %H:%M:%S"), "msg": msg})
        _write_private(os.path.join(DATA, "outbox.json"), box[-20:])
        self.status["outbox"] = len(box[-20:])
        print("[notify] 已放入待送清單（%d 則），稍後補送" % len(box[-20:]), flush=True)

    def flush_outbox(self):
        path = os.path.join(DATA, "outbox.json")
        box = _read(path, [])
        if not box:
            self.status["outbox"] = 0
            return
        left = []
        for item in box:
            if left or not notify.telegram_send("⏰ 補送（原訊息時間 %s）\n%s" % (item["t"], item["msg"]), retries=1):
                left.append(item)
        _write_private(path, left)
        self.status["outbox"] = len(left)

    def scan_async(self, mode, notify_user=True):
        if self.status["running"]:
            return False
        threading.Thread(target=self.scan, args=(mode, notify_user), daemon=True).start()
        return True

    def _prune_reports(self, keep):
        names = sorted({f.rsplit(".", 1)[0] for f in os.listdir(REPORTS) if f.endswith(".json")})
        for n in names[:-keep] if keep > 0 else []:
            for ext in (".json", ".md", ".html"):
                try:
                    os.remove(os.path.join(REPORTS, n + ext))
                except OSError:
                    pass

    def reports(self):
        out = []
        for f in sorted(os.listdir(REPORTS), reverse=True):
            if not f.endswith(".json"):
                continue
            d = _read(os.path.join(REPORTS, f), {})
            cnt = {}
            for x in d.get("findings", []):
                cnt[x["severity"]] = cnt.get(x["severity"], 0) + 1
            st = d.get("settings") or {}
            out.append({"name": f[:-5], "started": d.get("started"), "mode": d.get("mode"), "counts": cnt,
                        "source": st.get("source", ""), "targets": [t["path"] for t in st.get("targets", [])] or
                        [t["path"] for t in d.get("targets", [])], "notify": st.get("notify"),
                        "changes": len(d.get("changes") or []), "attention": sum(1 for c in (d.get("changes") or []) if c.get("attention"))})
        return out

    def scheduler(self):
        """常駐排程：每 N 分鐘快速掃描，每天固定時間完整掃描。"""
        cfg = load_config()
        state = _read(os.path.join(DATA, "state.json"), {})
        if os.environ.get("SECAUDIT_UNLOCK_DELAY"):
            notify.telegram_send("🔓 secaudit 已取得 1Password 授權並開始監控（等待授權期間提醒了 %s 次，這段時間沒有在監控）。"
                                 "接下來的快速掃描會比對這段期間的所有變動。" % os.environ.pop("SECAUDIT_UNLOCK_DELAY"))
        # 第一次執行或從沒做過完整掃描：先做一次完整掃描建立基準
        next_full = time.time() + 5 if "walk" not in state.get("inventory", {}) else self._next_full(cfg)
        next_quick = time.time() + 60
        next_feed = time.time() + 300      # 啟動 5 分鐘後抓第一次漏洞快訊
        while True:
            cfg = load_config()
            now = time.time()
            self.status["next_quick"] = time.strftime("%H:%M", time.localtime(next_quick))
            self.status["next_full"] = time.strftime("%m-%d %H:%M", time.localtime(next_full))
            hrs = cfg.get("vulnfeed_hours", 6)
            if hrs and now >= next_feed:
                next_feed = now + hrs * 3600
                self.run_vulnfeed()
            self.status["next_feed"] = time.strftime("%m-%d %H:%M", time.localtime(next_feed)) if hrs else "（已關閉）"
            if now - getattr(self, "_last_flush", 0) > 120:
                self._last_flush = now
                self.flush_outbox()
            if now >= next_full:
                self.scan("full", source="scheduler")
                next_full = self._next_full(cfg)
                next_quick = time.time() + cfg["quick_interval_min"] * 60
            elif now >= next_quick:
                self.scan("quick", source="scheduler")
                next_quick = time.time() + cfg["quick_interval_min"] * 60
            time.sleep(20)

    @staticmethod
    def _next_full(cfg):
        t = time.localtime()
        target = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, int(cfg["full_scan_hour"]), 0, 0, 0, 0, -1))
        return target + 86400 if target <= time.time() else target
