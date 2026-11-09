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
    "reminder_enabled": True,       # 未處理問題定期提醒
    "reminder_weekday": 0,          # 0 = 星期一
    "reminder_hour": 9,
    "escalate_days": 7,             # 高風險超過幾天未處理 → 改成每天提醒
    "secure_vault": "Personal",      # 封存含機密的檔案時用的 1Password vault
    "secure_dir": "~/Secure",       # 加密 DMG 存放的資料夾
    "watch_enabled": True,          # 關鍵位置即時監看
    "resource_monitor": True,
    "idle_project_days": 30,
    # 「寫死的機密 → .env.tpl」：op-run = 1Password 官方 op run（.env.tpl 放 op://…）；op-inject = {{ op://… }} 範本 + 自己的注入腳本
    "envtpl_style": "op-run",
    "envtpl_run": "",               # 執行指令範本（<指令> 會換成原本的指令）；空白 = 依格式用預設
    "envtpl_guide": "",             # 團隊自己的 1Password / .env 說明文件路徑（選填，會寫進處理紀錄）
    "envtpl_vault": "",             # 存放機密的 vault；空白 = 跟封存用的 vault 相同。修改需要 Touch ID        # 有問題的專案超過幾天沒有更新 → 報告列為「閒置專案」，可以批次封存       # CPU / 記憶體異常與新常駐程式監控（每分鐘取樣）
    "watch_interval_sec": 10,        # 第一次建立基準時也通知一次
    "report_keep_days": 30,         # 一般報告保留天數
    "full_report_keep_days": 90,    # 完整掃描報告保留天數
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


def backfill_first_seen(state):
    """舊版沒有記錄 first_seen：從過去的報告找出每個問題最早出現的時間補上（只在缺少時做一次）。"""
    from .diff import finding_key
    missing = [(s, k) for s, fs in (state.get("findings") or {}).items() for k, f in fs.items() if not f.get("first_seen")]
    if not missing:
        return
    earliest = {}
    for f in sorted(x for x in os.listdir(REPORTS) if x.endswith(".json")):
        d = _read(os.path.join(REPORTS, f), {})
        for x in d.get("findings", []):
            if x.get("severity") in ("high", "medium", "low"):
                earliest.setdefault((x.get("scope"), finding_key(x)), d.get("started"))
    for s, k in missing:
        state["findings"][s][k]["first_seen"] = earliest.get((s, k)) or state.get("updated") or time.strftime("%Y-%m-%d %H:%M:%S")


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
            from . import acks
            acks.apply(result)          # 已確認無害的問題移出 findings（檔案內容改變則標記失效）
            state = _read(os.path.join(DATA, "state.json"), {})
            backfill_first_seen(state)
            changes, new_state, baseline = compare(state, result)
            # 標註每個問題第一次出現的時間，報告裡顯示「已存在 N 天」
            from .diff import finding_key
            from .reminders import age_days
            for f in result["findings"]:
                ent = (new_state["findings"].get(f.get("scope"), {}) or {}).get(finding_key(f))
                if ent and ent.get("first_seen"):
                    f["first_seen"] = ent["first_seen"]
                    f["age_days"] = age_days(ent["first_seen"])
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
            # 排程 / 即時監看的快速掃描沒有變動時不另存報告（只更新狀態），避免報告清單被大量相同的報告淹沒
            skip_report = source in ("scheduler", "watch") and mode == "quick" and state and not changes and not baseline
            name = "" if skip_report else report.save_reports(result, REPORTS, changes if state else None, summary, sop)
            # 不發通知的手動掃描不更新比對基準，否則變動會被「吃掉」，排程掃描就永遠不會通知
            if notify_user or not state:
                _write_private(os.path.join(DATA, "state.json"), new_state)
            self._prune_reports(cfg)
            self.status["last_check"] = time.strftime("%H:%M:%S")
            try:        # 統計：沒有另存報告的快速掃描也要計數
                from . import stats as _stats
                cnt = {}
                for f in result.get("findings", []):
                    cnt[f["severity"]] = cnt.get(f["severity"], 0) + 1
                _stats.record_scan(mode, source, cnt, len(changes or []), sum(1 for c in (changes or []) if c.get("attention")),
                                   result.get("duration_sec"))
            except Exception:
                pass
            if name:
                self.status.update(last_report=name, last_changes=len(changes))
            else:
                self.status["phase"] = "完成（沒有變動，未另存報告）"
                return self.status.get("last_report") or ""
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

    def send_reminder(self, force=False):
        """送出未處理問題清單。回傳 (是否送出, 項目數, 是否升級中)。"""
        from . import reminders
        cfg = load_config()
        state = _read(os.path.join(DATA, "state.json"), {})
        feed_path = os.path.join(DATA, "vulnfeed.json")
        feed = _read(feed_path, {})
        pkgindex = _read(os.path.join(DATA, "cache.json"), {}).get("osv", {}).get("pkgindex", {})
        items, stale = reminders.open_items(state, feed.get("open", {}), pkgindex)
        if stale and feed.get("open"):
            for k in stale:
                feed["open"].pop(k, None)
            _write_private(feed_path, feed)
        esc = reminders.is_escalated(items, cfg)
        self.status["open_items"] = len(items)
        self.status["escalated"] = esc
        if not items and not force:
            return False, 0, esc
        import socket
        msg = reminders.build_message(items, cfg, "http://127.0.0.1:%d/" % cfg["web_port"], socket.gethostname()) if items else \
            "📋 目前沒有未處理的高 / 中風險問題 👍"
        ok = notify.telegram_send(msg)
        if not ok:
            self._outbox_add(msg)
        self.status["last_reminder"] = time.strftime("%m-%d %H:%M")
        return ok, len(items), esc

    @staticmethod
    def settings_snapshot(cfg, mode, source, notify_user, online, trigger=None):
        from .core import home_rel
        ts = [t for t in load_targets(cfg) if t.enabled]
        return {
            "mode": mode, "source": source, "notify": bool(notify_user), "online": bool(online),
            "llm": bool(cfg.get("llm_enabled")) and bool(notify_user), "model": cfg.get("ollama_model"),
            "targets": [{"label": t.label, "path": home_rel(t.path), "exists": os.path.isdir(t.path)} for t in ts] if mode == "full" else [],
            "targets_note": "" if mode == "full" else
            "重新檢查只看舊報告提過的檔案與專案，不遍歷資料夾" if mode == "recheck" else "快速掃描不遍歷資料夾，掃描範圍只套用在完整掃描",
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

    def recheck(self, name):
        """重新檢查舊報告：只看舊報告提過的問題、套用目前的規則，存成一份新的報告（模式 recheck）。
        不更新比對基準（state.json），因為它不是完整掃描，不能拿來判斷「沒有出現的東西就是消失了」。"""
        if not name.replace("-", "").isdigit():
            return None
        old = _read(os.path.join(REPORTS, name + ".json"), None)
        if not old:
            self.status["last_error"] = "找不到報告 %s" % name
            return None
        if not self.lock.acquire(blocking=False):
            return None
        try:
            self.cancel.clear()
            cfg = load_config()
            self.status.update(running=True, mode="recheck", phase="重新檢查 %s" % name, current="",
                               started=time.strftime("%H:%M:%S"), last_error="")
            cache = _read(os.path.join(DATA, "cache.json"), {})
            from .scanner import run_recheck
            online = cfg.get("online", True)
            result = run_recheck(old, cache=cache, progress=self._progress, cancel=self.cancel, online=online)
            _write_private(os.path.join(DATA, "cache.json"), cache)
            if result["cancelled"]:
                self.status["phase"] = "已取消"
                return None
            excluded_carry = result.pop("_excluded_carry", [])
            from .prune import prune as _prune
            pruned = _prune(DATA)          # 已經不存在的專案 / 檔案：清掉比對基準、已確認無害標記、修復紀錄
            result["settings"] = self.settings_snapshot(cfg, "recheck", "manual", False, online)
            from . import acks
            from .diff import finding_key
            from .recheck import compare as rc_compare
            from .reminders import age_days
            acks.apply(result)
            state = _read(os.path.join(DATA, "state.json"), {})
            backfill_first_seen(state)
            for f in result["findings"]:
                ent = ((state.get("findings") or {}).get(f.get("scope"), {}) or {}).get(finding_key(f))
                if ent and ent.get("first_seen"):
                    f["first_seen"] = ent["first_seen"]
                    f["age_days"] = age_days(ent["first_seen"])
            result["recheck"] = dict(rc_compare(old, result, excluded_carry), of=name, of_started=old.get("started", ""),
                                     of_mode=old.get("mode", ""), pruned=pruned)
            from .core import home_rel
            sop = build_sop(cfg, [{"path": t.path, "display": home_rel(t.path), "label": t.label, "enabled": t.enabled}
                                  for t in load_targets(cfg)])
            new_name = report.save_reports(result, REPORTS, None, "", sop)
            self._prune_reports(cfg)
            c = result["recheck"]["counts"]
            self.status.update(last_report=new_name, last_check=time.strftime("%H:%M:%S"),
                               phase="完成：已改善 %d、規則排除 %d、等級改變 %d、仍存在 %d、新出現 %d%s" % (
                                   c["resolved"], c["excluded"], c["reclassified"], c["still"], c["new"],
                                   "；清掉 %d 個已刪除專案的資料" % len(pruned["projects"]) if pruned["projects"] else ""))
            return new_name
        except Exception as e:
            self.status["last_error"] = "%s: %s" % (type(e).__name__, str(e)[:200])
            traceback.print_exc()
            return None
        finally:
            self.status["running"] = False
            self.lock.release()

    def recheck_async(self, name):
        if self.status["running"]:
            return False
        threading.Thread(target=self.recheck, args=(name,), daemon=True).start()
        return True

    def scan_async(self, mode, notify_user=True):
        if self.status["running"]:
            return False
        threading.Thread(target=self.scan, args=(mode, notify_user), daemon=True).start()
        return True

    def _prune_reports(self, cfg):
        """依天數保留：一般報告 report_keep_days 天、完整掃描 full_report_keep_days 天；最新 5 份一律保留。
        檔名就是時間，所以只有超過保留天數的報告才需要打開來看是不是完整掃描。"""
        if time.time() - getattr(self, "_last_prune", 0) < 3600:
            return
        self._last_prune = time.time()
        keep = int(cfg.get("report_keep_days", 30))
        keep_full = int(cfg.get("full_report_keep_days", 90))
        names = sorted({f.rsplit(".", 1)[0] for f in os.listdir(REPORTS) if f.endswith(".json")})
        now = time.time()
        for n in names[:-5]:
            try:
                age = (now - time.mktime(time.strptime(n, "%Y%m%d-%H%M%S"))) / 86400
            except ValueError:
                continue
            if age <= keep:
                continue
            if age <= keep_full and _read(os.path.join(REPORTS, n + ".json"), {}).get("mode") == "full":
                continue
            for ext in (".json", ".md", ".html"):
                try:
                    os.remove(os.path.join(REPORTS, n + ext))
                except OSError:
                    pass

    def reports(self, page=None, size=15):
        """報告清單。每份報告的摘要依檔案修改時間快取在記憶體，不用每次重讀全部 JSON。
        page=None 回傳全部（list）；否則回傳 {"items", "total", "page", "pages"}。"""
        cache = self.__dict__.setdefault("_report_index", {})
        names = sorted((f for f in os.listdir(REPORTS) if f.endswith(".json")), reverse=True)
        for k in list(cache):
            if k not in names:
                del cache[k]
        out = []
        for f in names:
            try:
                mt = os.path.getmtime(os.path.join(REPORTS, f))
            except OSError:
                continue
            ent = cache.get(f)
            if ent and ent[0] == mt:
                out.append(ent[1])
                continue
            d = _read(os.path.join(REPORTS, f), {})
            cnt = {}
            for x in d.get("findings", []):
                cnt[x["severity"]] = cnt.get(x["severity"], 0) + 1
            st = d.get("settings") or {}
            out.append({"name": f[:-5], "started": d.get("started"), "mode": d.get("mode"), "counts": cnt,
                        "source": st.get("source", ""), "targets": [t["path"] for t in st.get("targets", [])] or
                        [t["path"] for t in d.get("targets", [])], "notify": st.get("notify"),
                        "online": st.get("online"), "llm": st.get("llm"), "model": st.get("model"),
                        "changes": len(d.get("changes") or []), "attention": sum(1 for c in (d.get("changes") or []) if c.get("attention"))})
            cache[f] = (mt, out[-1])
        if page is None:
            return out
        pages = max(1, (len(out) + size - 1) // size)
        page = min(max(1, page), pages)
        return {"items": out[(page - 1) * size: page * size], "total": len(out), "page": page, "pages": pages}

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
        from . import reminders
        _items, _ = reminders.open_items(state, _read(os.path.join(DATA, "vulnfeed.json"), {}).get("open", {}),
                                         _read(os.path.join(DATA, "cache.json"), {}).get("osv", {}).get("pkgindex", {}))
        next_rem = reminders.next_time(cfg, reminders.is_escalated(_items, cfg))
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
            if cfg.get("reminder_enabled", True):
                if now >= next_rem:
                    _ok, _n, esc = self.send_reminder()
                    next_rem = reminders.next_time(cfg, esc, now + 60)
                self.status["next_reminder"] = time.strftime("%m-%d %H:%M", time.localtime(next_rem))
            else:
                self.status["next_reminder"] = "（已關閉）"
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
