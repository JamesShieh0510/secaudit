"""本機 Web UI。只綁 127.0.0.1，並用 token + SameSite cookie + Host 檢查防止其他網頁或程式操作。"""
import http.cookies
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import acks as acks_mod
from .app import DATA, REPORTS, Engine, load_config, load_targets, normalize_host, save_config
from .app import _read as _app_read
from .core import home_rel

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
# 內建的第三方前端程式：固定版本（從 npm 官方 tarball 取出，比對過 registry 的 sha512），提供前再比對 sha256，被改過就不提供
VENDOR = {"/static/vendor/mermaid-11.4.1.min.js": "a43bc1afd446f9c4cc66ac5dd45d02e8d65e26fc5344ec0ef787f88d6ddb6f9e"}
REPORT_RE = re.compile(r"^/reports/(\d{8}-\d{6})\.(html|md|json)$")


def get_token():
    p = os.path.join(DATA, "web_token")
    try:
        with open(p) as fh:
            t = fh.read().strip()
            if len(t) >= 32:
                return t
    except OSError:
        pass
    t = secrets.token_urlsafe(32)
    os.makedirs(DATA, mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(t)
    return t


def _vulnfeed_history():
    try:
        with open(os.path.join(DATA, "vulnfeed.json"), encoding="utf-8") as fh:
            h = json.load(fh).get("history", [])
    except (OSError, ValueError):
        return []
    return [{"time": r["time"], "period": r["period"], "manual": r.get("manual", False), "fetched": r["fetched"], "sent": r.get("sent"),
             "index_size": r.get("index_size", 0), "affected": r["affected"][:200], "kev": r["kev"][:10],
             "notable": r["notable"][:5], "ai": r.get("ai", ""), "sums": r.get("sums", {})} for r in h[:30]]


def next_settings(engine, cfg):
    """下一次掃描會套用的設定，以及範圍是否已套用到最近一次完整掃描。"""
    ts = [t for t in load_targets(cfg) if t.enabled]
    cur = sorted(home_rel(t.path) for t in ts)
    last_full = next((r for r in engine.reports() if r["mode"] == "full"), None)
    applied, pending = None, []
    if last_full:
        applied = sorted(last_full.get("targets") or []) == cur
        old = set(last_full.get("targets") or [])
        pending += ["新增掃描範圍：%s" % p for p in cur if p not in old]
        pending += ["移除掃描範圍：%s" % p for p in sorted(old - set(cur))]
        on = lambda b: "開" if b else "關"
        if last_full.get("online") is not None and bool(last_full["online"]) != bool(cfg.get("online")):
            pending.append("連網查詢 CVE：%s → %s" % (on(last_full["online"]), on(cfg.get("online"))))
        if last_full.get("llm") is not None and bool(last_full["llm"]) != bool(cfg.get("llm_enabled")):
            pending.append("AI 摘要：%s → %s" % (on(last_full["llm"]), on(cfg.get("llm_enabled"))))
        if last_full.get("model") and last_full["model"] != cfg.get("ollama_model"):
            pending.append("AI 模型：%s → %s" % (last_full["model"], cfg.get("ollama_model")))
    return {"targets": [{"label": t.label, "path": home_rel(t.path), "exists": os.path.isdir(t.path)} for t in ts],
            "next_quick": engine.status.get("next_quick", ""), "next_full": engine.status.get("next_full", ""),
            "online": cfg.get("online"), "llm": cfg.get("llm_enabled"), "model": cfg.get("ollama_model"),
            "watch": cfg.get("watch_enabled", True),
            "last_full": last_full["started"] if last_full else "", "applied": applied, "pending": pending}


def make_handler(engine: Engine, token: str, port: int):
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    codes, codes_lock = {}, threading.Lock()

    class H(BaseHTTPRequestHandler):
        server_version = "secaudit"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            data = body if isinstance(body, bytes) else (json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            extra = dict(extra or {})
            self.send_header("Cache-Control", extra.pop("Cache-Control", "no-store"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", extra.pop("X-Frame-Options", "DENY"))
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            if self.headers.get("Host") not in allowed_hosts:   # 防 DNS rebinding
                return False
            c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return "sa" in c and secrets.compare_digest(c["sa"].value, token)

        def _live_report(self, name, fmt):
            """報告依目前的標記重新產生；JSON 讀不到或產生失敗就退回原本存好的檔案。"""
            from . import report as _report
            from .sop import build_sop
            try:
                with open(os.path.join(REPORTS, name + ".json"), encoding="utf-8") as fh:
                    payload = json.load(fh)
                sop = None
                if not payload.get("sop"):
                    cfg = load_config()
                    sop = build_sop(cfg, [{"path": t.path, "display": home_rel(t.path), "label": t.label,
                                           "enabled": t.enabled} for t in load_targets(cfg)])
                return _report.render_live(payload, name, sop, fmt).encode("utf-8")
            except Exception:
                import traceback
                traceback.print_exc()
                return None

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(u.query)
            if u.path == "/" and qs.get("c") and self.headers.get("Host") in allowed_hosts:
                with codes_lock:
                    t0 = codes.pop(qs["c"][0], None)
                    for k in [k for k, v in codes.items() if time.time() - v > 60]:   # 順便清掉過期的
                        del codes[k]
                if t0 and time.time() - t0 < 60:
                    # 不能用 303：這次瀏覽是從 127.0.0.1（別的網站）跳過來的，轉址後的請求不會帶 SameSite=Strict 的 cookie。
                    # 改成回傳一頁，由 localhost 自己的頁面再跳轉，對瀏覽器來說就是同站。
                    return self._send(200, '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/">'
                                           '<p>登入中… <a href="/">繼續</a></p>', "text/html; charset=utf-8",
                                      {"Set-Cookie": "sa=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000" % token})
            if u.path == "/" and qs.get("t") and self.headers.get("Host") in allowed_hosts:
                if secrets.compare_digest(qs["t"][0], token):
                    self.send_response(303)
                    self.send_header("Set-Cookie", "sa=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000" % token)
                    self.send_header("Location", "/")
                    self.end_headers()
                    return
            if not self._authed():
                return self._send(401, "<h3>需要登入</h3><p>請使用終端機或 PM2 日誌中印出的網址開啟（含 ?t=…）。</p>",
                                  "text/html; charset=utf-8")
            if u.path == "/":
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if u.path == "/api/stats":
                from . import stats as stats_mod
                try:
                    days = max(0, min(3650, int((qs.get("days") or ["30"])[0])))
                except ValueError:
                    days = 30
                group = (qs.get("group") or ["full"])[0]
                group = group if group in ("full", "quick", "watch") else "full"
                return self._send(200, stats_mod.build(engine, days, group))
            if u.path == "/api/resources":
                # 資源監控 24 小時內的事件（頁首「常駐程式 / CPU / 記憶體」卡片點進來看）
                d = _app_read(os.path.join(DATA, "resources.json"), {})
                cut = time.time() - 86400
                ev = [e for e in d.get("events", []) if e.get("ts", 0) >= cut]
                return self._send(200, {"events": ev[::-1], "baseline": d.get("baseline", ""),
                                        "status": engine.status.get("resources") or {}})
            if u.path == "/api/perf":
                # 「⚡ 效能」頁籤：即時取樣（有人開著頁籤才會呼叫；2.5 秒快取）
                from . import perf
                d = perf.live(engine)
                if "md=1" in (u.query or ""):
                    return self._send(200, {"md": perf.as_markdown(d)})
                return self._send(200, d)
            if u.path in VENDOR:
                with open(os.path.join(STATIC, u.path[len("/static/"):]), "rb") as fh:
                    data = fh.read()
                if hashlib.sha256(data).hexdigest() != VENDOR[u.path]:
                    return self._send(500, {"error": "內建的 %s 和預期的 sha256 不一致，可能被竄改，已拒絕提供" % os.path.basename(u.path)})
                return self._send(200, data, "text/javascript; charset=utf-8", {"Cache-Control": "private, max-age=86400"})
            if u.path == "/api/state":
                cfg = load_config()
                return self._send(200, {
                    "status": engine.status,
                    "targets": [{"path": t.path, "display": home_rel(t.path), "label": t.label, "kind": t.kind,
                                 "enabled": t.enabled, "exists": os.path.isdir(t.path)} for t in load_targets(cfg)],
                    "reports": engine.reports(page=int((qs.get("rpage") or ["1"])[0] or 1), size=15),
                    "next": next_settings(engine, cfg),
                    "vulnfeed": _vulnfeed_history(),
                    "acks": acks_mod.items(),
                    "config": {k: cfg.get(k) for k in ("quick_interval_min", "full_scan_hour", "online", "llm_enabled",
                                                       "ollama_host", "ollama_model", "vulnfeed_hours", "reminder_enabled",
                                                       "reminder_weekday", "reminder_hour", "escalate_days", "secure_vault", "secure_dir",
                                                       "idle_project_days", "envtpl_style", "envtpl_run", "envtpl_guide",
                                                       "envtpl_vault")},
                    "secrets": {"telegram": bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")),
                                "ollama": bool(os.environ.get("OLLAMA_API_KEY"))},
                })
            if u.path == "/api/github":
                from . import ghwatch
                cfg = load_config()
                if "md=1" in (u.query or ""):
                    sev = urllib.parse.parse_qs(u.query).get("min", ["info"])[0]
                    return self._send(200, {"md": ghwatch.as_markdown(cfg, sev if sev in ("high", "medium", "low", "info") else "info")})
                st = ghwatch.load_alerts()
                marks = ghwatch.load_marks()
                alerts = sorted(st["alerts"].items(), key=lambda kv: (-kv[1].get("last", 0)))
                return self._send(200, {
                    "config": cfg.get("github_watch") or {},
                    "available": ghwatch.gh_accounts(),
                    "status": st.get("status") or {}, "running": bool(engine.status.get("github_running")),
                    "next": engine.status.get("next_github", ""),
                    "owners": {k: {"last_ok": v.get("last_ok"), "error": v.get("error", ""), "is_org": v.get("is_org"),
                                   "repos": v.get("repos_seen"), "audit_at": (v.get("audit") or {}).get("at")}
                               for k, v in st["owners"].items()},
                    "timeline": ghwatch.timeline()[-2000:],
                    "alerts": [dict({k: a.get(k) for k in ("rule", "severity", "title", "path", "detail", "evidence", "first", "last", "count", "owner")},
                                    key=key, check=(a.get("check") or {}).get("note", ""),
                                    state=ghwatch.alert_state(key, a, marks)[0], resolved=ghwatch.alert_state(key, a, marks)[1])
                               for key, a in alerts[:400]],
                })
            if u.path == "/api/actions":
                from . import actions, webauthn
                return self._send(200, {"catalog": actions.catalog(), "status": actions.status, "history": actions.history(),
                                        "queue": actions.queue_public(),
                                        "recent": actions.recent,
                                        "keys": webauthn.public_keys(),
                                        "localhost": self.headers.get("Host") == "localhost:%d" % port})
            if u.path == "/sop":
                from .report import CSS
                from .sop import build_sop, to_html as sop_html
                import html as _h
                cfg = load_config()
                blocks = build_sop(cfg, [{"path": t.path, "display": home_rel(t.path), "label": t.label, "enabled": t.enabled}
                                         for t in load_targets(cfg)])
                if "frag=1" in u.query:       # Web UI 的 SOP 分頁
                    return self._send(200, sop_html(blocks, _h.escape), "text/html; charset=utf-8")
                page = ('<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>運作 SOP</title>'
                        '<style>%s .sop{border:0;padding:0;background:none}</style></head><body><div class="wrap">'
                        '<p><a href="/" style="color:var(--info)">← 回到主控台</a></p>%s'
                        '<p class="muted" style="margin-top:24px">內容依照目前設定即時產生；修改設定後重新整理即可看到最新版本。</p>'
                        '</div><script src="/static/vendor/mermaid-11.4.1.min.js"></script><script>'
                        'mermaid.initialize({startOnLoad:false,securityLevel:"strict",theme:matchMedia("(prefers-color-scheme: dark)").matches?"dark":"default"});'
                        'mermaid.run({querySelector:"pre.mermaid"}).then(()=>document.querySelectorAll(".mmd-note").forEach(x=>x.remove()));'
                        '</script></body></html>') % (CSS, sop_html(blocks, _h.escape))
                return self._send(200, page, "text/html; charset=utf-8")
            m = REPORT_RE.match(u.path)
            if m:
                p = os.path.join(REPORTS, "%s.%s" % m.groups())
                if not os.path.isfile(p):
                    return self._send(404, {"error": "not found"})
                body = None
                if m.group(2) in ("html", "md"):
                    body = self._live_report(m.group(1), m.group(2))
                if body is None:
                    with open(p, "rb") as fh:
                        body = fh.read()
                ctype = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
                         "json": "application/json; charset=utf-8"}[m.group(2)]
                # 報告只允許被主控台自己的彈窗嵌入（同源），其他網站不能用 iframe 嵌入
                extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                                                    "connect-src 'self'; frame-ancestors 'self'",
                         "X-Frame-Options": "SAMEORIGIN"}
                if qs.get("dl"):
                    extra["Content-Disposition"] = 'attachment; filename="security-%s.%s"' % m.groups()
                return self._send(200, body, ctype, extra)
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._authed() or self.headers.get("X-Secaudit") != "1":   # 自訂 header：跨站表單送不出來
                return self._send(403, {"error": "forbidden"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(min(n, 1024 * 1024)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            path = urllib.parse.urlparse(self.path).path
            if path == "/api/scan":
                mode = "quick" if body.get("mode") == "quick" else "full"
                ok = engine.scan_async(mode, notify_user=bool(body.get("notify", False)))
                return self._send(200 if ok else 409, {"started": ok})
            if path == "/api/recheck":
                # 重新檢查舊報告：只讀取、不修改任何檔案，所以不需要授權
                name = str(body.get("report", ""))[:32]
                if not name.replace("-", "").isdigit() or not os.path.isfile(os.path.join(REPORTS, name + ".json")):
                    return self._send(404, {"started": False, "error": "找不到這份報告"})
                ok = engine.recheck_async(name)
                return self._send(200 if ok else 409, {"started": ok, "error": "" if ok else "目前有掃描在進行，請等它完成"})
            if path == "/api/reminder":
                ok, n, esc = engine.send_reminder(force=True)
                return self._send(200, {"ok": ok, "items": n, "escalated": esc})
            if path == "/api/vulnfeed":
                if engine.status.get("feed_running"):
                    return self._send(409, {"started": False})
                import threading
                lb = body.get("lookback_hours")
                lb = None if lb in (None, "", "since") else max(1, min(24 * 30, int(lb)))
                threading.Thread(target=engine.run_vulnfeed, kwargs={"force": True, "lookback_hours": lb}, daemon=True).start()
                return self._send(200, {"started": True})
            if path == "/api/cancel":
                engine.cancel.set()
                return self._send(200, {"ok": True})
            if path == "/api/targets":
                out = []
                for t in body.get("targets", []):
                    p = os.path.realpath(os.path.expanduser(str(t.get("path", ""))))
                    if not os.path.isabs(p) or p == "/":
                        continue
                    out.append({"path": p, "label": str(t.get("label", ""))[:80] or os.path.basename(p),
                                "kind": t.get("kind", "custom") if t.get("kind") in ("home", "cloud", "volume", "custom") else "custom",
                                "enabled": bool(t.get("enabled", True))})
                cfg = load_config()
                cfg["targets"] = out
                save_config(cfg)
                return self._send(200, {"ok": True})
            if path == "/api/config":
                cfg = load_config()
                for k, typ in (("quick_interval_min", int), ("full_scan_hour", int), ("online", bool),
                               ("llm_enabled", bool), ("ollama_model", str), ("vulnfeed_hours", int),
                               ("reminder_enabled", bool), ("reminder_weekday", int), ("reminder_hour", int), ("escalate_days", int),
                               ("idle_project_days", int)):
                    if k in body:
                        cfg[k] = typ(body[k])
                if "ollama_host" in body:
                    try:
                        cfg["ollama_host"] = normalize_host(body["ollama_host"])
                    except ValueError as e:
                        return self._send(400, {"error": str(e)})
                cfg["reminder_weekday"] = min(6, max(0, cfg.get("reminder_weekday", 0)))
                cfg["reminder_hour"] = min(23, max(0, cfg.get("reminder_hour", 9)))
                cfg["escalate_days"] = min(90, max(1, cfg.get("escalate_days", 7)))
                cfg["idle_project_days"] = min(3650, max(7, cfg.get("idle_project_days", 30)))
                if body.get("envtpl_style") in ("op-run", "op-inject"):
                    cfg["envtpl_style"] = body["envtpl_style"]
                for k, n in (("envtpl_run", 200), ("envtpl_guide", 300)):
                    if k in body:
                        cfg[k] = str(body[k]).replace("\n", " ").strip()[:n]
                cfg["quick_interval_min"] = max(5, cfg["quick_interval_min"])
                cfg["full_scan_hour"] = min(23, max(0, cfg["full_scan_hour"]))
                save_config(cfg)
                return self._send(200, {"ok": True})
            if path == "/api/github/config":
                from .ghwatch import NAME_RE
                accs, seen = [], set()
                for a in body.get("accounts") or []:
                    login = str(a.get("login", "")).strip()
                    if not NAME_RE.match(login) or login.lower() in seen:
                        continue
                    seen.add(login.lower())
                    owners = []
                    for o in a.get("owners") or []:
                        o = str(o).strip().strip("/").split("/")[-1]
                        if NAME_RE.match(o) and o.lower() not in {x.lower() for x in owners}:
                            owners.append(o)
                    accs.append({"login": login, "owners": owners[:30], "enabled": bool(a.get("enabled", True))})
                cfg = load_config()
                cfg["github_watch"] = {"enabled": bool(body.get("enabled")), "accounts": accs[:10],
                                       "interval_min": min(240, max(5, int(body.get("interval_min") or 15)))}
                save_config(cfg)
                engine._next_gh = 0          # 存檔後馬上檢查一次
                return self._send(200, {"ok": True})
            if path == "/api/github/mark":
                # 手動標記會降低警示，跟「已確認無害」一樣每次都發 Telegram
                from . import ghwatch
                from .notify import telegram_send
                import html as _h
                keys = [str(k)[:400] for k in (body.get("keys") or [body.get("key", "")]) if k][:500]
                kind = str(body.get("kind", ""))
                note = str(body.get("note", ""))[:300]
                ok_n, err = 0, ""
                for k in keys:
                    ok, msg = ghwatch.mark(k, kind, note)
                    ok_n += ok
                    err = err or ("" if ok else msg)
                if ok_n:
                    label = {"fixed": "已處理", "false_positive": "誤判", "reopen": "撤銷標記（重新列出）"}.get(kind, kind)
                    telegram_send("🐙 secaudit：%d 筆 GitHub 警示標記為「%s」%s。不是你做的話請到 Web UI 撤銷。" % (
                        ok_n, label, ("，備註：" + _h.escape(note[:100])) if note else ""))
                return self._send(200 if ok_n else 404, {"ok": bool(ok_n), "count": ok_n, "error": err})
            if path == "/api/github/poll":
                ok = engine.github_poll_async(force_audit=bool(body.get("audit")))
                return self._send(200 if ok else 409, {"started": ok})
            if path == "/api/pick":
                # 叫出 macOS 原生的「選擇資料夾」視窗
                try:
                    r = subprocess.run(["osascript", "-e", 'POSIX path of (choose folder with prompt "選擇要加入掃描的資料夾（例如 NAS）")'],
                                       capture_output=True, text=True, timeout=300)
                    p = r.stdout.strip().rstrip("/")
                except (OSError, subprocess.TimeoutExpired):
                    p = ""
                return self._send(200, {"path": p})
            if path == "/api/test-ollama":
                from .notify import test_ollama
                try:
                    host = normalize_host(body.get("host"))
                except ValueError as e:
                    return self._send(200, {"ok": False, "error": str(e), "models": []})
                return self._send(200, test_ollama(host, str(body.get("model", ""))[:100]))
            if path == "/api/notify":
                # 讓本機指令（例如維護腳本、AI 助手）在需要你介入前先發 Telegram 提醒；常駐程式已持有金鑰，不需再觸發 1Password
                from .notify import telegram_send
                import html as _h
                text = str(body.get("text", "")).strip()[:1500]
                if not text:
                    return self._send(400, {"ok": False})
                return self._send(200, {"ok": telegram_send("🔔 " + _h.escape(text))})
            if path == "/api/actions/plan":
                # 只產生預覽，不修改任何東西
                from . import actions
                try:
                    return self._send(200, actions.make_plan(str(body.get("action", "")), str(body.get("report", ""))[:32],
                                                                str(body.get("focus", ""))[:2000]))
                except KeyError:
                    return self._send(404, {"error": "未知的動作"})
                except Exception as e:
                    return self._send(500, {"error": "%s: %s" % (type(e).__name__, str(e)[:200])})
            if path == "/api/actions/all-md":
                # 全部修復動作的預覽彙整（只讀）
                from . import actions
                return self._send(200, {"markdown": actions.all_plans_markdown(str(body.get("report", ""))[:32])})
            if path == "/api/actions/plan-md":
                # 修復預覽彙整成 Markdown（只讀）
                from . import actions
                text = actions.plan_markdown(str(body.get("plan_id", "")), [str(x) for x in body.get("steps", [])][:5000])
                if text is None:
                    return self._send(404, {"error": "預覽已過期，請重新預覽"})
                return self._send(200, {"markdown": text})
            if path == "/api/actions/ack-steps":
                # 「已確認無害」會降低警示：伺服器端發 Telegram（ack_steps 裡）
                from . import actions
                n, errs = actions.ack_steps(str(body.get("plan_id", "")), [str(x) for x in body.get("steps", [])][:500],
                                            str(body.get("note", ""))[:200])
                return self._send(200, {"ok": n > 0, "done": n, "errors": errs[:10]})
            if path == "/api/actions/open-step":
                # 在對應的瀏覽器 profile 打開登出頁：只開網頁、不修改任何東西，網址由伺服器端的預覽決定
                from . import actions
                ok, msg = actions.open_step(str(body.get("plan_id", "")), str(body.get("step", ""))[:16])
                return self._send(200, {"ok": ok, "message": msg})
            if path == "/api/actions/unqueue":
                from . import actions
                return self._send(200, {"ok": actions.unqueue(str(body.get("qid", "")))})
            if path == "/api/actions/cancel":
                from . import actions
                return self._send(200, {"ok": actions.cancel()})
            if path == "/api/actions/run":
                # 會修改系統：伺服器端一定先跳 Touch ID，通過後才執行預覽過的步驟
                from . import actions
                ids = [str(x) for x in body.get("steps", [])][:500]
                ok, msg = actions.start(str(body.get("plan_id", "")), ids, method=str(body.get("method", "touchid")),
                                        assertion=body.get("assertion") if isinstance(body.get("assertion"), dict) else None,
                                        port=port)
                if msg == "queued":
                    return self._send(200, {"started": False, "queued": True})
                return self._send(200 if ok else 409, {"started": ok, "error": msg})
            if path == "/api/auth/options":
                # YubiKey 授權用的 challenge，綁定這次要授權的內容（某份預覽的某些步驟 / 某把要新增或刪除的金鑰）
                from . import actions, webauthn
                purpose = body.get("purpose")
                if purpose == "run":
                    opts = actions.yubikey_options(str(body.get("plan_id", "")), [str(x) for x in body.get("steps", [])][:500])
                elif purpose == "add-key" and isinstance(body.get("reg"), dict):
                    opts = webauthn.request_options("add-key", actions.key_add_binding(body["reg"]))
                elif purpose == "secure-cfg":
                    opts = webauthn.request_options("secure-cfg", actions.secure_cfg_binding(
                        str(body.get("vault", ""))[:100], str(body.get("dir", ""))[:500], str(body.get("env_vault", ""))[:100]))
                elif purpose == "del-key":
                    opts = webauthn.request_options("del-key", "del|" + str(body.get("id", "")))
                else:
                    return self._send(400, {"error": "bad purpose"})
                return self._send(200 if opts else 409, opts or {"error": "沒有已註冊的 YubiKey，或預覽已過期"})
            if path == "/api/keys/create-options":
                from . import webauthn
                return self._send(200, webauthn.creation_options(port))
            if path in ("/api/keys/add", "/api/keys/remove"):
                from . import actions
                method = str(body.get("method", "touchid"))
                asr = body.get("assertion") if isinstance(body.get("assertion"), dict) else None
                if path == "/api/keys/add":
                    ok, msg = actions.key_add(body.get("reg") if isinstance(body.get("reg"), dict) else {}, method, asr, port)
                else:
                    ok, msg = actions.key_remove(str(body.get("id", "")), method, asr, port)
                return self._send(200 if ok else 409, {"ok": ok, "error": msg})
            if path == "/api/switch-host":
                # 一次性、60 秒有效的登入碼，用來從 127.0.0.1 切到 localhost（WebAuthn 不接受 IP 位址），不把 token 交給網頁
                code = secrets.token_urlsafe(24)
                with codes_lock:
                    codes[code] = time.time()
                return self._send(200, {"url": "http://localhost:%d/?c=%s" % (port, code)})
            if path == "/api/secure-settings":
                # 封存用的 vault / DMG 資料夾決定機密被送去哪裡：一般的「儲存設定」不能改，要另外通過 Touch ID
                from . import actions
                ok, msg = actions.secure_settings_update(str(body.get("vault", ""))[:100], str(body.get("dir", ""))[:500],
                                                         method=str(body.get("method", "touchid")),
                                                         assertion=body.get("assertion") if isinstance(body.get("assertion"), dict) else None,
                                                         port=port, env_vault=str(body.get("env_vault", ""))[:100]
                                                         if "env_vault" in body else None)
                return self._send(200 if ok else 409, {"ok": ok, "error": msg})
            if path in ("/api/ack", "/api/unack"):
                # 「已確認無害」會降低警示，所以每次新增 / 取消都發 Telegram，讓使用者知道
                from . import acks
                from .notify import telegram_send
                import html as _h
                if path == "/api/ack":
                    ok, msg, ent = acks.add_from_report(str(body.get("report", ""))[:32], str(body.get("key", ""))[:1000],
                                                        str(body.get("note", ""))[:200])
                    if ok:
                        telegram_send("✅ secaudit：已將「%s」標記為已確認無害%s。不是你做的話請到 Web UI 取消。" % (
                            _h.escape(ent["title"][:120]), "（綁定檔案內容）" if ent["sha"] else ""))
                    return self._send(200 if ok else 404, {"ok": ok, "error": msg})
                key = str(body.get("key", ""))[:1000]
                ent = next((x for x in acks.items() if x["key"] == key), None)
                ok = acks.remove(key)
                if ok and ent:
                    telegram_send("↩️ secaudit：已取消「%s」的無害標記，下一次掃描起會重新列出。" % _h.escape(ent["title"][:120]))
                return self._send(200 if ok else 404, {"ok": ok})
            if path == "/api/test-telegram":
                from .notify import telegram_send
                return self._send(200, {"ok": telegram_send("🛡 secaudit 測試訊息：Telegram 警示設定成功。")})
            return self._send(404, {"error": "not found"})

    return H


def serve(engine: Engine, port: int):
    token = get_token()
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine, token, port))
    print("[secaudit] Web UI：http://127.0.0.1:%d/?t=%s" % (port, token), flush=True)
    print("[secaudit] 要用 YubiKey 授權時請改用：http://localhost:%d/?t=%s" % (port, token), flush=True)
    srv.serve_forever()
