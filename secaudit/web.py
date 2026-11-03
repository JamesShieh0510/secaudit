"""本機 Web UI。只綁 127.0.0.1，並用 token + SameSite cookie + Host 檢查防止其他網頁或程式操作。"""
import http.cookies
import json
import os
import re
import secrets
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .app import DATA, REPORTS, Engine, load_config, load_targets, normalize_host, save_config
from .core import home_rel

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
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
             "index_size": r.get("index_size", 0), "affected": r["affected"][:20], "kev": r["kev"][:10],
             "notable": r["notable"][:5], "ai": r.get("ai", ""), "sums": r.get("sums", {})} for r in h[:10]]


def next_settings(engine, cfg):
    """下一次掃描會套用的設定，以及範圍是否已套用到最近一次完整掃描。"""
    ts = [t for t in load_targets(cfg) if t.enabled]
    cur = sorted(home_rel(t.path) for t in ts)
    last_full = next((r for r in engine.reports() if r["mode"] == "full"), None)
    applied = None
    if last_full:
        applied = sorted(last_full.get("targets") or []) == cur
    return {"targets": [{"label": t.label, "path": home_rel(t.path), "exists": os.path.isdir(t.path)} for t in ts],
            "next_quick": engine.status.get("next_quick", ""), "next_full": engine.status.get("next_full", ""),
            "online": cfg.get("online"), "llm": cfg.get("llm_enabled"), "model": cfg.get("ollama_model"),
            "watch": cfg.get("watch_enabled", True),
            "last_full": last_full["started"] if last_full else "", "applied": applied}


def make_handler(engine: Engine, token: str, port: int):
    allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}

    class H(BaseHTTPRequestHandler):
        server_version = "secaudit"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            data = body if isinstance(body, bytes) else (json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
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

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(u.query)
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
            if u.path == "/api/state":
                cfg = load_config()
                return self._send(200, {
                    "status": engine.status,
                    "targets": [{"path": t.path, "display": home_rel(t.path), "label": t.label, "kind": t.kind,
                                 "enabled": t.enabled, "exists": os.path.isdir(t.path)} for t in load_targets(cfg)],
                    "reports": engine.reports()[:40],
                    "next": next_settings(engine, cfg),
                    "vulnfeed": _vulnfeed_history(),
                    "config": {k: cfg.get(k) for k in ("quick_interval_min", "full_scan_hour", "online", "llm_enabled",
                                                       "ollama_host", "ollama_model", "vulnfeed_hours", "reminder_enabled",
                                                       "reminder_weekday", "reminder_hour", "escalate_days")},
                    "secrets": {"telegram": bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID")),
                                "ollama": bool(os.environ.get("OLLAMA_API_KEY"))},
                })
            if u.path == "/sop":
                from .report import CSS
                from .sop import build_sop, to_html as sop_html
                import html as _h
                cfg = load_config()
                blocks = build_sop(cfg, [{"path": t.path, "display": home_rel(t.path), "label": t.label, "enabled": t.enabled}
                                         for t in load_targets(cfg)])
                page = ('<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">'
                        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>運作 SOP</title>'
                        '<style>%s .sop{border:0;padding:0;background:none}</style></head><body><div class="wrap">'
                        '<p><a href="/" style="color:var(--info)">← 回到主控台</a></p>%s'
                        '<p class="muted" style="margin-top:24px">內容依照目前設定即時產生；修改設定後重新整理即可看到最新版本。</p>'
                        '</div></body></html>') % (CSS, sop_html(blocks, _h.escape))
                return self._send(200, page, "text/html; charset=utf-8")
            m = REPORT_RE.match(u.path)
            if m:
                p = os.path.join(REPORTS, "%s.%s" % m.groups())
                if not os.path.isfile(p):
                    return self._send(404, {"error": "not found"})
                with open(p, "rb") as fh:
                    body = fh.read()
                ctype = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
                         "json": "application/json; charset=utf-8"}[m.group(2)]
                extra = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"}
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
                               ("reminder_enabled", bool), ("reminder_weekday", int), ("reminder_hour", int), ("escalate_days", int)):
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
                cfg["quick_interval_min"] = max(5, cfg["quick_interval_min"])
                cfg["full_scan_hour"] = min(23, max(0, cfg["full_scan_hour"]))
                save_config(cfg)
                return self._send(200, {"ok": True})
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
            if path == "/api/test-telegram":
                from .notify import telegram_send
                return self._send(200, {"ok": telegram_send("🛡 secaudit 測試訊息：Telegram 警示設定成功。")})
            return self._send(404, {"error": "not found"})

    return H


def serve(engine: Engine, port: int):
    token = get_token()
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine, token, port))
    print("[secaudit] Web UI：http://127.0.0.1:%d/?t=%s" % (port, token), flush=True)
    srv.serve_forever()
