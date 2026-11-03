#!/usr/bin/env python3
"""secaudit：Mac 安全檢查與變動監控。

  python3 audit.py daemon            常駐：排程掃描 + Telegram 警示 + Web UI（PM2 用這個）
  python3 audit.py serve             只開 Web UI
  python3 audit.py scan [--quick] [--path DIR ...] [--offline] [--notify]
  python3 audit.py url               印出 Web UI 網址

加上 --op-env .env.tpl 時，會用 1Password CLI（op inject）把機密讀進記憶體中的環境變數，
不會在磁碟上產生 .env 檔。
"""
import argparse
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_dotenv(path: str):
    """讀取專案目錄的 .env（可由 1Password `op inject` 等工具暫時產生）。不覆蓋已存在的環境變數。"""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return 0
    n = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.replace("export ", "").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k and k not in os.environ:
            os.environ[k] = v
            n += 1
    return n


def _op_inject(tpl: str):
    """回傳 (成功與否, 輸出或錯誤訊息)。"""
    try:
        r = subprocess.run(["op", "inject", "-i", tpl], capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, type(e).__name__
    return (r.returncode == 0), (r.stdout if r.returncode == 0 else r.stderr.strip()[:200])


def _apply_env(text: str) -> int:
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.replace("export ", "").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ[k] = v
        n += 1
    return n


def _ask_unlock(attempt: int, wait_min: int) -> bool:
    """跳出 macOS 對話框提醒授權。回傳 True = 使用者按「立即授權」。10 分鐘沒回應自動關閉。"""
    msg = ("secaudit 安全監控需要 1Password 授權才能開始運作（第 %d 次提醒）。\n\n"
           "目前「沒有」在監控你的電腦。\n\n"
           "按「立即授權」後，請在 1Password 視窗用 Touch ID 解鎖。\n"
           "按「稍後」會在 %d 分鐘後再提醒。" % (attempt, wait_min))
    script = ('display dialog "%s" with title "secaudit：需要 1Password 授權" '
              'buttons {"稍後", "立即授權"} default button "立即授權" with icon caution giving up after 600'
              % msg.replace('"', '\\"'))
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=660)
        return "立即授權" in r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def load_op_env(tpl: str, wait: bool = False):
    """wait=True（常駐模式）：授權失敗不結束，跳出提醒並定期重試，直到成功。"""
    attempt = 0
    backoff = [5, 10, 15, 30]   # 分鐘；之後固定 30 分鐘
    while True:
        ok, out = _op_inject(tpl)
        if ok:
            n = _apply_env(out)
            print("[secaudit] 已從 1Password 載入 %d 個環境變數%s" % (n, "（第 %d 次嘗試）" % (attempt + 1) if attempt else ""), flush=True)
            if attempt:
                os.environ["SECAUDIT_UNLOCK_DELAY"] = str(attempt)
            return
        if not wait:
            sys.exit("❌ 1Password 讀取失敗（可能是 1Password 尚未解鎖）：%s" % out)
        wait_min = backoff[min(attempt, len(backoff) - 1)]
        attempt += 1
        print("[secaudit] 1Password 授權失敗（第 %d 次）：%s → 跳出提醒，%d 分鐘後重試" % (attempt, out[:120], wait_min), flush=True)
        if _ask_unlock(attempt, wait_min):
            continue                  # 使用者按了「立即授權」，馬上重試
        time.sleep(wait_min * 60)


def main():
    ap = argparse.ArgumentParser(description="Mac 安全檢查與變動監控")
    ap.add_argument("--op-env", help="1Password 範本檔（例如 .env.tpl）")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("daemon")
    sub.add_parser("serve")
    sub.add_parser("url")
    sub.add_parser("test-notify", help="測試 Telegram 與 Ollama 設定")
    np_ = sub.add_parser("notify", help="透過執行中的常駐程式發 Telegram（不需要 1Password）")
    np_.add_argument("text")
    sp = sub.add_parser("scan")
    sp.add_argument("--quick", action="store_true", help="只做固定位置檢查，不遍歷資料夾")
    sp.add_argument("--path", action="append", default=[], help="額外加入的掃描資料夾（可重複）")
    sp.add_argument("--no-home", action="store_true", help="不掃家目錄")
    sp.add_argument("--offline", action="store_true", help="不查 CVE / 版本資料庫")
    sp.add_argument("--notify", action="store_true", help="有變動時發 Telegram")
    args = ap.parse_args()

    if args.op_env:
        load_op_env(args.op_env, wait=(args.cmd == "daemon"))
    else:
        load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

    from secaudit.app import Engine, load_config, save_config
    from secaudit.web import get_token, serve

    cfg = load_config()
    if args.cmd == "notify":
        import json
        import urllib.request
        tok = get_token()
        req = urllib.request.Request("http://127.0.0.1:%d/api/notify" % cfg["web_port"], method="POST",
                                     data=json.dumps({"text": args.text}).encode(),
                                     headers={"Content-Type": "application/json", "X-Secaudit": "1",
                                              "Cookie": "sa=" + tok, "Host": "127.0.0.1:%d" % cfg["web_port"]})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                ok = json.loads(r.read().decode()).get("ok")
        except Exception as e:
            ok = False
            print("常駐程式沒有回應（%s），可能沒有在執行" % type(e).__name__)
        print("Telegram：" + ("✅ 已送出" if ok else "❌ 失敗"))
        sys.exit(0 if ok else 1)
    if args.cmd == "test-notify":
        import json
        import urllib.request
        from secaudit.notify import telegram_send
        have = {k: bool(os.environ.get(k)) for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "OLLAMA_API_KEY")}
        print("環境變數：" + "、".join("%s %s" % (k, "✓" if v else "✗") for k, v in have.items()))
        print("Telegram：" + ("✅ 已送出" if telegram_send("🛡 secaudit 測試訊息：Telegram 警示設定成功。") else "❌ 失敗"))
        from secaudit.notify import test_ollama
        r = test_ollama(cfg.get("ollama_host", "https://ollama.com"), cfg.get("ollama_model"))
        where = "雲端" if r["cloud"] else "本機/區網"
        print("Ollama（%s，%s，%s）：%s" % (where, r["host"], cfg.get("ollama_model"),
              "✅ 模型回覆「%s」（%s 秒）" % (r.get("reply"), r.get("seconds")) if r["ok"] else "❌ " + r.get("error", "")))
    elif args.cmd == "url":
        print("http://127.0.0.1:%d/?t=%s" % (cfg["web_port"], get_token()))
    elif args.cmd == "serve":
        serve(Engine(), cfg["web_port"])
    elif args.cmd == "daemon":
        eng = Engine()
        threading.Thread(target=eng.scheduler, daemon=True).start()
        if cfg.get("watch_enabled", True):
            from secaudit.watch import Watcher
            threading.Thread(target=Watcher(eng, interval=max(3, int(cfg.get("watch_interval_sec", 10)))).run,
                             daemon=True).start()
        serve(eng, cfg["web_port"])
    elif args.cmd == "scan":
        from secaudit.app import load_targets
        targets = load_targets(cfg)
        if args.no_home or args.path:
            saved = cfg.get("targets", [])
            for p in args.path:
                p = os.path.realpath(os.path.expanduser(p))
                if not any(t["path"] == p for t in saved):
                    saved.append({"path": p, "label": os.path.basename(p), "kind": "custom", "enabled": True})
            for t in saved:
                if t.get("kind") == "home":
                    t["enabled"] = not args.no_home
            if args.no_home and not any(t.get("kind") == "home" for t in saved):
                saved.append({"path": os.path.expanduser("~"), "label": "家目錄", "kind": "home", "enabled": False})
            cfg["targets"] = saved
            save_config(cfg)
        eng = Engine()

        def prog(phase, cur):
            sys.stderr.write("\r\033[K%s %s" % (phase, cur[-80:]))
        eng._progress = prog
        name = eng.scan("quick" if args.quick else "full", notify_user=args.notify, online=False if args.offline else None)
        sys.stderr.write("\n")
        if name:
            from secaudit.app import REPORTS
            print("報告：%s/%s.{html,md,json}" % (REPORTS, name))
        else:
            print("掃描失敗：%s" % eng.status.get("last_error"))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
