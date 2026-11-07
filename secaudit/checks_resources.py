"""CPU / 記憶體異常與新出現的常駐程式。

背景執行緒每分鐘取樣一次（ps + sysctl，不讀檔案內容），發現事件就記下來並觸發一次快速掃描，
交給既有的比對 / AI 摘要 / Telegram 流程。事件保留 24 小時，期間會出現在每份報告裡。

偵測項目：
- 單一程式持續吃 CPU（10 分鐘每次取樣都 ≥ 80%，例如挖礦程式）
- 使用者閒置時整台電腦 CPU 偏高（10 分鐘平均 ≥ 50%）
- 記憶體壓力進入警告 / 危險、swap 短時間暴增、單一程式記憶體暴增
- 新出現的常駐程式：執行超過 5 分鐘、以前沒看過的執行檔（Apple 系統程式除外）；
  依簽章、位置、由誰啟動判斷風險
"""
import ctypes
import json
import os
import re
import subprocess
import threading
import time

from .core import HOME, Finding, ScanContext, home_rel, safe_env

CAT = "系統資源與常駐程式"
SAMPLE_SEC = 60
WINDOW = 10                 # 取樣次數（= 分鐘）
PROC_CPU = 80.0             # 單一程式 %CPU（100 = 一個核心跑滿）
IDLE_CPU = 50.0             # 閒置時整台電腦 CPU %
IDLE_MIN = 10
RESIDENT_SEC = 300          # 執行超過 5 分鐘才算常駐
EVENT_TTL = 86400
REPEAT_SEC = 6 * 3600       # 同一個程式的同一種事件，6 小時內不重複

# 看起來可疑的位置（暫存、共享、隱藏資料夾）
ODD_LOC = re.compile(r"^(?:/tmp/|/private/tmp/|/private/var/tmp/|/var/tmp/|/private/var/folders/|/var/folders/|/Users/Shared/"
                     r"|%s/(?:Library/(?!Application Support/|Caches/ms-playwright/)[^/]*|\.[^/]+/(?!versions/|bin/))|/Library/Caches/)" % re.escape(HOME))
# Apple 簽章但常被拿來長時間跑惡意腳本的工具：一樣要列入常駐程式清單
LOLBIN = re.compile(r"/(?:osascript|python[\d.]*|perl[\d.]*|ruby|php|nc|ncat|socat|curl|wget|bash|sh|zsh|screen|tclsh)$")
TERMINAL = re.compile(r"(?:Warp|Terminal|iTerm2?|Visual Studio Code|Code|Cursor|Ghostty|kitty|Alacritty|WezTerm)\.app/")
AI_TOOL = re.compile(r"(?:^|/)(?:claude|codex|cursor)$|/claude/versions/[^/]+$")

_libproc = None


def _pidpath(pid):
    global _libproc
    try:
        if _libproc is None:
            _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = ctypes.create_string_buffer(4096)
        n = _libproc.proc_pidpath(int(pid), buf, 4096)
        return buf.value.decode("utf-8", "replace") if n > 0 else ""
    except (OSError, ValueError, AttributeError):
        return ""


def _etime_sec(et):
    m = re.match(r"(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$", et.strip())
    if not m:
        return 0
    return int(m.group(1) or 0) * 86400 + int(m.group(2) or 0) * 3600 + int(m.group(3)) * 60 + int(m.group(4))


def snapshot():
    """{pid: {ppid, uid, cpu, rss_mb, age, exe, args}}"""
    env = safe_env()
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,uid=,%cpu=,rss=,etime=,comm="], capture_output=True, text=True,
                             timeout=15, env=env).stdout
        args = subprocess.run(["ps", "-axo", "pid=,args="], capture_output=True, text=True, timeout=15, env=env).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    a = {}
    for l in args.splitlines():
        t = l.strip().split(None, 1)
        if len(t) == 2:
            a[t[0]] = t[1]
    procs = {}
    for l in out.splitlines():
        t = l.split(None, 6)
        if len(t) < 7 or not t[0].isdigit():
            continue
        exe = t[6].strip()
        if not exe.startswith("/"):
            exe = _pidpath(t[0]) or exe
        try:
            procs[int(t[0])] = {"ppid": int(t[1]), "uid": int(t[2]), "cpu": float(t[3]), "rss_mb": int(t[4]) // 1024,
                                "age": _etime_sec(t[5]), "exe": exe, "args": a.get(t[0], exe)[:400]}
        except ValueError:
            continue
    return procs


def system_stats():
    s = {}
    try:
        out = subprocess.run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level", "vm.swapusage", "hw.memsize", "hw.ncpu"],
                             capture_output=True, text=True, timeout=5, env=safe_env()).stdout.splitlines()
        s["pressure"] = int(out[0])            # 1 正常、2 警告、4 危險
        m = re.search(r"used = ([\d.]+)M", out[1])
        s["swap_mb"] = float(m.group(1)) if m else 0.0
        s["mem_mb"] = int(out[2]) // 1048576
        s["ncpu"] = int(out[3])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        pass
    try:
        out = subprocess.run(["ioreg", "-c", "IOHIDSystem"], capture_output=True, text=True, timeout=10, env=safe_env()).stdout
        m = re.search(r'"HIDIdleTime" = (\d+)', out)
        s["idle_min"] = int(m.group(1)) / 1e9 / 60 if m else 0
    except (OSError, subprocess.TimeoutExpired):
        s["idle_min"] = 0
    return s


def norm_key(exe, args=""):
    """執行檔路徑去掉版本號、暫存資料夾亂數，讓更新後的同一個程式不會被當成新程式。"""
    k = exe
    k = re.sub(r"^/private/var/folders/[^/]+/[^/]+/[TC]/", "$TMPDIR/", k)
    k = re.sub(r"^/var/folders/[^/]+/[^/]+/[TC]/", "$TMPDIR/", k)
    k = re.sub(r"go-build\d+", "go-build*", k)
    k = re.sub(r"(?<=[/\-_@v])\d+(?:\.\d+)+(?:[-+.][\w.]+)?(?=/|$)", "*", k)   # 版本號
    k = re.sub(r"[0-9a-f]{12,}|\d{5,}", "*", k)                                   # 雜湊 / 亂數
    if LOLBIN.search(exe):
        # 直譯器：加上執行的腳本，否則所有 python 腳本都算同一個
        script = next((x for x in args.split()[1:] if not x.startswith("-")), "")
        if script:
            k += " " + re.sub(r"\d{5,}", "*", script[:200])
    return home_rel(k) if k.startswith(HOME) else k


_sign_cache = {}


def signer(exe):
    """回傳 (類型, 說明)：apple / devid / appstore / adhoc / unsigned / missing / unknown。"""
    if exe in _sign_cache:
        return _sign_cache[exe]
    if not exe.startswith("/"):
        return ("unknown", "無法取得執行檔路徑")
    if not os.path.exists(exe):
        r = ("missing", "⚠️ 執行檔已被刪除（程式還在記憶體裡執行）")
    else:
        try:
            out = subprocess.run(["codesign", "-dv", "--verbose=2", exe], capture_output=True, text=True, timeout=15,
                                 env=safe_env()).stderr
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        auth = re.findall(r"^Authority=(.+)$", out, re.M)
        if "not signed at all" in out:
            r = ("unsigned", "沒有簽章")
        elif "Signature=adhoc" in out:
            r = ("adhoc", "ad-hoc 簽章（自己編譯 / 未經 Apple 公證）")
        elif auth and auth[0] in ("Software Signing", "macOS Software Signing") or "Apple Code Signing" in "".join(auth[:1]):
            r = ("apple", "Apple 系統程式")
        elif auth and auth[0].startswith("Developer ID Application:"):
            r = ("devid", auth[0].split(":", 1)[1].strip())
        elif auth and auth[0].startswith("Apple Mac OS Application Signing"):
            r = ("appstore", "App Store")
        elif auth:
            r = ("other", auth[0])
        else:
            r = ("unknown", "無法讀取簽章")
    _sign_cache[exe] = r
    return r


def ancestry(procs, pid, limit=8):
    """[(pid, 名稱, exe)]，由近到遠。"""
    out, seen, p = [], set(), procs.get(pid, {}).get("ppid", 0)
    while p > 1 and p not in seen and len(out) < limit and p in procs:
        seen.add(p)
        e = procs[p]["exe"]
        m = re.search(r"([^/]+)\.app/", e)
        name = m.group(1) if m else "claude" if "/claude/versions/" in e else os.path.basename(e)
        out.append((p, name, e))
        p = procs[p]["ppid"]
    return out


def _from_user(chain):
    return any(TERMINAL.search(e) or AI_TOOL.search(e) or os.path.basename(e) in ("sshd", "tmux") for _, _, e in chain)


def _chain_text(chain, procs):
    return " ← ".join("%s［pid %d］" % (n, p) for p, n, _ in chain) or "launchd（開機 / 登入時自動執行，或父程式已結束）"


def _top(procs, field, n=5):
    rows = sorted(procs.items(), key=lambda kv: kv[1][field], reverse=True)[:n]
    return "；".join("%s %s（pid %d）" % (os.path.basename(v["exe"]),
                                         "%.0f%% CPU" % v["cpu"] if field == "cpu" else "%.1f GB" % (v["rss_mb"] / 1024), k)
                    for k, v in rows)


class ResourceMonitor:
    def __init__(self, engine, data_dir):
        self.engine = engine
        self.path = os.path.join(data_dir, "resources.json")
        self.lock = threading.Lock()
        self.cpu = {}            # pid -> [cpu 取樣]
        self.rss = {}            # pid -> [rss 取樣]
        self.total = []          # [(整台 CPU%, 閒置分鐘)]
        self.swap = []           # [swap MB]
        self.pressure = []
        self.state = self._load()
        self.dirty = False

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            d = {}
        d.setdefault("known", {})
        d.setdefault("events", [])
        d.setdefault("last_alert", {})
        return d

    def _save(self):
        from .app import _write_private
        with self.lock:
            _write_private(self.path, self.state)

    def _event(self, kind, key, severity, title, detail, path=""):
        tag = "%s|%s" % (kind, key)
        now = time.time()
        if now - self.state["last_alert"].get(tag, 0) < REPEAT_SEC:
            return
        self.state["last_alert"][tag] = now
        with self.lock:
            self.state["events"].append({"ts": now, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "key": key,
                                         "severity": severity, "title": title, "detail": detail, "path": path})
        self.dirty = True
        print("[resources] %s：%s" % (title, key), flush=True)

    # ---------- 常駐程式 ----------
    def check_resident(self, procs):
        known = self.state["known"]
        learning = not self.state.get("baseline")
        for pid, p in procs.items():
            if p["age"] < RESIDENT_SEC or pid <= 1 or not p["exe"].startswith("/"):
                continue        # 取不到路徑的多半是正在結束的程序
            key = norm_key(p["exe"], p["args"])
            if key in known:
                known[key]["last_seen"] = time.strftime("%Y-%m-%d")
                continue
            kind, who = signer(p["exe"])
            if kind == "apple" and not LOLBIN.search(p["exe"]):
                known[key] = {"first_seen": time.strftime("%Y-%m-%d"), "last_seen": time.strftime("%Y-%m-%d"), "signer": "apple"}
                continue
            chain = ancestry(procs, pid)
            known[key] = {"first_seen": time.strftime("%Y-%m-%d %H:%M"), "last_seen": time.strftime("%Y-%m-%d"),
                          "signer": "%s（%s）" % (kind, who), "parent": _chain_text(chain, procs)[:200]}
            self.dirty = True
            if learning:
                continue
            odd = bool(ODD_LOC.search(p["exe"])) or os.path.basename(p["exe"]).startswith(".")
            user = _from_user(chain)
            weak = kind in ("unsigned", "adhoc", "missing", "unknown")
            if kind == "missing" or (weak and odd and not user):
                sev = "high"
            elif user:
                sev = "info"            # 你自己從終端機 / AI 助理開的程式：只記在報告裡，不推播
            elif (weak and not user) or (odd and not user) or (LOLBIN.search(p["exe"]) and not user):
                sev = "medium"
            else:
                sev = "low"
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - p["age"]))
            rows = ["啟動時間：%s（已執行 %d 分鐘，執行身分 uid %d）" % (started, p["age"] // 60, p["uid"]),
                    "執行檔：%s" % home_rel(p["exe"]),
                    "指令：%s" % home_rel(p["args"][:240]),
                    "簽章：%s" % who if kind != "devid" else "簽章：Developer ID（%s）" % who,
                    "由誰啟動（由近到遠）：%s" % _chain_text(chain, procs),
                    "資源：CPU %.0f%%、記憶體 %.0f MB" % (p["cpu"], p["rss_mb"])]
            if odd:
                rows.append("位置：⚠️ 在暫存 / 共享 / 隱藏資料夾裡執行，一般正式安裝的程式不會放這裡")
            rows.append("判斷：%s" % ("從你的終端機或 AI 助理啟動，很可能是你自己在跑的程式" if user else
                                       "⚠️ 不是從你的終端機啟動（開機自動執行或背景服務），請確認你認得它" if sev != "low" else
                                       "有正式簽章的程式，確認是不是你最近安裝或開啟的 App"))
            self._event("resident", key, sev, "新出現的常駐程式：%s" % os.path.basename(key.split(" ")[0]),
                        "\n".join(rows), path=key)
        if learning:
            self.state["baseline"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.dirty = True
            print("[resources] 已建立常駐程式基準：%d 個執行檔" % len(known), flush=True)

    # ---------- CPU / 記憶體 ----------
    def check_usage(self, procs, s):
        for d in (self.cpu, self.rss):
            for pid in list(d):
                if pid not in procs:
                    del d[pid]
        for pid, p in procs.items():
            self.cpu.setdefault(pid, []).append(p["cpu"])
            self.rss.setdefault(pid, []).append(p["rss_mb"])
            self.cpu[pid] = self.cpu[pid][-WINDOW:]
            self.rss[pid] = self.rss[pid][-(WINDOW + 5):]
        ncpu = s.get("ncpu") or os.cpu_count() or 1
        idle = s.get("idle_min", 0)
        self.total = (self.total + [(sum(p["cpu"] for p in procs.values()) / ncpu, idle)])[-WINDOW:]
        self.swap = (self.swap + [s.get("swap_mb", 0)])[-30:]
        self.pressure = (self.pressure + [s.get("pressure", 1)])[-5:]
        ctx_rows = "閒置：%s" % ("使用者已 %d 分鐘沒有操作電腦" % idle if idle >= 1 else "使用者正在使用電腦")

        def base_rows(pid, p):
            chain = ancestry(procs, pid)
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - p["age"]))
            kind, who = signer(p["exe"])
            return chain, ["程式：%s（pid %d，%s 啟動）" % (home_rel(p["exe"]), pid, started),
                           "指令：%s" % home_rel(p["args"][:240]), "簽章：%s" % who,
                           "由誰啟動（由近到遠）：%s" % _chain_text(chain, procs), ctx_rows], kind

        for pid, hist in self.cpu.items():
            if len(hist) >= WINDOW and min(hist) >= PROC_CPU:
                p = procs[pid]
                chain, rows, kind = base_rows(pid, p)
                key = norm_key(p["exe"], p["args"])
                heavy = self.state.setdefault("heavy", {})
                if kind == "apple" and not LOLBIN.search(p["exe"]):
                    continue            # macOS 系統程式（WindowServer、Spotlight 索引…）
                signed = kind in ("devid", "appstore")
                if idle >= IDLE_MIN:
                    sev = "medium" if signed or _from_user(chain) else "high"
                elif kind in ("unsigned", "adhoc", "missing", "unknown") and not _from_user(chain):
                    sev = "medium"
                elif key in heavy:
                    continue            # 你使用電腦時本來就常吃 CPU 的程式（編譯、AI 模型），不再記錄
                else:
                    sev = "info"        # 你正在用電腦、程式有簽章或是你自己開的：只記在報告裡
                heavy[key] = time.strftime("%Y-%m-%d")
                rows.insert(1, "CPU：最近 %d 分鐘每次取樣都 ≥ %.0f%%（平均 %.0f%%，100%% = 一個核心跑滿）" % (
                    WINDOW, PROC_CPU, sum(hist) / len(hist)))
                rows.append("判斷：%s" % ("⚠️ 你沒在用電腦時持續吃 CPU，挖礦程式常見的行為" if idle >= IDLE_MIN else
                                           "你正在使用電腦，可能是編譯、AI 模型或影片處理；不認得這個程式再處理"))
                self._event("cpu", key, sev, "程式持續大量使用 CPU：%s" % os.path.basename(p["exe"]), "\n".join(rows), key)
        if len(self.total) >= WINDOW and min(i for _, i in self.total) >= IDLE_MIN:
            avg = sum(c for c, _ in self.total) / len(self.total)
            if avg >= IDLE_CPU:
                self._event("idle-cpu", "system", "medium", "閒置時整台電腦 CPU 偏高",
                            "\n".join(["CPU：使用者閒置期間，最近 %d 分鐘整台電腦平均 %.0f%%（%d 核）" % (WINDOW, avg, ncpu),
                                       ctx_rows, "最吃 CPU 的程式：%s" % _top(procs, "cpu")]))
        mem = s.get("mem_mb") or 1
        if len(self.pressure) >= 5 and min(self.pressure) >= 2 or self.pressure[-1:] == [4]:
            lvl = "危險" if self.pressure[-1] == 4 else "警告"
            self._event("pressure", "system", "medium", "記憶體壓力%s" % lvl,
                        "\n".join(["記憶體壓力：%s（%s）" % (lvl, "已持續 5 分鐘" if min(self.pressure) >= 2 else "剛進入危險"),
                                   "swap 使用：%.1f GB" % (self.swap[-1] / 1024), ctx_rows,
                                   "最吃記憶體的程式：%s" % _top(procs, "rss_mb")]))
        if len(self.swap) >= 2 and self.swap[-1] - min(self.swap) >= 4096:
            self._event("swap", "system", "low", "swap 短時間暴增",
                        "\n".join(["swap：%d 分鐘內從 %.1f GB 增加到 %.1f GB" % (len(self.swap), min(self.swap) / 1024, self.swap[-1] / 1024),
                                   ctx_rows, "最吃記憶體的程式：%s" % _top(procs, "rss_mb")]))
        for pid, hist in self.rss.items():
            if len(hist) >= 3 and hist[-1] - min(hist) >= max(3072, mem * 0.1) and hist[-1] >= mem * 0.15:
                p = procs[pid]
                chain, rows, kind = base_rows(pid, p)
                rows.insert(1, "記憶體：%d 分鐘內從 %.1f GB 增加到 %.1f GB（整台 %.0f GB）" % (
                    len(hist), min(hist) / 1024, hist[-1] / 1024, mem / 1024))
                self._event("rss", norm_key(p["exe"], p["args"]), "low" if kind in ("apple", "devid", "appstore") else "medium",
                            "程式記憶體暴增：%s" % os.path.basename(p["exe"]), "\n".join(rows), norm_key(p["exe"], p["args"]))

    def tick(self):
        procs = snapshot()
        if not procs:
            return
        s = system_stats()
        before = {id(e) for e in self.state["events"]}
        self.check_usage(procs, s)
        self.check_resident(procs)
        now = time.time()
        with self.lock:
            self.state["events"] = [e for e in self.state["events"] if now - e["ts"] < EVENT_TTL]
            self.state["last_alert"] = {k: v for k, v in self.state["last_alert"].items() if now - v < EVENT_TTL}
        st = self.engine.status.setdefault("resources", {})
        st.update(last=time.strftime("%H:%M:%S"), known=len(self.state["known"]), events=len(self.state["events"]),
                  cpu="%.0f%%" % (self.total[-1][0] if self.total else 0), swap_gb=round(s.get("swap_mb", 0) / 1024, 1),
                  pressure={1: "正常", 2: "警告", 4: "危險"}.get(s.get("pressure"), "?"))
        new = any(id(e) not in before and e["severity"] != "info" for e in self.state["events"])
        if self.dirty:
            self._save()
            self.dirty = False
        return new

    def run(self):
        pending = False
        while True:
            try:
                pending = self.tick() or pending
                if pending and not self.engine.status.get("running"):
                    pending = False
                    titles = [e["title"] for e in self.state["events"][-3:]]
                    self.engine.scan("quick", source="watch", trigger=["資源監控：" + "、".join(titles)], online=False)
            except Exception as e:      # 監控執行緒不能因為單次錯誤停掉
                print("[resources] %s: %s" % (type(e).__name__, e), flush=True)
            time.sleep(SAMPLE_SEC)


def check_resources(ctx: ScanContext):
    """把背景監控記下的事件（24 小時內）放進報告。"""
    from .app import DATA
    try:
        with open(os.path.join(DATA, "resources.json"), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return
    ctx.report(CAT, "")
    now = time.time()
    fix = {"resident": "對照啟動時間和由誰啟動，確認你認得這個程式。不認得：記下路徑後結束它（kill <pid>），"
                       "再檢查 LaunchAgent / LaunchDaemon 有沒有新的自動執行項目。",
           "cpu": "不認得這個程式就先結束它，並檢查它的執行檔位置與開機自動執行項目；認得的話可以忽略。",
           "idle-cpu": "看「最吃 CPU 的程式」裡有沒有你不認得的，再看該程式的詳細資料。",
           "pressure": "關掉不用的 App；如果最吃記憶體的程式你不認得，先查它的來源。",
           "swap": "通常是同時開太多大型程式；如果最吃記憶體的程式你不認得，先查它的來源。",
           "rss": "認得的程式（瀏覽器、AI 模型、編譯）可以忽略；不認得的先結束並查來源。"}
    why = {"resident": "惡意程式通常會在背景長時間執行（回連控制伺服器、挖礦、側錄），新出現又不認得的常駐程式值得確認。",
           "cpu": "長時間吃滿 CPU、尤其在你沒用電腦時，是挖礦程式的典型特徵。",
           "idle-cpu": "你沒在用電腦時 CPU 還很忙，可能有程式在背景做你不知道的事（挖礦、加密檔案、上傳資料）。",
           "pressure": "記憶體不足會讓電腦變慢；也可能是有程式異常佔用記憶體。",
           "swap": "swap 暴增代表有程式突然佔用大量記憶體。",
           "rss": "單一程式記憶體快速成長，可能是記憶體洩漏，也可能是程式在大量讀取 / 打包資料。"}
    for e in d.get("events", []):
        if now - e.get("ts", 0) >= EVENT_TTL:
            continue
        ctx.add(Finding(rule="res-" + e["kind"], severity=e["severity"], category=CAT,
                        title="%s（%s）" % (e["title"], e["time"][5:16]), path=e.get("path", ""),
                        detail=e["detail"], why=why.get(e["kind"], ""), fix=fix.get(e["kind"], "")))
