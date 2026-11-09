"""G. 瀏覽器 session 與擴充功能檢查。

只讀 cookie 的「網域、名稱、建立/到期/最後使用時間」，絕不讀 value / encrypted_value，也不解密。
"""
import json
import os
import re
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request

from .core import HOME, Finding, ScanContext, home_rel, safe_env, truncate

CAT = "瀏覽器"
APP_SUPPORT = os.path.join(HOME, "Library", "Application Support")
CHROMIUM_BROWSERS = [
    ("Chrome", "Google/Chrome"), ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "Microsoft Edge"),
    ("Arc", "Arc/User Data"), ("Chromium", "Chromium"), ("Vivaldi", "Vivaldi"),
]

# (服務, 網域結尾, 代表登入狀態的 cookie 名稱, 檢查/登出其他裝置的網址)
SENSITIVE = [
    ("Google 帳號", ("google.com",), {"SID", "__Secure-1PSID", "__Secure-3PSID"}, "https://myaccount.google.com/device-activity"),
    ("GitHub", ("github.com",), {"user_session", "__Host-user_session_same_site"}, "https://github.com/settings/sessions"),
    ("Claude", ("claude.ai",), {"sessionKey"}, "https://claude.ai/settings/account"),
    ("ChatGPT / OpenAI", ("chatgpt.com", "openai.com"), {"__Secure-next-auth.session-token", "__Secure-auth-session"}, "https://chatgpt.com/#settings/Security"),
    ("AWS Console", ("aws.amazon.com", "signin.aws.amazon.com"), {"aws-userInfo", "aws-creds", "noflush_awsccs_sid"}, "https://console.aws.amazon.com/"),
    ("Cloudflare", ("dash.cloudflare.com", "cloudflare.com"), {"CF_Authorization", "vses2"}, "https://dash.cloudflare.com/profile/sessions"),
    ("Vercel", ("vercel.com",), {"authorization"}, "https://vercel.com/account/security"),
    ("Supabase", ("supabase.com",), None, "https://supabase.com/dashboard/account/security"),
    ("npm", ("npmjs.com",), {"__session"}, "https://www.npmjs.com/settings/~/tokens"),
    ("Slack", ("slack.com",), {"d"}, "https://slack.com/account/sessions"),
    ("Notion", ("notion.so",), {"token_v2"}, "https://www.notion.so/profile/sessions"),
    ("X / Twitter", ("x.com", "twitter.com"), {"auth_token"}, "https://x.com/settings/sessions"),
    ("Facebook / Meta", ("facebook.com",), {"xs", "c_user"}, "https://accountscenter.facebook.com/password_and_security/login_activity"),
    ("Discord", ("discord.com",), None, "https://discord.com/channels/@me"),
    ("1Password", ("1password.com",), None, "https://my.1password.com/profile"),
    ("Stripe", ("stripe.com",), None, "https://dashboard.stripe.com/settings/security"),
    ("Binance", ("binance.com",), None, "https://www.binance.com/en/my/security/device-management"),
    ("Apple ID", ("apple.com", "icloud.com"), None, "https://account.apple.com/account/manage"),
    ("Microsoft 帳號", ("live.com", "microsoftonline.com", "microsoft.com"), {"ESTSAUTH", "ESTSAUTHPERSISTENT"}, "https://mysignins.microsoft.com/"),
]

DAY = 86400
CHROME_EPOCH = 11644473600


def _chrome_ts(v):
    return v / 1e6 - CHROME_EPOCH if v else 0


def _ro_connect(path):
    # immutable=1：不加鎖、不寫入，瀏覽器開著也能讀
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(path), uri=True, timeout=5)


def _service_for(host):
    h = host.lstrip(".").lower()
    for svc in SENSITIVE:
        if any(h == d or h.endswith("." + d) for d in svc[1]):
            return svc
    return None


def _chromium_profiles():
    for browser, rel in CHROMIUM_BROWSERS:
        root = os.path.join(APP_SUPPORT, rel)
        if not os.path.isdir(root):
            continue
        names = {}
        try:
            with open(os.path.join(root, "Local State"), encoding="utf-8") as fh:
                cache = json.load(fh).get("profile", {}).get("info_cache", {})
            for d, info in cache.items():
                n = info.get("name") or d
                if re.match(r"^(Person|使用者|Profile) ?\d*$", n) and info.get("user_name"):
                    n = info["user_name"]
                names[d] = n
        except (OSError, ValueError):
            pass
        for d in sorted(os.listdir(root)):
            p = os.path.join(root, d)
            if d == "Default" or d.startswith("Profile "):
                yield browser, "%s「%s」" % (browser, names.get(d, d)), p


def _cookie_sources():
    """(種類, 瀏覽器, profile 名稱, profile 資料夾, cookie 資料庫路徑)"""
    for browser, label, p in _chromium_profiles():
        for c in (os.path.join(p, "Network", "Cookies"), os.path.join(p, "Cookies")):
            if os.path.isfile(c):
                yield "chromium", browser, label, p, c
                break
    ff = os.path.join(APP_SUPPORT, "Firefox", "Profiles")
    if os.path.isdir(ff):
        for d in sorted(os.listdir(ff)):
            c = os.path.join(ff, d, "cookies.sqlite")
            if os.path.isfile(c):
                yield "firefox", "Firefox", "Firefox「%s」" % d.split(".", 1)[-1], os.path.join(ff, d), c


def session_items():
    """每個 (profile, 敏感服務) 一筆：{kind, browser, label, profile, cookies, svc, url, domains, created, expires, accessed}。
    profile 取該服務最舊的登入 cookie 當「登入多久」，最後使用取最新的。"""
    by = {s[0]: s for s in SENSITIVE}
    for kind, browser, label, pdir, path in _cookie_sources():
        for svc, (c, e, a) in _profile_sessions(kind, path).items():
            yield {"kind": kind, "browser": browser, "label": label, "profile": pdir, "cookies": path, "svc": svc,
                   "url": by[svc][3], "domains": by[svc][1], "created": c, "expires": e, "accessed": a}


def _collect_sessions():
    """回傳 {服務名稱: [(profile 名稱, 建立, 到期, 最後使用)]}，每個 profile 取最舊的登入 cookie。"""
    out = {}
    for it in session_items():
        out.setdefault(it["svc"], []).append((it["label"], it["created"], it["expires"], it["accessed"]))
    return out


def _profile_sessions(kind, path):
    """一個 cookie 資料庫裡各敏感服務的 [最舊建立, 到期, 最新使用]。"""
    per = {}
    try:
        con = _ro_connect(path)
        if kind == "chromium":
            rows = con.execute("SELECT host_key, name, creation_utc, expires_utc, last_access_utc FROM cookies").fetchall()
            rows = [(h, n, _chrome_ts(c), _chrome_ts(e), _chrome_ts(a)) for h, n, c, e, a in rows]
        else:
            rows = con.execute("SELECT host, name, creationTime, expiry, lastAccessed FROM moz_cookies").fetchall()
            rows = [(h, n, c / 1e6, e / 1000 if e > 1e11 else e, a / 1e6) for h, n, c, e, a in rows]
        con.close()
    except sqlite3.Error:
        return per
    for host, name, created, expires, accessed in rows:
        svc = _service_for(host)
        if not svc:
            continue
        auth_names = svc[2]
        if auth_names is not None and name not in auth_names:
            continue
        cur = per.get(svc[0])
        if cur is None or created < cur[0]:
            per[svc[0]] = [created, expires, accessed]
        else:
            cur[2] = max(cur[2], accessed)
    return per


def check_sessions(ctx: ScanContext):
    ctx.report(CAT, "瀏覽器登入 session")
    now = time.time()
    sessions = _collect_sessions()
    review = {s[0]: s[3] for s in SENSITIVE}
    for svc, items in sorted(sessions.items()):
        items.sort(key=lambda x: x[1])
        ages = [(now - c) / DAY for _, c, _, _ in items]
        idle = [(lbl, (now - a) / DAY) for lbl, _, _, a in items if a]
        long_left = [(lbl, (e - now) / DAY) for lbl, _, e, _ in items if e and e - now > 365 * DAY]
        stale = [(l, d) for l, d in idle if d > 90]
        oldest = max(ages) if ages else 0
        ctx.inv("瀏覽器登入 session", svc, "%d 個 profile" % len(items))
        sev = "medium" if oldest > 365 else "low" if oldest > 180 or stale else "info"
        lines = ["%s：已登入 %d 天、上次使用 %d 天前%s" % (
            lbl, (now - c) / DAY, (now - a) / DAY if a else -1,
            "、cookie 還有 %d 天才到期" % ((e - now) / DAY) if e and e > now else "") for lbl, c, e, a in items[:12]]
        if len(items) > 12:
            lines.append("…另有 %d 個 profile" % (len(items) - 12))
        reasons = []
        if oldest > 180:
            reasons.append("最久的登入狀態已持續 %d 天" % oldest)
        if stale:
            reasons.append("%d 個 profile 超過 90 天沒用，但仍保持登入" % len(stale))
        if long_left:
            reasons.append("%d 個 session cookie 有效期超過一年" % len(long_left))
        ctx.add(Finding(
            rule="browser-session", severity=sev, category=CAT,
            title="%s：%d 個瀏覽器 profile 保持登入%s" % (svc, len(items), "（%s）" % "；".join(reasons) if reasons else ""),
            detail=" ／ ".join(lines),
            why="Session cookie 等於「免密碼、免 2FA 的通行證」。竊密程式（infostealer）偷到後可以直接登入，"
                "而且不會觸發新裝置通知。登入越久、閒置越久的 session，被盜時越難察覺。",
            fix="到 %s 檢查有沒有不認得的裝置或地點，並登出其他所有 session；用不到的 profile 直接登出或刪除。" % review.get(svc, "該服務的安全性設定頁")))


RISKY_PERMS = {"cookies", "debugger", "nativeMessaging", "proxy", "webRequestBlocking", "declarativeNetRequestWithHostAccess",
               "clipboardRead", "history", "management", "privacy"}
ALL_HOSTS = re.compile(r"^(?:<all_urls>|\*://\*/\*|https?://\*/\*)$")


def _ext_name(ext_dir, manifest):
    n = manifest.get("name", "")
    m = re.match(r"__MSG_(.+)__", n)
    if m:
        loc = manifest.get("default_locale", "en")
        for l in (loc, "en", "en_US", "zh_TW"):
            try:
                with open(os.path.join(ext_dir, "_locales", l, "messages.json"), encoding="utf-8-sig") as fh:
                    msgs = json.load(fh)
                for k, v in msgs.items():
                    if k.lower() == m.group(1).lower():
                        return v.get("message", n)
            except (OSError, ValueError):
                continue
    return n


def check_extensions(ctx: ScanContext):
    ctx.report(CAT, "瀏覽器擴充功能")
    exts = {}
    for browser, label, p in _chromium_profiles():
        base = os.path.join(p, "Extensions")
        if not os.path.isdir(base):
            continue
        for eid in os.listdir(base):
            vdir = os.path.join(base, eid)
            if not os.path.isdir(vdir):
                continue
            vers = sorted(os.listdir(vdir))
            if not vers:
                continue
            d = os.path.join(vdir, vers[-1])
            try:
                with open(os.path.join(d, "manifest.json"), encoding="utf-8-sig") as fh:
                    mf = json.load(fh)
            except (OSError, ValueError):
                continue
            perms = [str(x) for x in (mf.get("permissions") or []) + (mf.get("optional_permissions") or [])
                     if isinstance(x, str)]
            hosts = [str(x) for x in (mf.get("host_permissions") or [])] + [x for x in perms if "://" in x or x == "<all_urls>"]
            for cs in mf.get("content_scripts") or []:
                hosts += [str(x) for x in cs.get("matches") or []]
            e = exts.setdefault((browser, eid), {"name": _ext_name(d, mf), "ver": mf.get("version", ""), "profiles": [],
                                                 "perms": set(), "all_hosts": False, "store": "update_url" in mf})
            e["profiles"].append(label)
            e["perms"].update(x for x in perms if x in RISKY_PERMS)
            e["all_hosts"] = e["all_hosts"] or any(ALL_HOSTS.match(h) for h in hosts)
    for (browser, eid), e in sorted(exts.items(), key=lambda x: x[1]["name"].lower()):
        ctx.inv("瀏覽器擴充功能", "%s ▸ %s（%s）" % (browser, e["name"], eid),
                "v%s | %s | %d 個 profile" % (e["ver"], ",".join(sorted(e["perms"])) + (",所有網站" if e["all_hosts"] else ""), len(e["profiles"])))
        risky = sorted(e["perms"])
        if e["all_hosts"] and ({"cookies", "debugger", "nativeMessaging", "webRequestBlocking", "proxy"} & e["perms"]):
            sev = "medium"
        elif e["all_hosts"] or risky:
            sev = "low"
        else:
            sev = "info"
        if not e["store"]:
            sev = "medium" if sev != "info" else "low"
        ctx.add(Finding(
            rule="browser-ext", severity=sev, category=CAT,
            title="%s 擴充功能「%s」%s" % (browser, truncate(e["name"], 60), "（非商店安裝）" if not e["store"] else ""),
            detail="權限：%s%s ／ 安裝在 %d 個 profile：%s" % (
                "、".join(risky) or "一般", "、可讀取所有網站" if e["all_hosts"] else "", len(e["profiles"]),
                "、".join(e["profiles"][:5]) + ("…" if len(e["profiles"]) > 5 else "")),
            evidence="id=%s v%s" % (eid, e["ver"]),
            why="能讀所有網站又有 cookies / debugger / nativeMessaging 權限的擴充功能，可以直接把登入 session 傳出去。"
                "擴充功能被轉賣或開發者帳號被盜後推送惡意更新，是近年常見的攻擊手法。",
            fix="不認得或用不到就移除；需要保留的，在 chrome://extensions 把「網站存取權」改成「點擊時」。"))


AUTOMATION_HINTS = [
    (r"chrome-devtools-mcp", "chrome-devtools-mcp（AI 助理的瀏覽器工具）"),
    (r"playwright|ms-playwright|--disable-field-trial-config", "Playwright"),
    (r"puppeteer", "Puppeteer"),
    (r"selenium|chromedriver", "Selenium / ChromeDriver"),
    (r"\bclaude\b|claude-code|@anthropic-ai", "Claude Code"),
    (r"\bcursor\b|Cursor\.app", "Cursor"),
    (r"\bcodex\b", "Codex"),
    (r"\bmcp\b|mcp-server|modelcontextprotocol", "MCP 伺服器"),
    (r"browser-use|browserbase|stagehand", "瀏覽器代理工具"),
]


# 執行檔本身是瀏覽器（排除指令列裡剛好帶著瀏覽器指令的 shell / node 程序）
BROWSER_EXE = re.compile(r"^(?:Google Chrome(?: for Testing| Canary)?|Chromium|Brave Browser|Microsoft Edge|Arc|Vivaldi"
                         r"|chrome|chromium|chrome-headless-shell|headless_shell)$")


def _ps_info(pid):
    """回傳 {ppid, user, start, etime, exe, cmd}；程序不存在回傳 None。"""
    try:
        out = subprocess.run(["ps", "-o", "ppid=,user=,lstart=,etime=,comm=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5, env=safe_env()).stdout.strip()
        cmd = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=5,
                             env=safe_env()).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    t = out.split(None, 8)
    if len(t) < 9:
        return None
    try:
        start = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(" ".join(t[2:7]), "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        start = " ".join(t[2:7])
    return {"ppid": int(t[0]), "user": t[1], "start": start, "etime": t[7], "exe": t[8], "cmd": cmd}


def _proc_label(info):
    exe = info["exe"]
    m = re.search(r"([^/]+)\.app/", exe)
    name = m.group(1) if m else os.path.basename(exe)
    hints = [h for rx, h in AUTOMATION_HINTS if re.search(rx, info["cmd"], re.I)]
    return name + ("（%s）" % "、".join(dict.fromkeys(hints)) if hints else "")


def _etime_zh(et):
    """ps 的 etime（[[天-]時:]分:秒）→ 中文。"""
    m = re.match(r"(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$", et)
    if not m:
        return et
    d, h, mi = int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3))
    return ("%d 天 " % d if d else "") + ("%d 小時 " % h if h else "") + "%d 分鐘" % mi


def _lsof(args):
    try:
        return subprocess.run(["lsof", "-nP"] + args, capture_output=True, text=True, timeout=10, env=safe_env()).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _debug_detail(pid, line):
    """整理遠端除錯瀏覽器的時間軸與細節，回傳 (細節文字, 是否為暫時設定檔, 是否對外開放)。"""
    rows = []
    info = _ps_info(pid)
    if info:
        rows.append("啟動時間：%s（已執行 %s，執行身分 %s）" % (info["start"], _etime_zh(info["etime"]), info["user"]))
    m = re.search(r"--user-data-dir=(\S+)", line)
    udd = m.group(1) if m else ""
    default_dirs = [os.path.join(APP_SUPPORT, d) for _, d in CHROMIUM_BROWSERS]
    temp_profile = bool(udd) and os.path.realpath(udd) not in [os.path.realpath(d) for d in default_dirs]
    if udd:
        rows.append("設定檔：%s%s" % (home_rel(udd), "（暫時 / 獨立的設定檔，不是你平常用的瀏覽器資料）" if temp_profile
                                      else "（⚠️ 你平常用的瀏覽器資料，裡面有你的登入狀態）"))
        try:
            rows.append("開始遠端除錯：%s（DevToolsActivePort 檔案的時間）" % time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(os.stat(os.path.join(udd, "DevToolsActivePort")).st_mtime)))
        except OSError:
            pass
    else:
        rows.append("設定檔：沒有指定 --user-data-dir，使用的是你平常的瀏覽器資料（⚠️ 裡面有你的登入狀態）")
    if "--headless" in line:
        rows.append("模式：無視窗（headless），畫面上看不到這個瀏覽器")
    # 由誰啟動：往上追父程序
    chain, p, seen, kinds, cwds = [], info["ppid"] if info else 0, set(), set(), []
    while p > 1 and p not in seen and len(chain) < 8:
        seen.add(p)
        pi = _ps_info(p)
        if not pi:
            break
        chain.append("%s［pid %d，%s 啟動］" % (_proc_label(pi), p, pi["start"]))
        kinds.update(h for rx, h in AUTOMATION_HINTS if re.search(rx, pi["cmd"], re.I))
        name = os.path.basename(pi["exe"])
        if re.search(r"(?:Warp|Terminal|iTerm2?|Code|Cursor|Ghostty|kitty|Alacritty|WezTerm)\.app/", pi["exe"]) or name in ("sshd", "tmux"):
            kinds.add("終端機")
        if pi["exe"].startswith("/Users/") or re.match(r"^-?(?:zsh|bash|sh|fish)$", name):
            kinds.add("shell")
        # 工作目錄：測試 / 腳本程式在哪個專案資料夾執行（最多列 2 個不同的）
        if len(cwds) < 2 and re.match(r"^(?:node|npm|npx|pnpm|yarn|bun|deno|[Pp]ython[\d.]*|claude|go|cargo|ruby)$", name):
            w = re.search(r"^n(/.+)$", _lsof(["-a", "-p", str(p), "-d", "cwd", "-Fn"]), re.M)
            if w and w.group(1) not in [c[0] for c in cwds]:
                cwds.append((home_rel(w.group(1)), "%s［pid %d］" % (name, p)))
        p = pi["ppid"]
    if chain:
        rows.append("由誰啟動（由近到遠）：" + " ← ".join(chain))
    for wp, wlabel in cwds:
        rows.append("在哪裡執行：%s %s" % (wlabel, wp))
    exposed = False
    port = re.search(r"--remote-debugging-port=(\d+)", line)
    if port and port.group(1) != "0":
        port = port.group(1)
        listen = _lsof(["-a", "-p", str(pid), "-iTCP:%s" % port, "-sTCP:LISTEN"])
        addrs = sorted(set(re.findall(r"TCP (\S+):%s \(LISTEN\)" % port, listen)))
        if addrs:
            exposed = any(a in ("*", "0.0.0.0", "[::]") for a in addrs)
            rows.append("監聽位址：%s%s" % ("、".join("%s:%s" % (a, port) for a in addrs),
                                         "（⚠️ 對整個網路開放，同網段的其他電腦也能連進來）" if exposed else "（只限本機）"))
        clients = {}
        for l in _lsof(["-iTCP:%s" % port, "-sTCP:ESTABLISHED"]).splitlines()[1:]:
            c = l.split()
            if len(c) > 1 and c[1].isdigit() and int(c[1]) != pid:
                clients[int(c[1])] = True
        if clients:
            labels = []
            for cp in sorted(clients)[:5]:
                ci = _ps_info(cp)
                if ci:
                    labels.append("%s［pid %d，%s 啟動］" % (_proc_label(ci), cp, ci["start"]))
            rows.append("目前正在控制它的程式：" + "、".join(labels))
        else:
            rows.append("目前正在控制它的程式：掃描當下沒有程式連線")
        try:
            with urllib.request.urlopen("http://127.0.0.1:%s/json/list" % port, timeout=3) as r:
                tabs = json.loads(r.read(200000).decode("utf-8", "replace"))
            pages = [t for t in tabs if t.get("type") == "page"]
            if pages:
                rows.append("開著的分頁（%d 個，網址已去掉參數）：" % len(pages))
                for t in pages[:10]:
                    u = urllib.parse.urlsplit(t.get("url", ""))
                    rows.append("  • %s — %s" % (truncate(t.get("title", "") or "（無標題）", 60),
                                                 truncate(urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", "")), 100)))
            else:
                rows.append("開著的分頁：沒有")
        except (OSError, ValueError):
            pass
    elif "--remote-debugging-pipe" in line:
        rows.append("連線方式：pipe（只有啟動它的程式能控制，其他程式連不進來）")
    # 自動判斷：從你的終端機 / AI 助理啟動、用暫時設定檔、外部連不進來 → 幾乎可以確定是你自己的自動化工具
    tools = sorted(kinds - {"shell", "終端機"})
    own = temp_profile and not exposed and bool(kinds & {"終端機", "Claude Code", "Cursor", "Codex"}) and \
        ("--remote-debugging-pipe" in line or not port)
    if own:
        rows.append("判斷：很可能是你自己的操作。它是從你的%s啟動（%s），用的是用完即丟的暫時設定檔，"
                    "其他程式也連不進來。對照上面的時間和資料夾，確認是不是你當時在跑的測試或 AI 助理的工作。"
                    % ("終端機" if "終端機" in kinds else "AI 助理", "、".join(tools) or "shell"))
    elif not kinds & {"終端機", "shell", "Claude Code", "Cursor", "Codex"}:
        rows.append("判斷：⚠️ 往上追不到你的終端機或 AI 助理，啟動來源不明（可能是開機自動執行的程式），請特別留意。")
    return "\n".join(rows), temp_profile, exposed, own


def check_debug_and_theft(ctx: ScanContext):
    ctx.report(CAT, "遠端除錯與 cookie 外流跡象")
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, timeout=10, env=safe_env()).stdout
    except (OSError, subprocess.TimeoutExpired):
        ps = ""
    exes = {}
    try:
        for l in subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=10, env=safe_env()).stdout.splitlines():
            t = l.split(None, 1)
            if len(t) == 2:
                exes[t[0]] = t[1].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    for line in ps.splitlines():
        if re.search(r"--remote-debugging-(?:port|pipe)", line) and BROWSER_EXE.match(os.path.basename(exes.get(line.split(None, 1)[0], ""))):
            if "--type=" in line:
                continue        # 分頁 / GPU 等子程序，只看主程序
            pid = int(line.split(None, 1)[0])
            m = re.search(r"--remote-debugging-port=(\d+)", line)
            detail, temp_profile, exposed, own = _debug_detail(pid, line)
            pipe_only = not m and "--remote-debugging-pipe" in line
            low_risk = temp_profile and not exposed
            # 確定是自己的測試 / AI 助理 → 只記在報告裡（資訊），不推播；每次跑測試都會出現，推播只是噪音
            sev = "info" if own else "medium" if low_risk or pipe_only and temp_profile else "high"
            ctx.add(Finding(
                rule="browser-remote-debug", severity=sev,
                category=CAT,
                title="瀏覽器正以遠端除錯模式執行%s" % ("（port %s）" % m.group(1) if m else "（pipe）"),
                detail=detail, evidence=truncate(line, 160),
                why="開著遠端除錯時，本機任何程式都能透過它讀出這個瀏覽器設定檔裡的所有 cookie 和登入狀態，竊密程式常用這招繞過 cookie 加密。"
                    + ("這次用的是獨立的暫時設定檔，你平常瀏覽器的登入狀態不在裡面，但在它裡面登入的帳號仍可能被讀走。" if temp_profile else "")
                    + "如果是你自己在用的 AI 瀏覽器自動化工具（例如 chrome-devtools-mcp、Playwright），用完請關閉。",
                fix="對照「啟動時間」和「由誰啟動」，回想當時是不是在用 AI 助理、跑自動化測試或爬蟲；"
                    "是的話用完關閉即可。若時間點你不在電腦前、或啟動它的程式你不認得，"
                    "先結束這個瀏覽器程序，再檢查開機自動執行項目和最近安裝的程式。"))
    names = {"Cookies", "Login Data", "Cookies.binarycookies", "cookies.sqlite", "key4.db", "logins.json", "Local State", "Web Data"}
    for base in ("/tmp", "/private/var/tmp", "/Users/Shared", os.path.join(HOME, "Downloads"), os.path.join(HOME, "Desktop")):
        for dp, dns, fns in os.walk(base):
            if dp.count(os.sep) - base.count(os.sep) >= 2:
                dns[:] = []
            for fn in fns:
                if fn in names or re.match(r"(?i)^(cookies|passwords?|logins?)[_ -]?.*\.(txt|json|csv|db)$", fn):
                    p = os.path.join(dp, fn)
                    ctx.add(Finding(
                        rule="browser-data-copy", severity="high", category=CAT,
                        title="瀏覽器憑證資料的副本出現在不該出現的位置", path=home_rel(p),
                        why="竊密程式通常會先把 Cookies / Login Data 複製到暫存或共享資料夾，再打包外傳。",
                        fix="確認這個檔案的來源；不是你匯出的，請把機器當作已被入侵處理：登出所有 session、更換密碼、檢查開機自動執行項目。"))
    safari = os.path.join(HOME, "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies", "Cookies.binarycookies")
    try:
        with open(safari, "rb") as fh:
            fh.read(4)
    except PermissionError:
        ctx.add(Finding(rule="browser-safari-tcc", severity="info", category=CAT, title="Safari cookie 需要「完整磁碟取用權限」才能檢查",
                        fix="系統設定 → 隱私權與安全性 → 完整磁碟取用權限，加入執行本工具的終端機或 PM2 的 node。"))
    except OSError:
        pass


def check_browsers(ctx: ScanContext):
    check_sessions(ctx)
    check_extensions(ctx)
    check_debug_and_theft(ctx)


def profile_last_used(pdir):
    """profile 上次被開啟的時間：Local State 的 active_time 與歷史紀錄檔修改時間取較新的（估計值）。"""
    t = 0
    try:
        with open(os.path.join(os.path.dirname(pdir), "Local State"), encoding="utf-8") as fh:
            t = (json.load(fh).get("profile", {}).get("info_cache", {}).get(os.path.basename(pdir)) or {}).get("active_time") or 0
    except (OSError, ValueError):
        pass
    try:
        t = max(t, os.path.getmtime(os.path.join(pdir, "History")))
    except OSError:
        pass
    return t
