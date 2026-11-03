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

from .core import HOME, Finding, ScanContext, home_rel, truncate

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


def _collect_sessions():
    """回傳 {服務名稱: [(profile 名稱, 建立, 到期, 最後使用)]}，每個 profile 取最舊的登入 cookie。"""
    out = {}
    sources = []
    for browser, label, p in _chromium_profiles():
        for c in (os.path.join(p, "Network", "Cookies"), os.path.join(p, "Cookies")):
            if os.path.isfile(c):
                sources.append(("chromium", label, c))
                break
    ff = os.path.join(APP_SUPPORT, "Firefox", "Profiles")
    if os.path.isdir(ff):
        for d in sorted(os.listdir(ff)):
            c = os.path.join(ff, d, "cookies.sqlite")
            if os.path.isfile(c):
                sources.append(("firefox", "Firefox「%s」" % d.split(".", 1)[-1], c))
    for kind, label, path in sources:
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
            continue
        per = {}
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
        for s, (c, e, a) in per.items():
            out.setdefault(s, []).append((label, c, e, a))
    return out


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


def check_debug_and_theft(ctx: ScanContext):
    ctx.report(CAT, "遠端除錯與 cookie 外流跡象")
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        ps = ""
    for line in ps.splitlines():
        if re.search(r"--remote-debugging-(?:port|pipe)", line) and re.search(r"Chrome|Chromium|Brave|Edge|Arc|chrome", line):
            m = re.search(r"--remote-debugging-port=(\d+)", line)
            ctx.add(Finding(
                rule="browser-remote-debug", severity="high", category=CAT,
                title="瀏覽器正以遠端除錯模式執行%s" % ("（port %s）" % m.group(1) if m else ""),
                evidence=truncate(line, 160),
                why="開著遠端除錯時，本機任何程式都能透過它讀出所有 cookie 和登入狀態，竊密程式常用這招繞過 cookie 加密。"
                    "如果是你自己在用的 AI 瀏覽器自動化工具（例如 chrome-devtools-mcp），用完請關閉。",
                fix="關閉這個瀏覽器程序；若不是你啟動的，檢查開機自動執行項目和最近安裝的程式。"))
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
