"""F. 開發環境供應鏈：lockfile 套件漏洞（OSV.dev）、執行環境版本（endoflife.date）、全域套件。

只會送出「套件名稱 + 版本」到 OSV.dev，不會送出程式碼或路徑。
"""
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

from .core import Finding, ScanContext, file_fingerprint, home_rel, read_text, truncate

CAT = "供應鏈與版本"
UA = {"User-Agent": "secaudit/1.0", "Content-Type": "application/json"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
             "poetry.lock", "uv.lock", "Pipfile.lock", "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock"}


def _http_json(url, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=UA, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------- lockfile 解析
def parse_lockfile(path: str):
    """回傳 [(ecosystem, name, version)]。"""
    name = os.path.basename(path)
    text = read_text(path, limit=30 * 1024 * 1024)
    if not text:
        return []
    out = []
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            d = json.loads(text)
            for k, v in (d.get("packages") or {}).items():
                if k and isinstance(v, dict) and v.get("version") and not v.get("link"):
                    out.append(("npm", v.get("name") or k.split("node_modules/")[-1], v["version"]))
            if not d.get("packages"):
                def walk(deps):
                    for n, v in (deps or {}).items():
                        if isinstance(v, dict) and v.get("version"):
                            out.append(("npm", n, v["version"]))
                            walk(v.get("dependencies"))
                walk(d.get("dependencies"))
        elif name == "yarn.lock":
            for m in re.finditer(r'^"?((?:@[^/@\s"]+/)?[^@\s",]+)@[^\n]*:\n(?:\s+.*\n)*?\s+version:?\s+"?([^"\s]+)"?', text, re.M):
                out.append(("npm", m.group(1), m.group(2)))
        elif name == "pnpm-lock.yaml":
            for m in re.finditer(r"^\s{2}'?/?((?:@[^/@\s']+/)?[^@\s'/(]+)[@/](\d[^:'(\s]*)", text, re.M):
                out.append(("npm", m.group(1), m.group(2)))
        elif name == "requirements.txt":
            for m in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", text, re.M):
                out.append(("PyPI", m.group(1), m.group(2)))
        elif name in ("poetry.lock", "uv.lock"):
            for m in re.finditer(r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text, re.M):
                out.append(("PyPI", m.group(1), m.group(2)))
        elif name == "Pipfile.lock":
            d = json.loads(text)
            for sect in ("default", "develop"):
                for n, v in (d.get(sect) or {}).items():
                    ver = str(v.get("version", "")).lstrip("=")
                    if ver:
                        out.append(("PyPI", n, ver))
        elif name == "go.mod":
            for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", text, re.M):
                out.append(("Go", m.group(1), m.group(2)))
        elif name == "Cargo.lock":
            for m in re.finditer(r'^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text, re.M):
                out.append(("crates.io", m.group(1), m.group(2)))
        elif name == "Gemfile.lock":
            for m in re.finditer(r"^\s{4}([A-Za-z0-9_\-]+) \(([\d.]+)\)", text, re.M):
                out.append(("RubyGems", m.group(1), m.group(2)))
        elif name == "composer.lock":
            d = json.loads(text)
            for p in (d.get("packages") or []) + (d.get("packages-dev") or []):
                out.append(("Packagist", p.get("name"), str(p.get("version", "")).lstrip("v")))
    except (ValueError, AttributeError):
        return []
    return [(e, n, v) for e, n, v in out if n and v]


# ---------------------------------------------------------------- OSV 查詢
SEV_MAP = {"CRITICAL": "high", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def query_osv(pkgs, cache: dict, ttl=24 * 3600, cancel=None):
    """pkgs: set of (eco, name, ver)。回傳 {(eco,name,ver): [vuln_id]}；vuln 詳細資料放 cache['vulns']。"""
    qcache = cache.setdefault("query", {})
    vcache = cache.setdefault("vulns", {})
    now = time.time()
    todo = [p for p in pkgs if now - qcache.get("|".join(p), {}).get("t", 0) > ttl]
    for i in range(0, len(todo), 500):
        if cancel is not None and cancel.is_set():
            return {}
        chunk = todo[i:i + 500]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        res = _http_json("https://api.osv.dev/v1/querybatch", body, timeout=60)
        for p, r in zip(chunk, res.get("results", [])):
            qcache["|".join(p)] = {"t": now, "ids": [v["id"] for v in (r.get("vulns") or [])]}
    result = {}
    need = set()
    for p in pkgs:
        ids = qcache.get("|".join(p), {}).get("ids", [])
        if ids:
            result[p] = ids
            need.update(i for i in ids if now - vcache.get(i, {}).get("t", 0) > 7 * ttl)
    def fetch(vid):
        if cancel is not None and cancel.is_set():
            return
        try:
            v = _http_json("https://api.osv.dev/v1/vulns/" + vid)
        except (urllib.error.URLError, ValueError, OSError):
            return
        sev = SEV_MAP.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "medium")
        fixed = {}
        for a in v.get("affected") or []:
            pk = (a.get("package") or {}).get("name")
            for r in a.get("ranges") or []:
                for ev in r.get("events") or []:
                    if "fixed" in ev:
                        fixed.setdefault(pk, []).append(ev["fixed"])
        cves = [x for x in (v.get("aliases") or []) if x.startswith("CVE-")]
        mal = vid.startswith("MAL-")
        vcache[vid] = {"t": now, "summary": v.get("summary") or truncate(v.get("details", ""), 140),
                       "severity": "high" if mal else sev, "fixed": fixed, "cves": cves, "malicious": mal}
    # 漏洞詳細資料平行抓取（8 條連線），結果快取 7 天
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(fetch, sorted(need)))
    return result


def check_dependencies(ctx: ScanContext, lockfiles, cache: dict):
    if not lockfiles:
        return
    ctx.report(CAT, "查詢 OSV 漏洞資料庫（%d 個 lockfile）" % len(lockfiles))
    where = {}
    for lf in lockfiles:
        proj = home_rel(os.path.dirname(lf))
        pk = parse_lockfile(lf)
        for p in pk:
            where.setdefault(p, set()).add(proj)
        # 套件清單太大不放入快照，只記錄 lockfile 指紋（lockfile 變了就代表相依套件變了）
        ctx.inv("專案 lockfile", home_rel(lf), "%d 個套件 | %s" % (len(pk), file_fingerprint(lf)))
    # 套件索引：給「漏洞快訊」比對用 {"eco|name": {version: [專案]}}
    idx = {k: v for k, v in cache.get("pkgindex", {}).items() if "全域 npm" in str(v)}
    for (eco, name, ver), projs in where.items():
        idx.setdefault("%s|%s" % (eco, name), {}).setdefault(ver, [])
        idx["%s|%s" % (eco, name)][ver] = sorted(set(idx["%s|%s" % (eco, name)][ver]) | projs)
    cache["pkgindex"] = idx
    try:
        vulns = query_osv(set(where), cache, cancel=ctx.cancel)
    except (urllib.error.URLError, ValueError, OSError) as e:
        ctx.add(Finding(rule="osv-error", severity="low", category=CAT, title="無法連線 OSV.dev，略過套件漏洞查詢",
                        detail=str(e)[:200]))
        return
    vc = cache.get("vulns", {})
    for (eco, name, ver), ids in sorted(vulns.items()):
        infos = [vc.get(i, {}) for i in ids]
        sev = "high" if any(x.get("severity") == "high" for x in infos) else \
            "medium" if any(x.get("severity") == "medium" for x in infos) else "low"
        mal = any(x.get("malicious") for x in infos)
        fix = fix_all(ver, name, infos)
        cves = sorted({c for x in infos for c in x.get("cves", [])})
        projs = sorted(where[(eco, name, ver)])
        label = ", ".join(cves[:4]) or ", ".join(ids[:4])
        ctx.inv("有漏洞的套件", "%s %s@%s" % (eco, name, ver), ",".join(sorted(ids)))
        ctx.add(Finding(
            rule="dep-malicious" if mal else "dep-vuln", severity="high" if mal else sev, category=CAT,
            title=("⚠️ 已知惡意套件 %s@%s" if mal else "%s@%s 有 %d 個已知漏洞" % ("%s", "%s", len(ids))) % (name, ver),
            path="；".join(projs[:5]) + (" 等 %d 個專案" % len(projs) if len(projs) > 5 else ""),
            detail="%s：%s" % (label, "；".join(truncate(x.get("summary", ""), 80) for x in infos[:3])),
            evidence="%s 套件" % eco,
            why="這個版本被公開通報有漏洞，攻擊方法通常也已公開。" if not mal else
                "OSV 把這個版本列為惡意套件（例如被盜帳號發佈的木馬版本）。安裝過就應假設機器已被入侵。",
            fix=("升級到 %s 以上（%s）" % (fix, _upgrade_hint(eco, name, fix))) if fix and not mal else
                ("立刻移除、更換所有機密、檢查開機自動執行項目。" if mal else "目前沒有修正版本，評估是否改用替代套件。")))


def best_fix(current, fixes):
    """挑「比目前新、優先同主版號」的最小修正版本，避免建議不必要的大版本升級。"""
    cur = _vkey(current)
    newer = sorted({f for f in fixes if _vkey(f) > cur}, key=_vkey)
    same_major = [f for f in newer if _vkey(f)[:1] == cur[:1]]
    return (same_major or newer or [""])[0]


def fix_all(current, name, infos):
    """每個漏洞各自取最小修正版，再取最大值 = 一次修掉全部漏洞的最低版本。"""
    per = [best_fix(current, x.get("fixed", {}).get(name, [])) for x in infos]
    per = [f for f in per if f]
    return max(per, key=_vkey) if per else ""


def _vkey(v):
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v.lstrip("v"))[:4]]


def _upgrade_hint(eco, name, ver):
    return {"npm": "直接相依：npm install %s@^%s；間接相依：npm audit fix 或升級引用它的套件" % (name, ver), "PyPI": "pip install '%s>=%s'" % (name, ver),
            "Go": "go get %s@%s" % (name, ver if ver.startswith("v") else "v" + ver),
            "crates.io": "cargo update -p %s" % name}.get(eco, "更新到修正版本")


# ---------------------------------------------------------------- 執行環境版本
RUNTIMES = [
    ("nodejs", "Node.js", ["node", "--version"], r"v?(\d+)\.(\d+)\.(\d+)"),
    ("python", "Python", ["python3", "--version"], r"(\d+)\.(\d+)\.(\d+)"),
    ("go", "Go", ["go", "version"], r"go(\d+)\.(\d+)(?:\.(\d+))?"),
    ("pnpm", "pnpm", ["pnpm", "--version"], r"(\d+)\.(\d+)\.(\d+)"),
    ("docker-engine", "Docker", ["docker", "version", "--format", "{{.Client.Version}}"], r"(\d+)\.(\d+)\.(\d+)"),
]


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def check_runtimes(ctx: ScanContext, cache: dict):
    ctx.report(CAT, "執行環境版本")
    eol = cache.setdefault("eol", {})
    today = time.strftime("%Y-%m-%d")
    for pid, label, cmd, rx in RUNTIMES:
        out = _run(cmd)
        m = re.search(rx, out)
        if not m:
            continue
        parts = [m.group(1), m.group(2), m.group(3) or "0"]
        ver = ".".join(parts)
        ctx.inv("執行環境版本", label, ver)
        if time.time() - eol.get(pid, {}).get("t", 0) > 24 * 3600:
            try:
                eol[pid] = {"t": time.time(), "data": _http_json("https://endoflife.date/api/%s.json" % pid)}
            except (urllib.error.URLError, ValueError, OSError):
                continue
        cycles = eol.get(pid, {}).get("data") or []
        cyc = next((c for c in cycles if str(c.get("cycle")) in (parts[0], "%s.%s" % (parts[0], parts[1]))), None)
        if not cyc:
            continue
        latest = str(cyc.get("latest", ""))
        e = cyc.get("eol")
        is_eol = e is True or (isinstance(e, str) and e <= today)
        if is_eol:
            newest = next((c for c in cycles if not (c.get("eol") is True or (isinstance(c.get("eol"), str) and c["eol"] <= today))
                           and (c.get("lts") or pid != "nodejs")), cycles[0] if cycles else {})
            ctx.add(Finding(
                rule="runtime-eol", severity="high", category=CAT,
                title="%s %s 已停止維護（EOL：%s）" % (label, ver, e if isinstance(e, str) else "是"),
                why="停止維護的版本不再收到安全修補，之後公開的漏洞都不會修。",
                fix="升級到仍在維護的版本，例如 %s %s。" % (label, newest.get("latest", newest.get("cycle", "")))))
        elif latest and _vkey(latest) > _vkey(ver):
            ctx.add(Finding(
                rule="runtime-outdated", severity="medium" if pid == "nodejs" else "low", category=CAT,
                title="%s %s 不是此版本線的最新修補版（最新 %s）" % (label, ver, latest),
                why="同一版本線的小版號更新通常就是安全修補（Node.js 會定期發佈 security release）。",
                fix={"nodejs": "nvm install %s 或 brew upgrade node" % latest,
                     "python": "brew upgrade python@%s.%s 或用 pyenv/uv 安裝 %s" % (parts[0], parts[1], latest),
                     "go": "brew upgrade go"}.get(pid, "更新到 %s" % latest)))


def check_global_npm(ctx: ScanContext, cache: dict):
    """全域 npm 套件也查 OSV（很多 AI CLI/MCP 都是全域安裝）。"""
    out = _run(["npm", "ls", "-g", "--depth=0", "--json"])
    try:
        deps = (json.loads(out).get("dependencies") or {}) if out.startswith("{") else {}
    except ValueError:
        return
    pkgs = set()
    for n, v in deps.items():
        if isinstance(v, dict) and v.get("version"):
            pkgs.add(("npm", n, v["version"]))
            ctx.inv("全域 npm 套件", n, v["version"])
            cache.setdefault("pkgindex", {}).setdefault("npm|%s" % n, {})[v["version"]] = ["全域 npm"]
    if not pkgs:
        return
    try:
        vulns = query_osv(pkgs, cache, cancel=ctx.cancel)
    except (urllib.error.URLError, ValueError, OSError):
        return
    vc = cache.get("vulns", {})
    for (eco, name, ver), ids in vulns.items():
        infos = [vc.get(i, {}) for i in ids]
        fix = fix_all(ver, name, infos)
        ctx.add(Finding(rule="global-npm-vuln", severity="high" if any(x.get("severity") == "high" for x in infos) else "medium",
                        category=CAT, title="全域 npm 套件 %s@%s 有已知漏洞" % (name, ver),
                        detail="；".join(sorted({c for x in infos for c in x.get("cves", [])}) or ids[:4]),
                        fix="npm install -g %s@%s" % (name, fix or "latest")))
