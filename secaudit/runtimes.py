"""各語言執行環境：找出所有已安裝的版本，以及專案中指定的版本，比對是否停止維護（EOL）或缺少修補。

支援：Node.js、Python、Go、Ruby、Java、PHP、Rust、Deno、Bun、.NET（以及 pnpm、Docker）。
安裝來源：nvm / fnm / volta / n / asdf / Homebrew / conda / pyenv / uv / python.org / rbenv / rvm /
         sdkman / rustup / 系統內建 / 官方安裝檔。
版本盡量從資料夾名稱或中繼資料判斷，必要時才執行 `--version`（結果依路徑與修改時間快取）。
"""
import glob
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

from .core import HOME, Finding, ScanContext, home_rel, read_text

CAT = "供應鏈與版本"
H = HOME
BREW = [p for p in ("/opt/homebrew", "/usr/local") if os.path.isdir(os.path.join(p, "Cellar"))]

# 產品 → (顯示名稱, endoflife.date 產品 id)
PRODUCTS = {
    "nodejs": ("Node.js", "nodejs"), "python": ("Python", "python"), "go": ("Go", "go"),
    "ruby": ("Ruby", "ruby"), "java": ("Java", "eclipse-temurin"), "php": ("PHP", "php"),
    "rust": ("Rust", "rust"), "deno": ("Deno", "deno"), "bun": ("Bun", "bun"), "dotnet": (".NET", "dotnet"),
    "pnpm": ("pnpm", "pnpm"), "docker": ("Docker", "docker-engine"),
}


def _clean(v):
    m = re.search(r"(\d+(?:\.\d+){0,3})", v or "")
    return m.group(1) if m else ""


def _vkey(v):
    return [int(x) for x in re.findall(r"\d+", v)[:4]] + [0] * (4 - len(re.findall(r"\d+", v)[:4]))


def _run_version(path, args, cache):
    """執行 `<path> <args>` 取版本；依 (路徑, 修改時間) 快取。"""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = "%s|%s|%d" % (path, " ".join(args), int(st.st_mtime))
    if key in cache:
        return cache[key]
    try:
        out = subprocess.run([path] + args, capture_output=True, text=True, timeout=10)
        v = _clean(out.stdout + " " + out.stderr)
    except (OSError, subprocess.TimeoutExpired):
        v = ""
    cache[key] = v
    return v


def _dirs(pattern):
    return sorted(p for p in glob.glob(os.path.expanduser(pattern)) if os.path.isdir(p))


def _which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.realpath(p)
    return ""


# ---------------------------------------------------------------- 找出已安裝的版本
def discover(vcache):
    """回傳 [{product, version, source, where, path}]。"""
    out = []

    def add(product, version, source, where, path=""):
        v = _clean(version)
        if v:
            out.append({"product": product, "version": v, "source": source, "where": where, "path": path})

    # Homebrew Cellar：Cellar/<formula>/<version>
    brew_map = [(r"^node(@\d+)?$", "nodejs"), (r"^python@3\.\d+$", "python"), (r"^go(@[\d.]+)?$", "go"),
                (r"^ruby(@[\d.]+)?$", "ruby"), (r"^openjdk(@\d+)?$", "java"), (r"^php(@[\d.]+)?$", "php"),
                (r"^rust$", "rust"), (r"^deno$", "deno"), (r"^bun$", "bun"), (r"^dotnet(@\d+)?$", "dotnet")]
    for b in BREW:
        for f in sorted(os.listdir(os.path.join(b, "Cellar"))):
            prod = next((p for rx, p in brew_map if re.match(rx, f)), None)
            if prod:
                for vd in _dirs(os.path.join(b, "Cellar", f, "*")):
                    add(prod, os.path.basename(vd).split("_")[0], "Homebrew", "brew %s" % f, vd)
    # Node.js
    for d in _dirs("~/.nvm/versions/node/v*"):
        add("nodejs", os.path.basename(d), "nvm", "nvm", d)
    for d in _dirs("~/.local/share/fnm/node-versions/v*") + _dirs("~/Library/Application Support/fnm/node-versions/v*"):
        add("nodejs", os.path.basename(d), "fnm", "fnm", d)
    for d in _dirs("~/.volta/tools/image/node/*"):
        add("nodejs", os.path.basename(d), "volta", "volta", d)
    for d in _dirs("/usr/local/n/versions/node/*"):
        add("nodejs", os.path.basename(d), "n", "n", d)
    # Python：conda（版本從 conda-meta 讀，不用執行）
    for base in ("~/miniconda3", "~/anaconda3", "~/miniforge3", "~/mambaforge", "/opt/miniconda3", "/opt/anaconda3",
                 "/opt/homebrew/Caskroom/miniconda/base", "/opt/homebrew/Caskroom/miniforge/base"):
        base = os.path.expanduser(base)
        if not os.path.isdir(os.path.join(base, "conda-meta")):
            continue
        name = os.path.basename(base.rstrip("/")) if "Caskroom" not in base else "miniconda"
        for env in [base] + _dirs(os.path.join(base, "envs", "*")):
            metas = glob.glob(os.path.join(env, "conda-meta", "python-3*.json"))
            if metas:
                add("python", os.path.basename(metas[0]).split("-")[1], "conda",
                    "conda %s" % ("base" if env == base else os.path.basename(env)), env)
    for d in _dirs("~/.pyenv/versions/*"):
        add("python", os.path.basename(d), "pyenv", "pyenv", d)
    for d in _dirs("~/.local/share/uv/python/cpython-*"):
        add("python", os.path.basename(d).split("-")[1], "uv", "uv", d)
    for d in _dirs("/Library/Frameworks/Python.framework/Versions/3.*"):
        py = os.path.join(d, "bin", "python3")
        if os.path.exists(py):
            add("python", _run_version(py, ["--version"], vcache), "python.org", "python.org 安裝檔", d)
    clt = "/Library/Developer/CommandLineTools/usr/bin/python3"
    if os.path.exists(clt):    # 直接呼叫 /usr/bin/python3 可能觸發「安裝開發者工具」視窗，改用 CLT 路徑
        add("python", _run_version(clt, ["--version"], vcache), "系統", "Xcode Command Line Tools", clt)
    # Go
    for vf in ["/usr/local/go/VERSION"] + glob.glob(os.path.expanduser("~/sdk/go*/VERSION")):
        t = read_text(vf) or ""
        add("go", t.split()[0] if t else "", "官方安裝檔" if vf.startswith("/usr/local") else "go install golang.org/dl",
            home_rel(os.path.dirname(vf)), os.path.dirname(vf))
    for d in _dirs("~/go/pkg/mod/golang.org/toolchain@*"):
        m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", d)
        if m:
            add("go", m.group(1), "Go 自動下載的 toolchain", "toolchain", d)
    for d in _dirs("~/.gvm/gos/go*") + _dirs("~/.goenv/versions/*"):
        add("go", os.path.basename(d), "gvm/goenv", home_rel(d), d)
    # Ruby
    for d in _dirs("~/.rbenv/versions/*"):
        add("ruby", os.path.basename(d), "rbenv", "rbenv", d)
    for d in _dirs("~/.rvm/rubies/ruby-*"):
        add("ruby", os.path.basename(d)[5:], "rvm", "rvm", d)
    if os.path.exists("/usr/bin/ruby"):
        add("ruby", _run_version("/usr/bin/ruby", ["-e", "print RUBY_VERSION"], vcache), "系統", "macOS 內建", "/usr/bin/ruby")
    # Java
    for d in _dirs("/Library/Java/JavaVirtualMachines/*") + _dirs("~/Library/Java/JavaVirtualMachines/*") + _dirs("~/.sdkman/candidates/java/*"):
        rel = next((p for p in (os.path.join(d, "Contents", "Home", "release"), os.path.join(d, "release")) if os.path.exists(p)), "")
        m = re.search(r'JAVA_VERSION="([^"]+)"', read_text(rel) or "") if rel else None
        if m:
            add("java", m.group(1).replace("1.8.0", "8.0"), "JDK", os.path.basename(d), d)
    # Rust（每個 toolchain 執行一次 rustc --version，有快取）
    for d in _dirs("~/.rustup/toolchains/*"):
        rc = os.path.join(d, "bin", "rustc")
        if os.path.exists(rc):
            add("rust", _run_version(rc, ["--version"], vcache), "rustup", "rustup %s" % os.path.basename(d).split("-")[0], d)
    # Deno / Bun（自己的安裝程式）
    for prod, p in (("deno", "~/.deno/bin/deno"), ("bun", "~/.bun/bin/bun")):
        p = os.path.expanduser(p)
        if os.path.exists(p):
            add(prod, _run_version(p, ["--version"], vcache), "官方安裝程式", home_rel(p), p)
    # .NET
    for d in _dirs("/usr/local/share/dotnet/shared/Microsoft.NETCore.App/*") + _dirs("~/.dotnet/shared/Microsoft.NETCore.App/*"):
        add("dotnet", os.path.basename(d), ".NET runtime", home_rel(d), d)
    # asdf / mise（一次處理多種語言）
    for root in ("~/.asdf/installs", "~/.local/share/mise/installs"):
        for prod_dir, prod in (("nodejs", "nodejs"), ("node", "nodejs"), ("python", "python"), ("golang", "go"), ("go", "go"),
                               ("ruby", "ruby"), ("java", "java"), ("php", "php"), ("rust", "rust"), ("deno", "deno"), ("bun", "bun")):
            for d in _dirs(os.path.join(root, prod_dir, "*")):
                add(prod, os.path.basename(d), "asdf/mise", "%s %s" % (os.path.basename(os.path.dirname(os.path.dirname(root))) or "asdf", prod_dir), d)
    # pnpm / Docker：只看 PATH 上的
    for prod, name, args in (("pnpm", "pnpm", ["--version"]), ("docker", "docker", ["version", "--format", "{{.Client.Version}}"])):
        p = _which(name)
        if p:
            add(prod, _run_version(p, args, vcache), "PATH", name, p)

    # 標記 PATH 上的預設版本
    for prod, name in (("nodejs", "node"), ("python", "python3"), ("go", "go"), ("ruby", "ruby"), ("java", "java"),
                       ("php", "php"), ("rust", "rustc"), ("deno", "deno"), ("bun", "bun")):
        p = _which(name)
        if not p:
            continue
        for x in out:
            if x["product"] == prod and x["path"] and p.startswith(os.path.realpath(x["path"]) + os.sep):
                x["default"] = True
    # 去除重複（同一個實體路徑）
    seen, uniq = set(), []
    for x in out:
        k = (x["product"], os.path.realpath(x["path"]) if x["path"] else x["where"], x["version"])
        if k not in seen:
            seen.add(k)
            uniq.append(x)
    return uniq


# ---------------------------------------------------------------- EOL 資料
def _get_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "secaudit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def eol_data(product, cache, online=True):
    """endoflife.date 的版本線資料，快取 24 小時；離線時沿用舊快取。"""
    pid = PRODUCTS[product][1]
    eol = cache.setdefault("eol", {})
    ent = eol.get(pid)
    if online and (not ent or time.time() - ent.get("t", 0) > 86400):
        try:
            eol[pid] = ent = {"t": time.time(), "data": _get_json("https://endoflife.date/api/%s.json" % pid)}
        except (urllib.error.URLError, ValueError, OSError):
            pass
    return (ent or {}).get("data") or []


def find_cycle(cycles, version):
    parts = re.findall(r"\d+", version)
    cands = [".".join(parts[:3]), ".".join(parts[:2]), parts[0] if parts else ""]
    if len(parts) >= 2:
        cands.append("%s.%s.0" % (parts[0], parts[1]))
    for c in cands:
        for cy in cycles:
            if str(cy.get("cycle")) == c:
                return cy
    return None


def is_eol(cy, today):
    e = cy.get("eol")
    return e is True or (isinstance(e, str) and e <= today)


def newest_supported(cycles, today, prefer_lts=False):
    """建議升級的目標：仍在維護、且發布超過一年的最新版本線（剛發布的版本很多套件還不支援）；Node.js 優先 LTS。"""
    ok = [c for c in cycles if not is_eol(c, today)]
    if prefer_lts:
        ok = [c for c in ok if c.get("lts")] or ok
    year_ago = time.strftime("%Y-%m-%d", time.localtime(time.time() - 365 * 86400))
    mature = [c for c in ok if str(c.get("releaseDate") or "9999") <= year_ago]
    return (mature or ok or cycles or [{}])[0]


def node_security_index(cache, online=True):
    """nodejs.org/dist/index.json：每個版本都有 security 標記。"""
    ent = cache.get("node_index")
    if online and (not ent or time.time() - ent.get("t", 0) > 86400):
        try:
            cache["node_index"] = ent = {"t": time.time(), "data": [
                {"v": r["version"].lstrip("v"), "date": r.get("date"), "sec": bool(r.get("security"))}
                for r in _get_json("https://nodejs.org/dist/index.json", timeout=30)]}
        except (urllib.error.URLError, ValueError, OSError):
            pass
    return (ent or {}).get("data") or []


def missed_node_security(version, index):
    """回傳同一版本線中比目前新、且標記為安全修補的版本（新到舊）。"""
    major = version.split(".")[0]
    cur = _vkey(version)
    return [r for r in index if r["v"].split(".")[0] == major and _vkey(r["v"]) > cur and r["sec"]]


# ---------------------------------------------------------------- 修正建議
def _fix_hint(x, target):
    s, w = x["source"], x["where"]
    t = target or "仍在維護的版本"
    return {
        "nvm": "nvm install %s && nvm alias default %s，確認沒有專案使用後 nvm uninstall %s" % (t.split(".")[0], t.split(".")[0], x["version"]),
        "Homebrew": "brew upgrade %s；舊版本線不再使用的話 brew uninstall %s" % (w[5:], w[5:]),
        "conda": "conda create -n <新名稱> python=%s，確認可用後 conda env remove -n %s" % (".".join(t.split(".")[:2]), w[6:]) if w != "conda base" else "base 環境建議改用新的 conda 環境，不要直接升級 base",
        "pyenv": "pyenv install %s，之後 pyenv uninstall %s" % (t, x["version"]),
        "uv": "uv python install %s，之後 uv python uninstall %s" % (".".join(t.split(".")[:2]), x["version"]),
        "rbenv": "rbenv install %s，之後 rbenv uninstall %s" % (t, x["version"]),
        "rustup": "rustup update；不用的 toolchain 用 rustup toolchain uninstall 移除",
        "fnm": "fnm install %s，之後 fnm uninstall %s" % (t.split(".")[0], x["version"]),
        "volta": "volta install node@%s" % t.split(".")[0],
        "Go 自動下載的 toolchain": "這是專案 go.mod 的 toolchain 指令自動下載的快取；把那些專案的 go / toolchain 版本改新後，"
                                   "可刪除 %s（或 go clean -modcache 清掉整個模組快取）" % home_rel(x["path"]),
    }.get(s, "更新到 %s" % t)


# ---------------------------------------------------------------- 已安裝版本的檢查
def check_installed(ctx: ScanContext, cache: dict, online=True):
    ctx.report(CAT, "已安裝的執行環境")
    vcache = cache.setdefault("runtime_versions", {})
    installs = discover(vcache)
    today = time.strftime("%Y-%m-%d")
    node_idx = node_security_index(cache, online) if any(x["product"] == "nodejs" for x in installs) else []
    groups = {}   # (product, status) -> [install]
    for x in installs:
        name = PRODUCTS[x["product"]][0]
        ctx.inv("已安裝的執行環境", "%s ▸ %s%s" % (name, x["where"], "（預設）" if x.get("default") else ""), x["version"])
        cycles = eol_data(x["product"], cache, online)
        cy = find_cycle(cycles, x["version"]) if cycles else None
        if not cy:
            continue
        x["latest"] = str(cy.get("latest") or "")
        x["eol_date"] = cy.get("eol") if isinstance(cy.get("eol"), str) else ""
        if is_eol(cy, today):
            x["target"] = str(newest_supported(cycles, today, x["product"] == "nodejs").get("latest") or "")
            groups.setdefault((x["product"], "eol"), []).append(x)
            continue
        if x["product"] == "nodejs" and node_idx:
            miss = missed_node_security(x["version"], node_idx)
            if miss:
                x["missed"] = miss
                x["target"] = x["latest"]
                groups.setdefault((x["product"], "security"), []).append(x)
                continue
        if x["latest"] and _vkey(x["latest"]) > _vkey(x["version"]):
            x["target"] = x["latest"]
            groups.setdefault((x["product"], "outdated"), []).append(x)

    for (prod, status), xs in sorted(groups.items()):
        name = PRODUCTS[prod][0]
        xs.sort(key=lambda x: (not x.get("default"), _vkey(x["version"])))
        has_default = any(x.get("default") for x in xs)
        lines = []
        for x in xs[:15]:
            extra = ""
            if status == "eol":
                extra = "，%s 停止維護" % x["eol_date"] if x.get("eol_date") else ""
            elif status == "security":
                extra = "，錯過 %d 次安全更新（最近 %s 的 v%s）" % (len(x["missed"]), x["missed"][0]["date"], x["missed"][0]["v"])
            lines.append("%s %s（%s%s）%s → 建議：%s" % (name, x["version"], x["where"], "，預設" if x.get("default") else "",
                                                     extra, _fix_hint(x, x.get("target"))))
        if len(xs) > 15:
            lines.append("…另有 %d 個" % (len(xs) - 15))
        if status == "eol":
            sev = "high" if has_default else "medium"
            title = "%s：%d 個已安裝的版本已停止維護%s" % (name, len(xs), "（包含預設版本）" if has_default else "")
            why = "停止維護的版本不再收到安全修補，之後公開的漏洞都不會修。即使不是預設版本，只要有專案或工具在用就有風險。"
        elif status == "security":
            sev = "high"
            n = max(len(x["missed"]) for x in xs)
            title = "%s：%d 個已安裝的版本缺少安全更新（最多錯過 %d 次）" % (name, len(xs), n)
            why = "Node.js 官方把這些更新標記為安全修補（security release），代表目前版本有已公開的漏洞。"
        else:
            sev = "medium" if has_default else "low"
            title = "%s：%d 個已安裝的版本不是最新修補版" % (name, len(xs))
            why = "同一版本線的小版號更新常包含安全修補。"
        ctx.add(Finding(rule="runtime-%s-%s" % (prod, status), severity=sev, category=CAT, title=title,
                        detail=" ／ ".join(lines), why=why,
                        fix="依每個項目的建議更新；用不到的版本直接移除可以減少攻擊面。"))


# ---------------------------------------------------------------- 專案指定的版本
PIN_FILES = {".nvmrc", ".node-version", ".python-version", ".ruby-version", ".go-version", ".java-version",
             ".tool-versions", "runtime.txt", "go.mod", "package.json", "pyproject.toml", "composer.json", "Gemfile"}
DOCKER_IMAGES = [
    (r"^(?:docker\.io/)?(?:library/)?node$", "nodejs"), (r"^(?:docker\.io/)?(?:library/)?python$", "python"),
    (r"^(?:docker\.io/)?(?:library/)?golang$", "go"), (r"^(?:docker\.io/)?(?:library/)?ruby$", "ruby"),
    (r"^(?:docker\.io/)?(?:library/)?php$", "php"), (r"^(?:docker\.io/)?(?:library/)?(?:openjdk|eclipse-temurin|amazoncorretto)$", "java"),
    (r"^(?:docker\.io/)?(?:library/)?rust$", "rust"), (r"^denoland/deno$", "deno"), (r"^oven/bun$", "bun"),
    (r"^mcr\.microsoft\.com/dotnet/(?:sdk|aspnet|runtime)$", "dotnet"),
]
TOOL_VERSIONS = {"nodejs": "nodejs", "node": "nodejs", "python": "python", "golang": "go", "go": "go", "ruby": "ruby",
                 "java": "java", "php": "php", "rust": "rust", "deno": "deno", "bun": "bun"}


def is_pin_file(fn):
    return fn in PIN_FILES or fn.startswith("Dockerfile") or fn.endswith(".Dockerfile") or \
        re.match(r"^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$", fn) is not None


def parse_pins(path):
    """回傳 [(product, version, 說明)]。只取明確的版本線；>= 這類開放範圍不算。"""
    fn = os.path.basename(path)
    t = read_text(path, limit=512 * 1024) or ""
    out = []
    if fn in (".nvmrc", ".node-version"):
        v = t.strip().lstrip("v")
        if re.match(r"^\d", v):
            out.append(("nodejs", v, fn))
    elif fn == ".python-version":
        for line in t.split():
            if re.match(r"^\d", line):
                out.append(("python", line, fn))
    elif fn in (".ruby-version", ".go-version", ".java-version"):
        prod = {".ruby-version": "ruby", ".go-version": "go", ".java-version": "java"}[fn]
        v = t.strip().replace("ruby-", "")
        if re.match(r"^\d", v):
            out.append((prod, v, fn))
    elif fn == ".tool-versions":
        for line in t.splitlines():
            p = line.split()
            if len(p) >= 2 and p[0] in TOOL_VERSIONS and re.match(r"^\d", p[1]):
                out.append((TOOL_VERSIONS[p[0]], p[1], ".tool-versions"))
    elif fn == "runtime.txt":
        m = re.search(r"python-(\d+\.\d+(?:\.\d+)?)", t)
        if m:
            out.append(("python", m.group(1), "runtime.txt"))
    elif fn == "go.mod":
        m = re.search(r"^go\s+(\d+\.\d+)", t, re.M)
        if m:
            out.append(("go", m.group(1), "go.mod 的 go 指令"))
        m = re.search(r"^toolchain\s+go(\d+\.\d+(?:\.\d+)?)", t, re.M)
        if m:
            out.append(("go", m.group(1), "go.mod 的 toolchain"))
    elif fn == "package.json":
        try:
            eng = (json.loads(t).get("engines") or {}).get("node", "")
        except ValueError:
            eng = ""
        m = re.match(r"^\s*[\^~=v]*(\d+)(?:\.x|\.\*)?(?:\.\d+)*\s*$", str(eng))   # 16、^16、~16.4、16.x
        if m:
            out.append(("nodejs", m.group(1), "package.json engines.node = %s" % eng))
    elif fn == "pyproject.toml":
        m = re.search(r'requires-python\s*=\s*"\s*(?:==|~=)\s*(\d+\.\d+)', t)
        if m:
            out.append(("python", m.group(1), "pyproject.toml requires-python"))
    elif fn == "composer.json":
        try:
            php = (json.loads(t).get("require") or {}).get("php", "")
        except ValueError:
            php = ""
        m = re.match(r"^\s*[\^~=]*(\d+\.\d+)", str(php))
        if m and not str(php).strip().startswith(">"):
            out.append(("php", m.group(1), "composer.json require.php = %s" % php))
    elif fn == "Gemfile":
        m = re.search(r"""^\s*ruby\s+['"]~?>?\s*(\d+\.\d+(?:\.\d+)?)""", t, re.M)
        if m:
            out.append(("ruby", m.group(1), "Gemfile ruby"))
    else:  # Dockerfile / compose
        rx = r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)" if not fn.endswith((".yml", ".yaml")) else r"^\s*image:\s*['\"]?([^\s'\"]+)"
        for m in re.finditer(rx, t, re.M | re.I):
            img = m.group(1)
            if "$" in img:
                continue
            name, _, tag = img.split("@")[0].rpartition(":") if ":" in img.split("/")[-1] else (img, "", "")
            prod = next((p for r, p in DOCKER_IMAGES if re.match(r, name)), None)
            tv = re.match(r"^(\d+(?:\.\d+){0,2})", tag or "")
            if prod and tv:
                is_df = fn.startswith("Dockerfile") or fn.endswith(".Dockerfile")
                out.append((prod, tv.group(1), "%s：%s" % ("Dockerfile FROM" if is_df else "compose image", img)))
    return out


def check_project_pins(ctx: ScanContext, pin_files, cache, online=True):
    if not pin_files:
        return
    ctx.report(CAT, "專案指定的執行環境版本（%d 個檔案）" % len(pin_files))
    today = time.strftime("%Y-%m-%d")
    groups = {}
    for p in pin_files:
        for prod, ver, desc in parse_pins(p):
            cycles = eol_data(prod, cache, online)
            cy = find_cycle(cycles, ver) if cycles else None
            ctx.inv("專案指定的執行環境", "%s ▸ %s" % (home_rel(p), desc), "%s %s" % (PRODUCTS[prod][0], ver))
            if cy and is_eol(cy, today):
                docker = desc.startswith(("Dockerfile", "compose"))
                tgt = newest_supported(cycles, today, prod == "nodejs").get("cycle", "")
                groups.setdefault((prod, docker), []).append((home_rel(p), ver, desc, cy.get("eol"), tgt))
    for (prod, docker), items in sorted(groups.items()):
        name = PRODUCTS[prod][0]
        lines = ["%s：%s %s（%s%s）" % (path, name, ver, desc, "，%s 停止維護" % e if isinstance(e, str) else "")
                 for path, ver, desc, e, _ in items[:15]]
        if len(items) > 15:
            lines.append("…另有 %d 個" % (len(items) - 15))
        tgt = items[0][4]
        ctx.add(Finding(
            rule="pin-%s-%s" % (prod, "docker" if docker else "project"), severity="high" if docker else "medium", category=CAT,
            title="%s：%d 處%s指定了已停止維護的版本" % (name, len(items), "容器映像" if docker else "專案設定"),
            detail=" ／ ".join(lines),
            why=("部署出去的容器會一直使用這個版本，伺服器上的服務等於跑在不再修補漏洞的環境。" if docker else
                 "專案指定的版本會被開發工具、CI 自動採用，團隊成員也會跟著用舊版。"),
            fix="把版本改成仍在維護的 %s %s 以上，測試後重新部署。" % (name, tgt)))


# ---------------------------------------------------------------- 已停用的 Codex plugin
def disabled_codex_plugins():
    """從 ~/.codex/config.toml 找出 enabled = false 的 plugin，回傳 {(marketplace, name)}。"""
    t = read_text(os.path.join(H, ".codex", "config.toml")) or ""
    out = set()
    for m in re.finditer(r'^\[plugins\."([^"@]+)@([^"]+)"\]\s*\n(?:[^\[]*?\n)?\s*enabled\s*=\s*false', t, re.M):
        out.add((m.group(2), m.group(1)))
    return out
