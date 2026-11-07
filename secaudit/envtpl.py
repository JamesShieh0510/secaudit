"""寫死的機密 → 1Password（Dev Env）+ .env.tpl 的 op:// 引用，程式改成讀環境變數。

依照 ~/projects/ENV_1PASSWORD_GUIDE.md 的慣例：
  - 機密值放在 1Password vault「Dev Env」，每個專案一筆「API Credential」項目，標題 env | ~/<專案>/.env，每個變數一個欄位
  - 專案根目錄的 .env.tpl 只放引用：VAR={{ op://Dev Env/<項目ID>/VAR }}
  - 執行時用 bash ~/op-env-run.sh（程式直接讀環境變數時加 -e）

安全原則：
  - 機密值只經由 stdin 傳給 op，不出現在指令參數；不寫進任何紀錄（處理紀錄只放遮罩值）
  - 改寫程式前，原檔存成 1Password 文件（還原只要一行指令），改寫後做語法檢查，不通過就把原檔寫回去
  - 只自動改寫「整個字串就是機密」的情況；機密嵌在更長的字串裡、或檔案格式不支援環境變數，就只搬值並在紀錄裡寫改法
"""
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time

from .core import HOME, home_rel, mask
from .rules import GENERIC_ASSIGN, SECRET_RULES, is_placeholder

VAULT = "Dev Env"

RULE_VAR = {"anthropic-key": "ANTHROPIC_API_KEY", "openai-key": "OPENAI_API_KEY", "google-api-key": "GOOGLE_API_KEY",
            "aws-access-key": "AWS_ACCESS_KEY_ID", "github-token": "GITHUB_TOKEN", "slack-token": "SLACK_TOKEN",
            "db-url": "DATABASE_URL", "jdbc-password": "DB_PASSWORD", "plain-assign": "SECRET"}
LANG = {".py": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".go": "go",
        ".sh": "sh", ".bash": "sh", ".zsh": "sh", ".md": "doc", ".txt": "doc"}
LANG_NAME = {"py": "Python", "js": "JavaScript / TypeScript", "go": "Go", "sh": "shell", "compose": "docker compose",
             "doc": "文件", "env": ".env"}
ENV_LINE = re.compile(r'^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)$')


def kind_of(path):
    n = os.path.basename(path).lower()
    if n.endswith(".tpl"):
        return "manual"
    if re.match(r"^(?:\.env(?:\..+)?|.+\.env)$", n):
        return "env"
    if re.match(r"^(?:docker-)?compose(?:[.\-].+)?\.ya?ml$", n):
        return "compose"
    return LANG.get(os.path.splitext(n)[1], "manual")


def _snake(name):
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").upper()


def _var_for(text, start, rule):
    """變數名稱：優先用同一行「名稱 = / : 值」裡的名稱，其次依機密種類。"""
    ls = text.rfind("\n", 0, start) + 1
    m = re.search(r"([A-Za-z_][A-Za-z0-9_.]*)\s*(?::=|=|:)\s*[\"'`]?$", text[ls:start])
    if m:
        name = _snake(m.group(1).split(".")[-1])
        if name in ("URL", "DSN", "URI", "CONN", "CONNECTION", "DATABASE", "DB") and rule == "db-url":
            return "DATABASE_URL"
        specific = rule in RULE_VAR and rule not in ("plain-assign", "db-url", "jdbc-password")
        generic = name in ("API_KEY", "KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "AUTH_TOKEN", "ACCESS_TOKEN", "APIKEY")
        if specific and (generic or not re.search(r"KEY|TOKEN|SECRET|PASSWORD|URL|DSN", name)):
            return RULE_VAR[rule]
        if len(name) >= 3 and name not in ("VALUE", "DATA", "STR", "S", "X"):
            return name
    return RULE_VAR.get(rule, "SECRET")


def find(text):
    """回傳 [{start, end, value, var, rule, sev}]，依位置排序、去掉重疊（優先保留比較明確的規則）。"""
    from .checks_secrets import _db_url, _random_enough
    hits = []
    for rid, name, rx, sev in SECRET_RULES:
        if rid == "private-key":
            continue            # 私鑰（例如 service account JSON）不適合放進環境變數，另外處理
        for m in rx.finditer(text):
            s = sev
            if rid in ("openai-key", "anthropic-key") and not _random_enough(m.group(0)):
                continue
            if rid == "db-url":
                skip, s, _ = _db_url(m.group(0))
                if skip:
                    continue
            hits.append({"start": m.start(), "end": m.end(), "value": m.group(0), "rule": rid, "sev": s, "name": name})
    for m in GENERIC_ASSIGN.finditer(text):
        val = m.group(2)
        if is_placeholder(val) or val.lower() in ("true", "false", "null", "none"):
            continue
        hits.append({"start": m.start(2), "end": m.end(2), "value": val, "rule": "plain-assign", "sev": "medium",
                     "name": "明文機密變數", "key": m.group(1)})
    hits.sort(key=lambda h: (h["start"], h["rule"] == "plain-assign", -(h["end"] - h["start"])))
    out, last = [], -1
    for h in hits:
        if h["start"] < last:
            continue
        h["var"] = _snake(h["key"]) if h.get("key") else _var_for(text, h["start"], h["rule"])
        out.append(h)
        last = h["end"]
    return out


def has_private_key(text):
    return any(rid == "private-key" and rx.search(text) for rid, _, rx, _ in SECRET_RULES)


# ---------------------------------------------------------------- 改寫
def _expr(lang, var):
    return {"py": 'os.environ["%s"]' % var, "js": "process.env.%s" % var, "go": 'os.Getenv("%s")' % var}[lang]


def rewrite(text, lang, hits):
    """回傳 (新內容, [(hit, 怎麼改)], [(hit, 為什麼不能自動改)])。"""
    done, manual = [], []
    parts, pos = [], 0
    for h in hits:
        s, e = h["start"], h["end"]
        q = text[s - 1] if s > 0 else ""
        whole = q in "\"'`" and text[e:e + 1] == q
        if lang in ("py", "js", "go"):
            if not whole or (lang == "go" and q == "`") or (lang == "py" and text[max(0, s - 2):s - 1] in "fFrRbB" and
                                                            text[max(0, s - 2):s - 1] != ""):
                manual.append((h, "機密嵌在比較長的字串（或格式化字串）裡，自動改寫可能改錯，請手動改"))
                continue
            parts += [text[pos:s - 1], _expr(lang, h["var"])]
            pos = e + 1
            done.append((h, "%s → %s" % (q + mask(h["value"]) + q, _expr(lang, h["var"]))))
        elif lang == "sh":
            if whole and q == "'":
                parts += [text[pos:s - 1], '"${%s}"' % h["var"]]
                pos = e + 1
            elif whole and q == '"':
                parts += [text[pos:s], "${%s}" % h["var"]]
                pos = e
            else:
                parts += [text[pos:s], '"${%s}"' % h["var"]]
                pos = e
            done.append((h, "%s → ${%s}" % (mask(h["value"]), h["var"])))
        elif lang in ("compose", "doc"):
            parts += [text[pos:s], "${%s}" % h["var"]]
            pos = e
            done.append((h, "%s → ${%s}" % (mask(h["value"]), h["var"])))
        else:
            manual.append((h, "這種檔案格式不會自動展開環境變數"))
    parts.append(text[pos:])
    new = "".join(parts)
    if done and lang == "py" and not re.search(r"^\s*(?:import\s+(?:[\w.]+\s*,\s*)*os\b|from\s+os\s+import)", new, re.M):
        new = _insert_py_import(new)
    if done and lang == "go" and not re.search(r'^\s*(?:import\s+)?"os"\s*$', new, re.M):
        new = _insert_go_import(new)
    return new, done, manual


def _insert_py_import(t):
    lines = t.split("\n")
    i = 0
    while i < len(lines) and (lines[i].startswith("#!") or re.match(r"^#.*coding[:=]", lines[i])):
        i += 1
    # 跳過模組 docstring 與 from __future__
    if i < len(lines) and re.match(r'^\s*[rRuU]?("""|\'\'\')', lines[i]):
        qq = re.match(r'^\s*[rRuU]?("""|\'\'\')', lines[i]).group(1)
        if lines[i].count(qq) >= 2:
            i += 1
        else:
            i += 1
            while i < len(lines) and qq not in lines[i]:
                i += 1
            i += 1
    while i < len(lines) and lines[i].startswith("from __future__"):
        i += 1
    lines.insert(i, "import os")
    return "\n".join(lines)


def _insert_go_import(t):
    m = re.search(r"^import\s*\(\s*\n", t, re.M)
    if m:
        return t[:m.end()] + '\t"os"\n' + t[m.end():]
    m = re.search(r"^import\s+(?:\w+\s+)?\"[^\"]+\"\s*\n", t, re.M)
    if m:
        return t[:m.end()] + 'import "os"\n' + t[m.end():]
    m = re.search(r"^package\s+\w+\s*\n", t, re.M)
    return (t[:m.end()] + '\nimport "os"\n' + t[m.end():]) if m else t


def syntax_ok(path, lang, text):
    """把新內容寫到暫存檔做語法檢查（不動原檔）。回傳 (通過, 錯誤訊息)。沒有檢查工具的語言視為通過。"""
    ext = os.path.splitext(path)[1]
    cmd = {"py": ["python3", "-m", "py_compile"], "go": ["gofmt", "-e", "-l"], "sh": ["bash", "-n"]}.get(lang)
    if lang == "js" and ext in (".js", ".cjs", ".mjs"):
        cmd = ["node", "--check"]
    if not cmd:
        return True, ""
    d = tempfile.mkdtemp(prefix="envtpl-")
    tmp = os.path.join(d, os.path.basename(path))
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            r = subprocess.run(cmd + [tmp], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return True, "（沒有做語法檢查：%s）" % e
        return r.returncode == 0, (r.stderr or r.stdout).replace(tmp, os.path.basename(path)).strip()[:300]
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- .env 檔
def parse_env(text):
    """[(kind, data)]：kind = raw（原樣保留）或 kv：(prefix, key, eq, quote, value, tail)。支援引號與多行值。"""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        ln = lines[i]
        m = ENV_LINE.match(ln)
        if not m or ln.lstrip().startswith("#"):
            out.append(("raw", ln))
            i += 1
            continue
        pre, key, eq, rest = m.groups()
        q = rest[:1] if rest[:1] in ('"', "'") else ""
        if not q:
            val, tail = rest, ""
            mm = re.match(r"^(\S*)(\s+#.*)?$", rest)
            if mm:
                val, tail = mm.group(1), mm.group(2) or ""
            out.append(("kv", (pre, key, eq, "", val, tail)))
            i += 1
            continue
        body, j, end = rest[1:], i, -1
        while True:
            k = 0
            while k < len(body):
                c = body[k]
                if q == '"' and c == "\\":
                    k += 2
                    continue
                if c == q:
                    end = k
                    break
                k += 1
            if end >= 0 or j + 1 >= len(lines):
                break
            j += 1
            body += "\n" + lines[j]
        if end < 0:
            out.append(("raw", ln))
            i += 1
            continue
        out.append(("kv", (pre, key, eq, q, body[:end], body[end + 1:])))
        i = j + 1
    return out


def env_tpl_text(parsed, item_id, vault=VAULT):
    lines, fields = [], {}
    for kind, d in parsed:
        if kind == "raw":
            lines.append(d)
            continue
        pre, key, eq, q, val, tail = d
        if val == "" or is_placeholder(val):
            lines.append("%s%s%s%s%s%s%s" % (pre, key, eq, q, val, q, tail))
            continue
        fields[key] = val
        lines.append("%s%s%s%s{{ op://%s/%s/%s }}%s%s" % (pre, key, eq, q, vault, item_id, key, q, tail))
    return "\n".join(lines), fields


# ---------------------------------------------------------------- 1Password（值一律走 stdin）
def _op(argv, stdin=None, timeout=120):
    from .actions import _op_env, _quiet_err
    return _quiet_err(["op"] + argv, stdin_bytes=stdin, timeout=timeout, env=_op_env())


def op_item_find(title, vault=VAULT):
    ok, out, err = _op(["item", "list", "--vault", vault, "--format", "json"])
    if not ok:
        return None, err or "讀不到 vault「%s」" % vault
    try:
        for it in json.loads(out.decode() or "[]"):
            if it.get("title") == title:
                return it.get("id"), ""
    except ValueError:
        pass
    return "", ""


def op_item_upsert(title, fields, item_id="", vault=VAULT):
    """建立或更新 API Credential 項目：每個變數一個隱藏欄位。回傳 (項目 ID, 錯誤)。"""
    if not item_id:
        tpl = {"title": title, "category": "API_CREDENTIAL", "tags": ["secaudit", "env"],
               "fields": [{"id": k, "type": "CONCEALED", "label": k, "value": v} for k, v in fields.items()]}
        ok, out, err = _op(["item", "create", "--vault", vault, "--format", "json", "-"], json.dumps(tpl).encode())
        if not ok:
            return "", err
        try:
            return str(json.loads(out.decode()).get("id", "")), ""
        except ValueError:
            return "", "無法解析 op 的回應"
    ok, out, err = _op(["item", "get", item_id, "--vault", vault, "--format", "json"])
    if not ok:
        return "", err
    try:
        item = json.loads(out.decode())
    except ValueError:
        return "", "無法解析項目資料"
    fl = item.setdefault("fields", [])
    for k, v in fields.items():
        f = next((x for x in fl if x.get("label") == k), None)
        if f:
            f["value"] = v
        else:
            fl.append({"id": k, "type": "CONCEALED", "label": k, "value": v})
    ok, _, err = _op(["item", "edit", item_id, "--vault", vault], json.dumps(item, ensure_ascii=False).encode())
    return (item_id, "") if ok else ("", err)


def op_verify(item_id, fields, vault=VAULT):
    """逐一用 op read 讀回比對（值不輸出、不記錄）。回傳不一致的變數名稱清單。"""
    bad = []
    for k, v in fields.items():
        ok, out, _ = _op(["read", "op://%s/%s/%s" % (vault, item_id, k)])
        if not ok or out.decode().rstrip("\n") != v:
            bad.append(k)
        del out
    return bad


def op_backup(path, vault=VAULT):
    """原檔存成 1Password 文件（檔案內容由 op 自己讀，不經過指令參數）。回傳 (文件 ID, 標題, 錯誤)。"""
    title = "secaudit 備份：%s（%s）" % (home_rel(path), time.strftime("%Y-%m-%d %H:%M"))
    ok, out, err = _op(["document", "create", path, "--vault", vault, "--title", title, "--tags", "secaudit,secaudit/backup",
                        "--format", "json"])
    if not ok:
        return "", title, err
    try:
        meta = json.loads(out.decode())
        return str(meta.get("uuid") or meta.get("id") or ""), title, ""
    except ValueError:
        return "", title, "無法解析 op 的回應"


def tpl_item(tpl_path):
    """既有 .env.tpl 用的是哪一筆項目（vault, item_id）。"""
    try:
        with open(tpl_path, encoding="utf-8") as fh:
            m = re.search(r"op://([^/}]+)/([^/}]+)/", fh.read())
        return (m.group(1).strip(), m.group(2).strip()) if m else ("", "")
    except OSError:
        return "", ""


def tpl_vars(tpl_path):
    try:
        with open(tpl_path, encoding="utf-8") as fh:
            return set(re.findall(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", fh.read(), re.M))
    except OSError:
        return set()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_atomic(path, text):
    st = os.stat(path)
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".secaudit-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


RUN_HELP = [
    "之後執行這個專案要透過 `bash ~/op-env-run.sh -e <原本的指令>`（建議 alias：`openv`）。`-e` 會把 .env 匯出成環境變數，"
    "因為程式現在是直接讀環境變數；如果專案本來就用 dotenv 讀 .env，可以不加 `-e`。monorepo 加 `-r`。",
    "pm2：在專案資料夾執行 `openv -e pm2 start <設定檔> --update-env`；`pm2 resurrect`／開機自動啟動也要透過 openv。",
    "docker compose：`openv -r docker compose up`（compose 會讀產生出來的 .env 展開 ${變數}）。不要在 Dockerfile 裡 COPY .env。",
    "VS Code / JetBrains 的 Run/Debug 不會經過 op-env-run.sh：改成在終端機用 openv 啟動，或照 ~/projects/ENV_1PASSWORD_GUIDE.md §3 設定。",
    "CI/CD（GitHub Actions、Drone）不會讀本機的 .env.tpl：要把同名的變數加到 CI 的 secrets。",
]
