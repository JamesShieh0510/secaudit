"""共用資料結構與工具函式（Python 3.8 相容，只用標準庫）。"""
import os
import re
import stat
import threading
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

HOME = os.path.expanduser("~")

SEVERITIES = ["high", "medium", "low", "info"]
SEV_LABEL = {"high": "高", "medium": "中", "low": "低", "info": "資訊"}

# macOS 檔案旗標：雲端「僅限線上」的佔位檔。讀取內容會觸發下載，所以只看不讀。
SF_DATALESS = 0x40000000

MAX_CONTENT_BYTES = 1024 * 1024  # 超過 1MB 的檔案不掃內容

# 遍歷時直接略過的資料夾名稱（體積大、幾乎不會放設定檔）
PRUNE_DIRS = {
    "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    ".cache", ".npm", ".pnpm-store", ".yarn", ".cargo", ".rustup", ".gradle",
    ".m2", ".next", ".nuxt", ".turbo", ".Trash", ".DocumentRevisions-V100",
    ".Spotlight-V100", ".fseventsd", ".TemporaryItems", "#recycle", "@eaDir",
    ".pyenv", ".nvm", ".bun", ".deno", "site-packages", "Pods", "DerivedData",
}


@dataclass
class Finding:
    rule: str
    severity: str           # high / medium / low / info
    category: str
    title: str
    path: str = ""
    detail: str = ""
    evidence: str = ""      # 一律是遮罩或截斷後的內容
    why: str = ""
    fix: str = ""
    scope: str = ""         # system（固定位置檢查）/ walk（遍歷目標資料夾）/ online（需連網）

    def to_dict(self):
        return asdict(self)


@dataclass
class Target:
    path: str
    label: str = ""
    kind: str = "custom"    # home / cloud / custom
    enabled: bool = True


@dataclass
class ScanContext:
    targets: List[Target]
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "files_seen": 0, "files_read": 0, "dataless_skipped": 0,
        "errors": 0, "dirs_seen": 0,
    })
    progress: Optional[Callable[[str, str], None]] = None
    cancel: threading.Event = field(default_factory=threading.Event)
    max_files_per_target: int = 500000
    # 清單快照：{scope: {區段: {項目鍵: 描述}}}，用來比對兩次掃描之間的變動
    inventory: Dict[str, Dict[str, Dict[str, str]]] = field(default_factory=dict)
    scope: str = "system"

    def add(self, f: Finding):
        f.scope = self.scope
        self.findings.append(f)

    def inv(self, section: str, key: str, value: str):
        self.inventory.setdefault(self.scope, {}).setdefault(section, {})[key] = value

    def report(self, phase: str, current: str = ""):
        if self.progress:
            self.progress(phase, current)


def home_rel(path: str) -> str:
    if path == HOME or path.startswith(HOME + os.sep):
        return "~" + path[len(HOME):]
    return path


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 10:
        return v[:2] + "****"
    return v[:6] + "****" + v[-4:]


def truncate(s: str, n: int = 120) -> str:
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[:n] + "…"


def lstat_safe(path: str):
    try:
        return os.lstat(path)
    except OSError:
        return None


def is_dataless(st) -> bool:
    return bool(getattr(st, "st_flags", 0) & SF_DATALESS)


def read_text(path: str, ctx: Optional[ScanContext] = None, limit: int = MAX_CONTENT_BYTES) -> Optional[str]:
    """安全讀取文字檔：略過雲端佔位檔、過大檔、二進位檔、符號連結。"""
    st = lstat_safe(path)
    if st is None or not stat.S_ISREG(st.st_mode):
        return None
    if is_dataless(st):
        if ctx:
            ctx.stats["dataless_skipped"] += 1
        return None
    if st.st_size > limit:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
    except OSError:
        if ctx:
            ctx.stats["errors"] += 1
        return None
    if b"\x00" in data[:4096]:
        return None
    if ctx:
        ctx.stats["files_read"] += 1
    return data.decode("utf-8", errors="replace")


def file_fingerprint(path: str) -> str:
    """不讀內容就能比對的指紋：大小 + 修改時間；小檔案另外加內容雜湊。"""
    import hashlib
    import time
    st = lstat_safe(path)
    if st is None:
        return "missing"
    fp = "size=%d mtime=%s mode=%s" % (st.st_size, time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)), mode_str(st))
    if stat.S_ISREG(st.st_mode) and st.st_size <= MAX_CONTENT_BYTES and not is_dataless(st):
        try:
            with open(path, "rb") as fh:
                fp += " sha256=" + hashlib.sha256(fh.read()).hexdigest()[:16]
        except OSError:
            pass
    return fp


def mode_str(st) -> str:
    return oct(stat.S_IMODE(st.st_mode))[2:].zfill(3)


def group_or_world_readable(st) -> bool:
    return bool(st.st_mode & (stat.S_IRGRP | stat.S_IROTH))


# ---------------------------------------------------------------- 子程序用的環境變數
SECRET_ENV = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "OLLAMA_API_KEY")
_SECRETISH = re.compile(r"KEY|TOKEN|SECRET|PASSW|PWD|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE|CHAT_ID|DSN|DATABASE|_URL$|_URI$|_SK$", re.I)
_ENV_KEEP = {"PWD", "OLDPWD", "SSH_AUTH_SOCK"}


def remember_secret_keys(names):
    """記錄從 1Password / .env 載入的變數名稱（存在 SECAUDIT_SECRET_KEYS），讓所有子程序都能把它們過濾掉。"""
    cur = {k for k in os.environ.get("SECAUDIT_SECRET_KEYS", "").split(",") if k}
    os.environ["SECAUDIT_SECRET_KEYS"] = ",".join(sorted(cur | set(names)))


def safe_env(**extra):
    """拿掉常駐程式持有的機密後的環境變數：固定名單 + SECAUDIT_SECRET_KEYS 列出的名稱 + 名稱看起來像機密的變數。
    掃描時執行的 codesign、crontab、npm、各語言的 --version 等子程序都用這個，避免把 Telegram / Ollama 金鑰交給它們。"""
    drop = set(SECRET_ENV) | {k for k in os.environ.get("SECAUDIT_SECRET_KEYS", "").split(",") if k}
    env = {k: v for k, v in os.environ.items()
           if k not in drop and k != "SECAUDIT_SECRET_KEYS" and (k in _ENV_KEEP or not _SECRETISH.search(k))}
    env.update(extra)
    return env
