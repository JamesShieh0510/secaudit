"""關鍵位置即時監看。

做法類似 git 判斷檔案有沒有改：每隔幾秒只 stat（大小、修改時間、inode），不讀內容；
發現不一樣後先等一小段時間（把同一批更新合併），再跑一次快速掃描，交給既有的比對與 Telegram 流程。
沒有實質變動（例如 ~/.claude.json 只是啟動次數 +1）就不會通知。
"""
import hashlib
import json
import os
import subprocess
import time

from .core import HOME, home_rel
from .checks_ai import MCP_JSON_SOURCES, SKILL_ROOTS
from .checks_browser import _chromium_profiles
from .checks_persistence import LAUNCH_DIRS, SHELL_RC

SKIP = {"node_modules", ".git", "__pycache__", ".venv"}


def _st(p):
    try:
        st = os.lstat(p)
        return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_mode)
    except OSError:
        return None


def sig_dir(path, depth):
    """資料夾指紋：depth 層以內所有項目的 (相對路徑, stat)。"""
    out = []
    base_depth = path.rstrip(os.sep).count(os.sep)
    try:
        for dp, dns, fns in os.walk(path):
            dns[:] = [d for d in dns if d not in SKIP and not d.startswith("temp_git_")]
            if dp.count(os.sep) - base_depth >= depth:
                dns[:] = []
            for n in dns + fns:
                full = os.path.join(dp, n)
                out.append((os.path.relpath(full, path), _st(full)))
    except OSError:
        return None
    return hashlib.sha1(repr(sorted(out)).encode()).hexdigest() if out or os.path.isdir(path) else None


class ClaudeJsonSig:
    """~/.claude.json 幾乎每分鐘都在變（啟動次數、快取），只取 MCP 設定的部分做指紋。"""

    def __init__(self, path):
        self.path, self.last_st, self.last_sig = path, None, None

    def __call__(self):
        st = _st(self.path)
        if st == self.last_st:
            return self.last_sig
        self.last_st = st
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            mcp = {"_": d.get("mcpServers")}
            for k, v in (d.get("projects") or {}).items():
                if isinstance(v, dict) and v.get("mcpServers"):
                    mcp[k] = v["mcpServers"]
            self.last_sig = hashlib.sha1(json.dumps(mcp, sort_keys=True).encode()).hexdigest()
        except (OSError, ValueError):
            pass   # 寫到一半讀不到時沿用上次的指紋
        return self.last_sig


def _crontab_sig():
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return hashlib.sha1(out.encode()).hexdigest()


def build_watch_list():
    """回傳 [(標籤, 取得指紋的函式)]。"""
    w = []

    def f(label, p):
        p = os.path.expanduser(p)
        w.append((label, lambda p=p: _st(p)))

    def d(label, p, depth=1):
        p = os.path.expanduser(p)
        w.append((label, lambda p=p, depth=depth: sig_dir(p, depth)))

    w.append(("~/.claude.json 的 MCP 設定", ClaudeJsonSig(os.path.join(HOME, ".claude.json"))))
    for p in ("~/.claude/settings.json", "~/.claude/settings.local.json", "~/.claude/CLAUDE.md",
              "~/.claude/channels/telegram/access.json", "~/.claude/plugins/installed_plugins.json",
              "~/.claude/plugins/known_marketplaces.json", "~/.codex/config.toml", "~/.codex/AGENTS.md",
              "~/.gemini/GEMINI.md", "~/.git-credentials", "~/.netrc", "~/.aws/credentials", "~/.npmrc",
              "~/.docker/config.json", "~/.ssh/authorized_keys", "~/.ssh/config"):
        f(p, p)
    for p, label in MCP_JSON_SOURCES:
        f("%s MCP 設定" % label, p)
    for p in SHELL_RC:
        f(p, p)
    d("~/.ssh", "~/.ssh", 1)
    d("/Users/Shared", "/Users/Shared", 2)
    d("~/Library 隱藏資料夾", "~/Library", 1)
    for p, label in LAUNCH_DIRS:
        d(label, p, 1)
    for p, label in SKILL_ROOTS:
        if "plugins" in p:      # plugin 快取很大，改看 installed_plugins.json
            continue
        d("%s（%s）" % (label, p), p, 3)
    for browser, label, prof in _chromium_profiles():
        d("%s 擴充功能" % label, os.path.join(prof, "Extensions"), 2)
    w.append(("crontab", _crontab_sig))
    from .app import DATA      # 授權修復動作用的 YubiKey 清單：任何人直接改這個檔都要警示
    f("secaudit 授權金鑰", os.path.join(DATA, "webauthn.json"))
    return w


class Watcher:
    def __init__(self, engine, interval=10, debounce=20, max_wait=90):
        self.engine, self.interval, self.debounce, self.max_wait = engine, interval, debounce, max_wait
        self.items, self.sigs = [], {}
        self.pending = {}         # 標籤 -> 第一次發現變動的時間
        self.last_change = 0
        self.built = 0

    def _rebuild(self):
        self.items = build_watch_list()
        self.built = time.time()
        for label, fn in self.items:
            if label not in self.sigs:
                self.sigs[label] = fn()

    def poll(self):
        """掃一輪指紋，回傳這一輪發現變動的標籤。"""
        if time.time() - self.built > 600:   # 每 10 分鐘重建清單（例如新增了瀏覽器 profile）
            self._rebuild()
        changed = []
        for label, fn in self.items:
            try:
                s = fn()
            except Exception:
                continue
            if s != self.sigs.get(label):
                self.sigs[label] = s
                changed.append(label)
        return changed

    def run(self):
        self._rebuild()
        self.engine.status["watch"] = {"paths": len(self.items), "last_trigger": "", "pending": 0}
        while True:
            t0 = time.time()
            changed = self.poll()
            now = time.time()
            for c in changed:
                self.pending.setdefault(c, now)
                self.last_change = now
            ws = self.engine.status["watch"]
            ws.update(paths=len(self.items), pending=len(self.pending), cost_ms=int((time.time() - t0) * 1000))
            if self.pending:
                first = min(self.pending.values())
                quiet = now - self.last_change >= self.debounce
                if (quiet or now - first >= self.max_wait) and not self.engine.status["running"]:
                    trig = sorted(self.pending, key=self.pending.get)
                    self.pending = {}
                    ws["last_trigger"] = "%s（%s）" % (time.strftime("%H:%M:%S"), "、".join(trig[:3]))
                    print("[watch] 偵測到變動：%s → 執行快速掃描" % "、".join(trig), flush=True)
                    self.engine.scan("quick", source="watch", trigger=trig, online=False)  # 不連網，幾秒內完成
            time.sleep(self.interval)
