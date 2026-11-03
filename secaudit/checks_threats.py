"""H. 入侵跡象：可疑位置的執行檔、勒索軟體跡象。"""
import os
import re
import stat

from .core import HOME, Finding, ScanContext, file_fingerprint, home_rel, lstat_safe, is_dataless
from .checks_persistence import _signature

CAT = "入侵跡象"

MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}

# (位置, 遍歷深度, 只看隱藏資料夾/檔案)
ODD_LOCATIONS = [
    ("/tmp", 3, False), ("/private/var/tmp", 3, False), ("/Users/Shared", 3, False),
    ("~/Library/LaunchAgents", 1, False),
    # 只看隱藏資料夾：深度 2 = 隱藏資料夾裡的檔案
    ("~/Library", 2, True), ("~/Library/Application Support", 2, True), ("~/Library/Caches", 2, True),
    ("~/Downloads", 2, True), ("~/Documents", 2, True), ("~/Desktop", 2, True),
    ("~", 1, True),   # 家目錄只看第一層的隱藏檔（.nvm、.cargo 等開發工具資料夾裡本來就有很多執行檔）
]
SKIP_PREFIX = ("/private/tmp/claude-", "/tmp/claude-", "/private/tmp/com.apple", "/tmp/com.apple")
SKIP_NAMES = {".DS_Store", ".localized", ".CFUserTextEncoding", ".zsh_history", ".bash_history", ".viminfo", ".lesshst",
              ".python_history", ".node_repl_history", ".zcompdump", ".wget-hsts", ".Trash", ".zsh_sessions"}


def _exec_kind(path, st):
    """'macho' / 'script' / None（只讀前 4 個 byte 判斷，不讀整個檔案）。"""
    if not stat.S_ISREG(st.st_mode) or is_dataless(st) or st.st_size < 4:
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head in MACHO_MAGIC:
        if head == b"\xca\xfe\xba\xbe" and path.endswith(".class"):
            return None   # Java class 檔與 fat Mach-O 魔數相同
        return "macho"
    if head[:2] == b"#!" and st.st_mode & 0o111:
        return "script"
    return None


def check_odd_executables(ctx: ScanContext):
    ctx.report(CAT, "可疑位置的執行檔")
    seen = 0
    for loc, depth, hidden_only in ODD_LOCATIONS:
        base = os.path.expanduser(loc)
        if not os.path.isdir(base):
            continue
        bdepth = base.rstrip(os.sep).count(os.sep)
        for dp, dns, fns in os.walk(base):
            if dp.startswith(SKIP_PREFIX) or ctx.cancel.is_set():
                dns[:] = []
                continue
            level = dp.count(os.sep) - bdepth
            if hidden_only and level == 0:
                # 只往下看隱藏資料夾（例如 ~/Library/.xyz/），一般 App 資料夾不看
                dns[:] = [d for d in dns if d.startswith(".") and d not in SKIP_NAMES]
                fns = [f for f in fns if f.startswith(".") and f not in SKIP_NAMES]
            dns[:] = [d for d in dns if not d.endswith(".app") and d not in ("node_modules", ".git")]
            if level + 1 >= depth:
                dns[:] = []
            if len(fns) > 3000:
                continue
            for fn in fns:
                p = os.path.join(dp, fn)
                st = lstat_safe(p)
                if st is None:
                    continue
                kind = _exec_kind(p, st)
                if not kind:
                    continue
                seen += 1
                if seen > 300:
                    return
                sig = _signature(p) if kind == "macho" else "script"
                hidden = "/." in p[len(base):] or fn.startswith(".")
                ctx.inv("可疑位置的執行檔", home_rel(p), "%s | sig=%s | %s" % (kind, sig, file_fingerprint(p)))
                if kind == "macho":
                    sev = "high" if sig in ("unsigned", "adhoc") and (hidden or loc in ("/tmp", "/private/var/tmp", "/Users/Shared")) \
                        else "medium" if sig in ("unsigned", "adhoc") else "low"
                    what = "沒有開發者簽章的程式" if sig in ("unsigned", "adhoc") else "程式（簽章：%s）" % sig
                else:
                    sev = "high" if hidden else "medium"
                    what = "可執行腳本"
                ctx.add(Finding(
                    rule="odd-executable", severity=sev, category=CAT,
                    title="%s出現%s" % ("隱藏位置" if hidden else "暫存／共享資料夾", what), path=home_rel(p),
                    evidence="%s, %d bytes" % (kind, st.st_size),
                    why="惡意程式常把自己放在暫存、共享或隱藏資料夾，再用 LaunchAgent 或 cron 定期執行。"
                        "正常的 App 很少把執行檔放在這些地方。",
                    fix="唯讀檢查：codesign -dv '%s'；file '%s'；ls -la@ '%s'（看下載來源屬性）。不認得就移除，"
                        "並檢查是否有 LaunchAgent 指向它。" % (p, p, p)))


# ---------------------------------------------------------------- 勒索軟體跡象
RANSOM_NOTE = re.compile(
    r"(?i)^(?:_readme\.txt|!+\s*read[_\- ]?me\s*!+.*|.*(?:decrypt|ransom|recover[_\- ]?(?:my|your|all)?[_\- ]?files|"
    r"restore[_\- ]?(?:my|your|all)?[_\- ]?files|unlock[_\- ]?(?:my|your)?[_\- ]?files|how[_\- ]?to[_\- ]?(?:back|get|return|recover)|"
    r"your[_\- ]?files[_\- ]?(?:are|were)?[_\- ]?encrypted).*\.(?:txt|html?|hta|rtf|png|url))$")
RANSOM_EXT = {"locked", "encrypted", "crypted", "crypt", "lockbit", "ryk", "wncry", "wcry", "cerber", "locky", "zepto",
              "djvu", "makop", "phobos", "eking", "devos", "dharma", "onion", "rhysida", "akira", "8base", "medusa",
              "kraken", "hive", "conti", "babuk", "lockfile", "encrypt", "enc1", "cryptolocker", "darkness", "nochance"}
DOC_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "jpg", "jpeg", "png", "heic", "txt", "csv", "key",
           "pages", "numbers", "zip", "mp4", "mov", "psd", "ai", "md", "json", "sql"}


class RansomTracker:
    """遍歷時逐檔餵入，結束後彙整：勒索信檔名、大量「原副檔名.怪副檔名」的檔案。"""

    def __init__(self):
        self.notes, self.dirs = [], {}

    def feed(self, dp, fn):
        if RANSOM_NOTE.match(fn):
            self.notes.append(os.path.join(dp, fn))
            return
        parts = fn.lower().rsplit(".", 2)
        if len(parts) == 3 and parts[1] in DOC_EXT and parts[2] not in DOC_EXT:
            ext = parts[2]
            d = self.dirs.setdefault((dp, ext), [0, fn])
            d[0] += 1
        elif len(parts) >= 2 and parts[-1] in RANSOM_EXT:
            d = self.dirs.setdefault((dp, "*" + parts[-1]), [0, fn])
            d[0] += 1

    def report(self, ctx: ScanContext):
        for p in self.notes[:50]:
            ctx.inv("勒索軟體跡象", home_rel(p), "note")
            ctx.add(Finding(
                rule="ransom-note", severity="high", category=CAT, title="發現疑似勒索信的檔案", path=home_rel(p),
                why="勒索軟體加密檔案後，會在每個資料夾留下類似「HOW_TO_DECRYPT.txt」的說明檔。",
                fix="立刻中斷網路（Wi-Fi、拔網路線、退出 NAS 掛載），不要關機、不要付款；"
                    "用另一台裝置查看這個檔案的內容與檔案修改時間，並確認備份是否完好。"))
        by_ext = {}
        for (dp, ext), (n, sample) in self.dirs.items():
            e = by_ext.setdefault(ext, [0, 0, sample, dp])
            e[0] += n
            e[1] += 1
        for ext, (n, ndirs, sample, dp) in by_ext.items():
            known = ext.startswith("*")
            if n < (5 if known else 30) or (not known and ndirs < 3):
                continue
            ctx.inv("勒索軟體跡象", "副檔名 .%s" % ext.lstrip("*"), "%d 個檔案 / %d 個資料夾" % (n, ndirs))
            ctx.add(Finding(
                rule="ransom-ext", severity="high" if known or n >= 100 else "medium", category=CAT,
                title="大量檔案被加上相同的陌生副檔名「.%s」" % ext.lstrip("*"),
                path=home_rel(dp), detail="共 %d 個檔案、分布在 %d 個資料夾，例如：%s" % (n, ndirs, sample),
                why="勒索軟體加密後通常會把「報告.docx」改名成「報告.docx.xxxx」。短時間大量出現就要高度警覺。",
                fix="打開其中一個檔案確認是否還能正常開啟；若不能，立刻中斷網路與 NAS 連線，從備份還原，不要付款。"))


def check_ransom_quick(ctx: ScanContext):
    """快速掃描版：只看常被勒索軟體優先加密的位置（桌面、文件、下載與家目錄第一層），深度 2。"""
    ctx.report(CAT, "勒索軟體跡象")
    t = RansomTracker()
    for loc in ("~", "~/Desktop", "~/Documents", "~/Downloads", "~/Pictures"):
        base = os.path.expanduser(loc)
        if not os.path.isdir(base):
            continue
        bdepth = base.count(os.sep)
        for dp, dns, fns in os.walk(base):
            if loc == "~":
                dns[:] = []
            if dp.count(os.sep) - bdepth >= 1:
                dns[:] = []
            dns[:] = [d for d in dns if not d.startswith(".") and d not in ("node_modules", "Library")]
            for fn in fns:
                t.feed(dp, fn)
    t.report(ctx)
