"""偵測規則：機密格式、可疑指令、隱藏字元。"""
import re

# 規則有變動時加 1：AI 對話紀錄等快取會自動失效、重新掃描
RULES_VERSION = 3

# (rule_id, 名稱, regex, severity)
SECRET_RULES = [
    ("anthropic-key", "Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "high"),
    ("openai-key", "OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-)?(?!ant-)[A-Za-z0-9_\-]{32,}"), "high"),
    ("google-api-key", "Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("aws-access-key", "AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("github-token", "GitHub Token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"), "high"),
    ("slack-token", "Slack Token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "high"),
    ("stripe-live", "Stripe Live Key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"), "high"),
    ("telegram-bot", "Telegram Bot Token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"), "high"),
    ("hf-token", "Hugging Face Token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), "high"),
    ("groq-key", "Groq API Key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), "high"),
    # 資料庫 / 訊息佇列連線字串（帳號:密碼@主機）。本機測試用的弱帳密在 find_secrets 裡降為低風險
    ("db-url", "資料庫連線字串（含密碼）", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|clickhouse|cockroachdb|"
        r"oracle|neo4j(?:\+s)?|couchdb|elasticsearch)(?:\+\w+)?://[^\s:/@'\"<>{}]+:[^\s@/'\"<>{}]{3,}@[^\s'\"<>]+"), "high"),
    ("jdbc-password", "JDBC 連線字串（含密碼）", re.compile(r"\bjdbc:\w+:[^\s'\"]*?(?:password|pwd)=[^\s;&'\"]{3,}", re.I), "high"),
    ("slack-webhook", "Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"), "high"),
    ("discord-webhook", "Discord Webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,}/[\w-]{50,}"), "high"),
    # 私鑰：標記後面必須接著金鑰內容（至少 3 行 base64）。只有標記的通常是程式碼或說明文字。
    # 換行可能是真的換行，也可能是 JSON 裡跳脫的 \\n（AI 對話紀錄）
    ("private-key", "私鑰內容", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        r"(?:\\\\r|\\\\n|\\r|\\n|\s)+(?:[A-Za-z0-9+/=]{40,}(?:\\\\r|\\\\n|\\r|\\n|\s)+){3,}"), "high"),
]

# .env 類檔案內「KEY=明文值」的通用規則（只套用在 env 類檔案，避免誤報）
GENERIC_ASSIGN = re.compile(
    r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)S?[A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"'#]{8,})""",
    re.IGNORECASE | re.MULTILINE,
)

PLACEHOLDER_HINTS = ("op://", "${", "{{", "xxxx", "your_", "your-", "example", "changeme",
                     "<", "placeholder", "dummy", "****", "...", "process.env", "os.environ",
                     # 讀環境變數 / 設定的程式碼，不是寫死的值
                     "getenv", "environ", "env(", "env.", "viper.", "config.", "settings.", "secrets.")


def is_placeholder(value: str) -> bool:
    v = value.lower()
    if re.match(r"^[A-Za-z_][\w.]*\(", value):
        return True          # 函式呼叫（例如 rekorSigningKey()、os.Getenv(...)）：是程式碼，不是寫死的值
    return any(h in v for h in PLACEHOLDER_HINTS) or len(set(v)) <= 3


# 可疑指令（用在 shell 啟動檔、hooks、skills、LaunchAgent）
SUSPICIOUS_CMDS = [
    ("curl-pipe-sh", re.compile(r"(?:curl|wget)[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"), "high", "下載後直接執行遠端腳本"),
    ("eval-remote", re.compile(r"eval\s+[\"']?\$\((?:curl|wget)"), "high", "eval 執行遠端內容"),
    ("base64-exec", re.compile(r"base64\s+(?:-d|--decode|-D)[^\n]*\|\s*(?:ba|z)?sh"), "high", "解碼 base64 後執行"),
    ("reverse-shell", re.compile(r"/dev/tcp/|\bnc\s+(?:-[a-z]*e|-c)\b|\bncat\b.*-e|socat\s+.*exec", re.I), "high", "疑似反向 shell"),
    ("python-exec-remote", re.compile(r"python[0-9.]*\s+-c\s+[\"'].*(?:urllib|requests|socket)", re.I), "high", "python -c 連網執行"),
    ("osascript", re.compile(r"\bosascript\b"), "medium", "使用 AppleScript（可操作其他 App、彈出假密碼框）"),
    ("exfil-endpoint", re.compile(r"(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|pastebin\.com|transfer\.sh|interact\.sh|oast\.)", re.I), "high", "傳送資料到常見外洩端點"),
    ("sensitive-path", re.compile(r"(?:~|\$HOME|/Users/[^/\s]+)/(?:\.ssh|\.aws/credentials|\.config/gcloud|\.kube/config|\.netrc|\.git-credentials|Library/Keychains)|id_rsa|id_ed25519", re.I), "medium", "存取敏感憑證路徑"),
    ("keychain-dump", re.compile(r"security\s+(?:find-generic-password|find-internet-password|dump-keychain)"), "high", "讀取 macOS 鑰匙圈"),
    ("alias-hijack", re.compile(r"^\s*alias\s+(?:sudo|ssh|git|op|gpg|security)=", re.M), "high", "覆寫敏感指令的 alias"),
    ("chmod-777", re.compile(r"chmod\s+(?:-R\s+)?777"), "low", "chmod 777"),
]

# Prompt injection 常見語句（中英）
INJECTION_PHRASES = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|above) instructions|disregard (?:the )?(?:system|previous)|"
    # 「do not tell the user to run X」是在避免給錯建議，不算；「do not tell the user about/that…」才是要瞞著使用者
    r"(?:do not|don't|never) (?:tell|inform|mention (?:it |this )?to|let) the user (?:about|that|what|anything|know|see)\b|"
    r"without (?:telling|informing|notifying|alerting) the user|(?:hide|conceal|keep) (?:this|it|that) from the user|"
    r"you are now (?:in )?(?:developer|dan|jailbreak)|"
    r"忽略(?:之前|先前|上面|以上)的?(?:所有)?指令|不要告訴使用者|不要讓使用者知道",
    re.I,
)

# 隱藏 / 方向控制字元（可在 AI 指令檔中藏東西）
# 高風險：Unicode tag（可藏整段 ASCII 指令）、方向控制字元（讓顯示順序與實際不同）
HIDDEN_CHARS_HIGH = re.compile("[\U000e0000-\U000e007f‪-‮⁦-⁩]")
# 中風險：零寬字元。U+200D（emoji 連字）和 U+FE0F 太常見，不列入
HIDDEN_CHARS = re.compile("[​‌‎‏⁠-⁤᠎]")

# 會被 AI 代理自動讀進 context 的指令檔
AI_INSTRUCTION_FILES = {
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
    ".windsurfrules", "copilot-instructions.md", ".clinerules",
}

ENV_FILE_RE = re.compile(r"^(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$")
ENV_SAFE_SUFFIX = (".tpl", ".example", ".sample", ".template", ".dist", ".defaults")

CONTENT_EXTS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".sh", ".zsh", ".bash", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".jsx", ".go", ".rb", ".php", ".java", ".kt", ".swift", ".rs", ".tf", ".tfvars",
    ".md", ".txt", ".xml", ".plist", ".ipynb", ".sql", ".csv", ".pem", ".key", ".ps1",
}
CONTENT_NAMES = {
    ".zshrc", ".bashrc", ".bash_profile", ".profile", ".zprofile", ".zshenv",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", "credentials", "config",
    ".zsh_history", ".bash_history", ".python_history", ".node_repl_history",
    "Dockerfile", "Makefile",
}

PRIVATE_KEY_NAMES = re.compile(r"^(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|.*\.(?:pem|key|p12|pfx|keystore|jks|ppk))$", re.I)
