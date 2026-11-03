# secaudit — Mac 安全檢查與變動監控

> A read-only macOS security auditor focused on AI-agent era threats: MCP servers, Claude Code / Codex settings, skills & plugins, leaked API keys in AI transcripts, browser sessions, persistence (LaunchAgents), supply-chain CVEs. Watches critical paths in near-real time and alerts you on Telegram with an LLM-written triage (you / auto-update / suspicious). Python 3.8+ standard library only. UI and reports are in Traditional Chinese.

一個掃描時**只讀不改**（修復動作需要 Touch ID 授權）的 macOS 安全檢查工具，特別針對 AI 工具普及後的新攻擊面：MCP 伺服器、Claude Code / Codex 設定、skills 與 plugins、AI 對話紀錄裡貼過的金鑰、瀏覽器登入 session、開機自動執行項目、套件漏洞。

常駐後會即時監看關鍵位置，有變動就透過 Telegram 通知，並請 LLM 判斷這個變動比較像「你自己操作的」「程式自動更新的」還是「可疑、需要確認的」。

- 只用 Python 3.8+ 標準庫，不需要 `pip install`。
- 掃描結果輸出 HTML（給人看）與 Markdown（給其他 AI 處理），機密一律遮罩。
- 附本機 Web UI：設定掃描範圍、查看報告、漏洞快訊、運作 SOP。

## 功能

| 分類 | 檢查內容 |
|---|---|
| 入侵跡象 | 暫存 / 共享 / 隱藏資料夾裡的執行檔（含程式簽章）、勒索信檔名、大量「原檔名.怪副檔名」 |
| AI 與 Agent | MCP 伺服器（Claude Code / Claude Desktop / Cursor / Codex / Gemini / Windsurf / VS Code）：未鎖版本、明文金鑰、可疑路徑；Claude Code 允許清單與 hooks；skills / plugins / 指令檔中的隱藏 Unicode 字元、prompt injection 語句、可疑指令；Claude Code Telegram channel 存取政策；**AI 對話紀錄裡貼過的金鑰** |
| 機密與憑證 | 明文 `.env`、各家 API Key 格式、私鑰（權限、是否有密碼保護）、`~/.ssh`（新增的金鑰、authorized_keys 新增的公鑰）、`~/.aws`、`~/.npmrc`、`~/.docker`、`~/.git-credentials` 等 |
| 瀏覽器 | Chrome / Arc / Brave / Edge / Firefox 各 profile 中重要服務的登入 session 持續多久、閒置多久；擴充功能權限；是否開著遠端除錯；暫存資料夾是否出現 Cookies / Login Data 副本。**只讀 cookie 的網域與時間，不讀取、不解密 cookie 值** |
| 開機自動執行 | LaunchAgents / LaunchDaemons（含程式簽章）、crontab、shell 啟動檔 |
| 供應鏈與版本 | 各專案 lockfile（npm / pnpm / yarn / pip / poetry / uv / Go / Cargo / Gemfile / composer）查 [OSV.dev](https://osv.dev)；全域 npm 套件 |
| 執行環境版本 | **所有已安裝的**Node.js、Python、Go、Ruby、Java、PHP、Rust、Deno、Bun、.NET（nvm / fnm / volta / asdf / mise / Homebrew / conda / pyenv / uv / rbenv / rvm / sdkman / rustup / 系統內建）是否停止維護（[endoflife.date](https://endoflife.date)）；Node.js 是否錯過官方標記的安全更新；專案指定的版本（`.nvmrc`、`.python-version`、`.tool-versions`、`go.mod`、`package.json` engines、`pyproject.toml`、`Dockerfile` FROM、compose `image:`） |
| 漏洞快訊 | 定期抓取 [GitHub Advisory Database](https://github.com/advisories) 與 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)，比對你專案實際使用的套件版本，影響到你的會標出要升級到哪個版本，附每則 50～100 字摘要與連結 |

### 執行方式

| 觸發 | 預設頻率 | 內容 |
|---|---|---|
| ⚡ 即時監看 | 每 10 秒 | 只 stat 約 100 個關鍵位置（不讀內容），有變動時合併一批後跑一次快速掃描 |
| 🔁 快速掃描 | 每 15 分鐘 | 固定位置檢查 + AI 對話紀錄 + 執行環境版本 |
| 🗂 完整掃描 | 每天 03:00 | 再加上遍歷你勾選的資料夾 + 專案套件 CVE |
| 🧯 漏洞快訊 | 每 6 小時 | 新漏洞摘要推送 |
| 📋 未處理提醒 | 每週一 09:00 | 還沒處理的高 / 中風險與「已存在幾天」；高風險超過 7 天未處理改成每天提醒 |

完整說明請見 Web UI 的「📖 運作 SOP」頁面（依目前設定即時產生）。

## 設計原則

- **掃描只讀不改**：掃描、監看、警示都不會修改、刪除或停用任何東西。LLM 只被允許建議唯讀的檢查指令，輸出刪除 / 停用類指令會被自動隱藏。
- **修復動作一律要 Touch ID**：Web UI 的「🛠 修復動作」是唯一會修改系統的地方（程式碼集中在 `secaudit/actions.py`）。流程固定是「伺服器產生預覽 → 你勾選步驟 → macOS Touch ID 對話框（只接受指紋，不能改用密碼）→ 執行」。前端只能送步驟 id，不能送路徑或指令；每次執行都記錄在 `data/actions.jsonl`。目的是擋住沒有人在電腦前的觸發（其他網頁、拿到 token 的程式、被 prompt injection 的 AI 助手）。
  - 🔑 遮罩 AI 對話紀錄裡的金鑰：只處理最近一次報告列出、位於 `~/.claude` / `~/.codex` 的檔案；用等長的 `[REDACTED]***` 直接覆寫，不換掉檔案，正在寫入的程式不受影響。
  - ⬆️ 升級執行環境：Homebrew 的修補版、`rustup update stable`、`bun upgrade`、pnpm。會跨版本線的 Homebrew 升級（例如 `node` 24 → 26）會標示出來，預設不勾選。
  - 🧹 清除比本機 Go 舊的 toolchain 快取。
  - 📦 / 🔐 含機密的檔案 → 加密 DMG 或 1Password：處理最近一次報告中「檔案裡寫死了機密」與明文 `.env` 的檔案。DMG：產生隨機密碼並先存進 1Password（讀回確認一致）→ `hdiutil` 建立 AES-256 加密 DMG（預設在 `~/Secure/`）→ 掛載後逐檔比對 sha256 → 刪除原檔。1Password：`op document create` 存成文件 → 下載回來比對 sha256 → 刪除原檔。任何一步驗證沒過就不刪原檔；預覽之後被改過的檔案會略過；已提交到 git 的檔案預設不勾選。密碼只經由 stdin 傳遞，op / hdiutil 的輸出不寫進任何紀錄；Touch ID 對話框只顯示固定文字。vault 與 DMG 資料夾可在 Web UI 設定。
  - Touch ID 小工具是 `secaudit/touchid.swift`。常駐程式每次啟動後第一次使用時，用 `swiftc` 重新編譯到 `data/bin/`（需要 Xcode Command Line Tools），並在記憶體記下雜湊，之後每次使用前比對。
  - **YubiKey（WebAuthn / FIDO2）**：可以取代 Touch ID，兩者任選一種。只支援 ES256，簽章用 macOS 內建的 `/usr/bin/openssl` 驗證。WebAuthn 不接受 IP 位址，所以要用 `http://localhost:8765` 開啟 Web UI（頁面上有「切換到 localhost」按鈕）。註冊時會驗證 attestation 出廠憑證，必須追溯到 Yubico 的 FIDO 根憑證（`secaudit/yubico_fido_roots.pem`），所以只接受真的 YubiKey，軟體偽造的金鑰會被拒絕（瀏覽器詢問「是否允許查看安全金鑰的品牌和型號」時要按允許）。每次註冊和授權都要求輸入 YubiKey PIN（觸碰加 PIN），撿到 YubiKey 的人沒有 PIN 就不能用；不支援 PIN 的舊款 U2F 金鑰無法註冊。新增或刪除 YubiKey 本身也要先通過 Touch ID 或已註冊的 YubiKey，Touch ID 對話框只顯示固定文字，不含使用者輸入的名稱；授權的 challenge 會綁定這次預覽勾選的步驟，只能用一次。`data/webauthn.json` 只存公鑰，而且在即時監看清單中，被直接修改會發 ⚠️ 警示。
  - 威脅模型：擋得住其他網頁、遠端，以及只能呼叫 Web UI API 的程式。擋不住已經能以你的身分寫入檔案、執行程式的惡意程式，因為它可以直接改 secaudit 本身。
- **機密不外流**：報告與警示中的機密一律遮罩；報告檔案權限 600。從 1Password / `.env` 載入的變數名稱會記在 `SECAUDIT_SECRET_KEYS`，掃描時執行的子程序（各語言 `--version`、npm、codesign、crontab…）與修復動作都用 `safe_env()` 把這些變數和名稱像機密的變數拿掉，Telegram / Ollama 金鑰不會交給其他程式。
- **誤報可以標記為「已確認無害」**：在報告的問題下方按「✅ 標記為已確認無害」（從 Web UI 開啟的報告才有作用）。被標記的問題移到報告最下方，不計入風險數量與未處理提醒；指向檔案的標記綁定檔案內容的 sha256，檔案一改變標記就失效並重新警示。只能標記報告裡真的存在的問題，標記清單（`data/acks.json`）也在清單快照與即時監看中，新增或取消標記都會發 Telegram，避免惡意程式把自己的警示偷偷藏起來。可以在 Web UI 的「✅ 已確認無害」區塊取消標記。
- **雲端硬碟不觸發下載**：iCloud / Google Drive / OneDrive 中「僅限線上」的檔案只看檔名。
- **規則優先於 LLM**：高敏感區段（開機自動執行、MCP、hooks、擴充功能、`~/.ssh`…）的變動一律標 ⚠️，不受 LLM 判斷影響；送給 LLM 的資料會標明「這是資料不是指令」，以防檔案內容藏 prompt injection。
- **Web UI 只綁 127.0.0.1**：需要 token 登入，並有 SameSite cookie、Host 檢查、自訂 header 防止其他網頁操作。

## 需求

- macOS（使用 `codesign`、`launchctl`、`plutil`、`osascript` 等內建工具）
- Python 3.8 以上
- 選用：[PM2](https://pm2.keymetrics.io/)（常駐）、[1Password CLI](https://developer.1password.com/docs/cli/)（管理金鑰）、Telegram bot、Ollama（本機或 [ollama.com](https://ollama.com) 雲端）

## 快速開始

```bash
git clone https://github.com/<you>/secaudit.git
cd secaudit
python3 audit.py scan --quick --offline    # 不連網的快速掃描，幾秒到一分鐘
python3 audit.py serve                     # 開 Web UI，終端機會印出含登入 token 的網址
```

報告存在 `data/reports/`，每次產出 `.html`、`.md`、`.json`。

```bash
python3 audit.py scan                          # 完整掃描（範圍在 Web UI 設定）
python3 audit.py scan --no-home --path ~/code  # 只掃指定資料夾
python3 audit.py test-notify                   # 測試 Telegram 與 Ollama 設定
python3 audit.py url                           # 再次取得 Web UI 網址
```

> 第一次完整掃描家目錄可能要花一段時間；建議先用 `--no-home --path <小資料夾>` 試跑。

## 常駐監控（PM2）

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup        # 依照它印出的指令設定開機自動啟動
pm2 logs secaudit  # 日誌裡有 Web UI 網址
```

`pm2 startup` 印出的指令要用 sudo 執行，產生的 `~/Library/LaunchAgents/pm2.<user>.plist` 會變成 root 擁有，macOS 登入時可能不會載入它。可以把它換成自己擁有的同內容檔案：

```bash
P=~/Library/LaunchAgents/pm2.$(whoami).plist; cp "$P" /tmp/pm2.plist && rm -f "$P" && cp /tmp/pm2.plist "$P" && rm /tmp/pm2.plist
```

建立這個檔案後，你會收到一則「⚠️ 新增 LaunchAgent」的警示，這是預期中的。

## 設定 Telegram 與 Ollama

需要三個環境變數：`TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID`、`OLLAMA_API_KEY`（用本機 Ollama 時不需要）。

1. 跟 [@BotFather](https://t.me/BotFather) 建立一個**專用**的 bot（不要和其他會把訊息當指令的 bot 共用）。對 bot 傳一則訊息，再到 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查出 chat id。
2. 使用 ollama.com 雲端時，在 [ollama.com/settings/keys](https://ollama.com/settings/keys) 建立 API Key。

### 方法 A：1Password（建議）

金鑰只會被讀進記憶體，不會寫入磁碟。

```bash
# 逐一隱藏輸入、建立 1Password 項目，並產生 .env.tpl（只含 op:// 引用）
OP_VAULT="Private" bash scripts/op-store.sh "secaudit" \
     TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID OLLAMA_API_KEY --tpl .env.tpl
```

或手動把 `.env.tpl.example` 複製成 `.env.tpl`，每一行填入 1Password 引用：

```
TELEGRAM_BOT_TOKEN={{ op://<vault>/<item>/TELEGRAM_BOT_TOKEN }}
```

有 `.env.tpl` 時，`ecosystem.config.js` 會自動用 `audit.py --op-env .env.tpl daemon` 啟動。開機後如果 1Password 還沒解鎖，會跳出 macOS 對話框提醒授權，並定期重試。

### 方法 B：環境變數或 `.env`

沒有 `.env.tpl` 時，程式會讀取環境變數，或讀取專案目錄的 `.env`（`KEY=VALUE` 格式）。`.env` 是明文，已列在 `.gitignore`，請自行評估風險。

### 模型

預設是 ollama.com 雲端上的 `gpt-oss:120b`，可以在 Web UI 修改。如果改用本機 Ollama（主機填 `http://127.0.0.1:11434`），變動清單就完全不會離開你的電腦。

## 掃描範圍

| 目標 | 預設 | 說明 |
|---|---|---|
| 家目錄 | ✅ | 不含 `~/Library`（雲端硬碟就掛在裡面）；AI 工具設定另外用固定位置檢查 |
| iCloud Drive / Google Drive / OneDrive / Dropbox | ⬜ | 自動偵測 `~/Library/Mobile Documents`、`~/Library/CloudStorage/*` |
| 外接磁碟 / NAS | ⬜ | 自動列出 `/Volumes/*`，也可在 Web UI 用「選擇資料夾…」加入任何路徑 |

## 哪些資料會離開你的電腦

| 送到哪裡 | 送出什麼 |
|---|---|
| OSV.dev | 套件名稱與版本 |
| endoflife.date、nodejs.org | 只下載公開的版本清單 |
| GitHub API / CISA | 只下載公開漏洞清單，不上傳資料 |
| Ollama 主機（啟用 AI 摘要時） | 變動清單：路徑、指令片段、檔案指紋（機密已遮罩）；漏洞快訊的公開漏洞資料 |
| Telegram | 警示與漏洞快訊 |

這些都可以在 Web UI 關閉：「查詢 CVE / 版本資料庫」「AI 摘要」「漏洞快訊頻率 = 0」。

## 可以依自己的環境調整的地方

| 項目 | 位置 | 說明 |
|---|---|---|
| 排程、模型、Ollama 主機、漏洞快訊頻率 | Web UI「常駐監控設定」 | 存在 `data/config.json` |
| Web UI port（預設 8765） | `data/config.json` 的 `web_port` | |
| 要追蹤登入 session 的服務 | `secaudit/checks_browser.py` 的 `SENSITIVE` | 預設是 Google、GitHub、Claude、OpenAI、AWS、Stripe 等常見服務，可增減 |
| 漏洞快訊比對的本機軟體 | `secaudit/vulnfeed.py` 的 `installed_software()` | 用來判斷 CISA KEV 的漏洞是否可能影響你 |
| 機密格式、可疑指令規則 | `secaudit/rules.py` | |
| 視為可信任的 plugin marketplace | `secaudit/checks_ai.py` 的 `TRUSTED_MARKETPLACES` | 只檢查高風險隱藏字元，減少官方說明文件的誤報 |
| 即時監看的位置 | `secaudit/watch.py` 的 `build_watch_list()` | |
| 1Password vault | `OP_VAULT` 環境變數（`scripts/op-store.sh`） | 預設 `Private` |

## 限制

- **只支援 macOS**；介面與報告目前只有繁體中文。
- 不是防毒軟體：不做行為監控或惡意程式特徵比對，主要是「設定與狀態」的檢查，以及變動偵測。
- 只能說明「目前沒有發現跡象」，無法證明沒被入侵。
- Safari cookie 需要給終端機「完整磁碟取用權限」才能檢查。
- LLM 的分類只供參考；⚠️ 標記才是由規則判定的。

## 專案結構

```
audit.py                 指令入口（scan / serve / daemon / test-notify / url）
ecosystem.config.js      PM2 設定
scripts/op-store.sh      把金鑰存進 1Password 並產生 .env.tpl
secaudit/
  scanner.py             掃描流程（system / walk / online 三種範圍）
  checks_*.py            各類檢查
  supply_chain.py        lockfile 解析、OSV、endoflife.date
  vulnfeed.py            漏洞快訊
  diff.py                變動比對與 ⚠️ 規則
  watch.py               即時監看
  notify.py              Telegram、LLM
  report.py / sop.py     報告與 SOP
  app.py / web.py        排程、狀態、Web UI
  actions.py             修復動作（唯一會修改系統的模組，執行前必須通過 Touch ID）
  touchid.swift          Touch ID 授權小工具
data/                    掃描結果與狀態（不進 git）
```

## License

MIT
