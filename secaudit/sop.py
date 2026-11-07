"""程式運作 SOP：依目前設定產生，附在每份報告後面。

內容以區塊表示，Markdown 與 HTML 共用同一份來源，避免兩邊說法不一致：
  ("h", 標題) / ("p", 段落) / ("ul", [項目]) / ("ol", [步驟]) / ("table", [欄位], [[列]])
"""


def build_sop(cfg: dict, targets: list):
    q = cfg.get("quick_interval_min", 15)
    h = cfg.get("full_scan_hour", 3)
    watch_on = cfg.get("watch_enabled", True)
    wi = cfg.get("watch_interval_sec", 10)
    online = cfg.get("online", True)
    llm = cfg.get("llm_enabled", True)
    host = cfg.get("ollama_host", "https://ollama.com")
    model = cfg.get("ollama_model", "gpt-oss:120b")
    enabled = [t for t in targets if t.get("enabled")]
    tlist = "、".join("%s（%s）" % (t["label"], t.get("display") or t["path"]) for t in enabled) or "（沒有勾選任何資料夾）"

    B = []
    B += [("h", "這份報告怎麼來的：程式運作 SOP"),
          ("p", "本工具只讀不改：不會修改、刪除或停用任何檔案與設定，所有「建議」都需要你自己決定是否執行。"
                "以下內容依照目前的設定自動產生。")]

    off = lambda on, txt: txt if on else "（已關閉）"
    vh = cfg.get("vulnfeed_hours", 6)
    rem = "每週%s %02d:00" % ("一二三四五六日"[cfg.get("reminder_weekday", 0)], cfg.get("reminder_hour", 9))
    B += [("mermaid", "流程圖：什麼時候檢查、發現變動後怎麼處理", "\n".join([
        "flowchart TD",
        '  W["⚡ 即時監看<br>%s"]' % off(watch_on, "每 %d 秒看關鍵位置" % wi),
        '  R["📈 資源監控<br>%s"]' % off(cfg.get("resource_monitor", True), "每 60 秒取樣 CPU / 記憶體"),
        '  Q["🔁 快速掃描<br>每 %d 分鐘"]' % q,
        '  F["🗂 完整掃描<br>每天 %02d:00"]' % h,
        '  M["👆 手動<br>Web UI 按鈕"]',
        '  W -->|"有變動，等 20 秒合併"| QS',
        '  R -->|"異常 / 新常駐程式"| QS',
        '  Q --> QS',
        '  M --> QS',
        '  M --> FS',
        '  F --> FS',
        '  QS["快速掃描<br>固定位置 + AI 對話紀錄 + 執行環境"]',
        '  FS["完整掃描<br>＋ 遍歷勾選的資料夾 ＋ 專案套件 CVE"]',
        '  FS --> IP["💤 判斷閒置專案"]',
        '  QS --> CMP{"和上一次比對<br>有變動嗎？"}',
        '  IP --> CMP',
        '  CMP -->|沒有| S1["只更新狀態<br>不打擾你"]',
        '  CMP -->|有| RULE["規則標 ⚠️<br>高敏感區段、新的高 / 中風險"]',
        '  RULE --> AI["%s"]' % ("AI 分類<br>A 你本人操作 / B 自動更新 / C 可疑" if llm else "（AI 摘要已關閉）"),
        '  AI --> OUT["📋 存報告 ＋ 📱 Telegram 通知"]',
        '  V["🧯 漏洞快訊<br>%s"] -->|"影響你的套件"| OUT' % off(vh, "每 %s 小時" % vh),
        '  D["📋 未處理提醒<br>%s"] --> YOU' % off(cfg.get("reminder_enabled", True), rem),
        '  OUT --> YOU(["你：看下面的處理流程"])',
    ])),
          ("mermaid", "流程圖：收到通知之後", "\n".join([
        "flowchart TD",
        '  A(["📱 收到 Telegram"]) --> B{"是你剛剛做的操作嗎？<br>安裝工具、改設定、自己開的程式"}',
        '  B -->|是| OK["不用處理<br>可在報告標記「已確認無害」"]',
        '  B -->|不確定 / 不是| C["打開報告看細節<br>時間、由誰啟動、簽章、位置"]',
        '  C --> D{"AI 怎麼分類？"}',
        '  D -->|"A / B"| E["多半沒事<br>用報告裡的唯讀指令確認來源"]',
        '  D -->|"C 可疑"| G["先不要刪除<br>記下路徑與時間"]',
        '  G --> H{"確認是惡意的？"}',
        '  H -->|是| I["停用移除 → 從乾淨裝置換密碼、登出 session<br>撤銷 API 金鑰 → 跑一次完整掃描"]',
        '  H -->|不確定| J["把報告的 .md 交給 AI 或資安人員判斷"]',
        '  C --> K{"有對應的修復動作？"}',
        '  K -->|有| L["🛠 處理頁籤：預覽 → 勾選<br>→ Touch ID 授權 → 執行"]',
        '  K -->|"專案已閒置"| P["📦 整個專案封存成加密 DMG<br>密碼存 1Password"]',
    ]))]

    B += [("h", "1. 什麼時候會執行"),
          ("table", ["觸發方式", "頻率", "做什麼"], [
              ["⚡ 即時監看", ("每 %d 秒" % wi) if watch_on else "（已關閉）",
               "檢查約 100 個關鍵位置（開機自動執行、AI 設定、~/.ssh、/Users/Shared、瀏覽器擴充功能…）的檔案大小、修改時間、inode（不讀內容）。發現不一樣時，"
               "等 20 秒沒有新變動（最久 90 秒）再跑一次「不連網的快速掃描」，把同一批變動合併成一則通知。"],
              ["🔁 快速掃描", "每 %d 分鐘" % q, "固定位置檢查 + AI 對話紀錄 + 執行環境版本。"],
              ["🗂 完整掃描", "每天 %02d:00" % h, "快速掃描的全部內容 + 遍歷你勾選的資料夾 + 專案套件 CVE 查詢。"
               "常駐程式第一次啟動時也會先做一次，建立比對基準。最後判斷有問題的專案是不是已經閒置。"],
              ["🧯 漏洞快訊", ("每 %d 小時" % cfg.get("vulnfeed_hours", 6)) if cfg.get("vulnfeed_hours", 6) else "（已關閉）",
               "抓取 GitHub Advisory Database 與 CISA KEV 的新漏洞，比對你專案的套件版本與本機軟體；"
               "有影響到你的會以 🔴 標出要升級到哪個版本，再推送 Telegram 摘要。"],
              ["📈 資源監控", "每 60 秒" if cfg.get("resource_monitor", True) else "（已關閉）",
               "取樣整台 CPU、記憶體壓力、swap 和所有程式的清單（只看 ps 資訊，不讀程式內容）。"
               "發現新出現的常駐程式（第一次見到、已執行超過 5 分鐘）、某個程式連續 10 分鐘吃滿 CPU、"
               "你沒在用電腦時整台持續高 CPU、記憶體壓力或 swap 暴增，就記錄事件並立刻跑一次不連網的快速掃描，再推送 Telegram。"
               "第一次啟動時先把目前所有程式記成基準，不發通知。"],
              ["📋 未處理提醒", ("每週%s %02d:00" % ("一二三四五六日"[cfg.get("reminder_weekday", 0)], cfg.get("reminder_hour", 9)))
               if cfg.get("reminder_enabled", True) else "（已關閉）",
               "列出還沒處理的高 / 中風險問題與「已存在幾天」，依嚴重程度 × 天數排序；"
               "有高風險超過 %d 天未處理時，改成每天提醒直到處理完。漏洞快訊中影響你專案的套件也會留在清單裡，直到升級。"
               % cfg.get("escalate_days", 7)],
              ["👆 手動", "Web UI 或指令", "手動掃描預設不發 Telegram（Web UI 可勾選要不要發）。"],
          ])]

    B += [("h", "1-1. 開機後的 1Password 授權"),
          ("ol", ["登入 macOS 後，PM2 自動啟動 secaudit，secaudit 向 1Password 要求讀取 Telegram / Ollama 金鑰。",
                  "如果 1Password 還沒解鎖或你沒有按 Touch ID：跳出「secaudit：需要 1Password 授權」對話框，"
                  "按「立即授權」會馬上再試一次；按「稍後」或 10 分鐘沒回應，會在 5 → 10 → 15 → 30 分鐘（之後每 30 分鐘）再提醒。",
                  "等待授權期間不會掃描，也無法發 Telegram（金鑰就在 1Password 裡）。",
                  "授權成功後會發一則 Telegram 告訴你「等了幾次才授權」，接著的快速掃描會比對等待期間發生的所有變動。"])]

    B += [("h", "2. 快速掃描與完整掃描的差別"),
          ("table", ["檢查項目", "即時監看觸發", "快速掃描", "完整掃描"], [
              ["MCP 伺服器、Claude Code 允許清單與 hooks、skills / plugins、AI 指令檔、Telegram channel", "✅", "✅", "✅"],
              ["LaunchAgents / LaunchDaemons（含程式簽章）、crontab、shell 啟動檔", "✅", "✅", "✅"],
              ["~/.ssh（新增的金鑰檔、authorized_keys 新增的公鑰）、~/.aws、~/.npmrc、~/.docker、~/.git-credentials 等憑證檔", "✅", "✅", "✅"],
              ["~/.ssh/config 會執行指令或開通道的設定（ProxyCommand、LocalCommand、RemoteForward、Match exec…）；"
               "macOS「遠端登入」（SSH 伺服器）有沒有開", "✅", "✅", "✅"],
              ["入侵跡象：暫存 / 共享 / 隱藏資料夾裡的執行檔（含簽章檢查）", "✅", "✅", "✅"],
              ["勒索軟體跡象：勒索信檔名、大量「原檔名.怪副檔名」", "桌面、文件、下載、圖片", "桌面、文件、下載、圖片", "＋所有勾選的資料夾（含 NAS）"],
              ["瀏覽器登入 session、擴充功能、遠端除錯、cookie 外流跡象", "✅", "✅", "✅"],
              ["CPU / 記憶體異常、新出現的常駐程式（讀取資源監控 24 小時內的事件）", "✅", "✅", "✅"],
              ["AI 對話紀錄裡有沒有貼過金鑰（只重掃有變動的檔案）", "✅", "✅", "✅"],
              ["所有已安裝的執行環境（Node.js、Python、Go、Ruby、Java、PHP、Rust、Deno、Bun、.NET；"
               "nvm / Homebrew / conda / pyenv / uv / rbenv / rustup / asdf…）是否停止維護；Node.js 是否錯過官方標記的安全更新", "—",
               "✅" if online else "（已關閉）", "✅" if online else "（已關閉）"],
              ["全域 npm 套件 CVE", "—", "✅" if online else "（已關閉）", "✅" if online else "（已關閉）"],
              ["遍歷勾選的資料夾：明文 .env、金鑰、私鑰、專案層級 AI 設定", "—", "—", "✅"],
              ["各專案 lockfile 的套件漏洞（OSV.dev）", "—", "—", "✅" if online else "（已關閉）"],
              ["專案指定的執行環境版本：.nvmrc、.python-version、.tool-versions、go.mod、package.json engines、"
               "pyproject.toml、Dockerfile FROM、docker-compose image 等是否停止維護", "—", "—", "✅" if online else "（已關閉）"],
              ["一般耗時", "數秒", "數秒～1 分鐘", "依資料夾大小，數十秒到數十分鐘"],
          ]),
          ("p", "完整掃描目前的範圍：" + tlist),
          ("ul", ["「家目錄」不含 ~/Library，所以不包含 iCloud / Google Drive / OneDrive；雲端硬碟要另外勾選。",
                  "雲端「僅限線上」的檔案只看檔名，不讀內容，不會觸發下載。",
                  "會略過 node_modules、.git、虛擬環境、快取等大型資料夾，以及超過 1MB 的檔案和二進位檔。"])]

    B += [("h", "2-1. 資源監控怎麼判斷要不要通知"),
          ("ul", ["由誰啟動：沿著父程式往上找。從終端機、Claude Code / Codex / Cursor、ssh / tmux 或 PM2 開的算「你開的」，"
                  "只記在報告裡、不推播。",
                  "Apple 簽章的系統程式不會因為吃 CPU 被通報（例如 WindowServer、Spotlight 建索引）。",
                  "🔴 高：執行檔已經被刪除，或沒有正式簽章（ad-hoc / 未簽章）＋ 放在暫存 / 共享 / 隱藏資料夾 ＋ 不是你開的；"
                  "或是不認得的程式在你沒用電腦時持續吃滿 CPU（挖礦常見）。",
                  "🟠 中：沒有正式簽章、位置可疑，或是 osascript / python / curl / shell 這類常被濫用的工具，而且不是你開的；"
                  "以及你閒置時整台 CPU 10 分鐘平均超過 50%、記憶體壓力持續偏高。",
                  "🟡 低：其他第一次出現的背景程式（例如 App 自己的輔助程式、Ollama 載入模型），swap 突然增加 4 GB 以上。",
                  "ssh / scp / sftp / rsync 也算常被濫用的工具：不是你開的、在背景長時間執行就是中風險；"
                  "帶 -R（反向通道）、-D、-L、-w 這類開通道參數的 ssh 直接是高風險。",
                  "對外連線（約每 5 分鐘）：不是你開的常被濫用工具（ssh、curl、nc、python…）或沒有正式簽章的程式，"
                  "持續 5 分鐘以上連到外部 IP，會記在報告裡（目前只記錄、不推播）。只看得到你自己帳號的程式。",
                  "同一個程式的同一種事件 6 小時內只通知一次；事件在報告裡保留 24 小時，過期不會發「已解決」。",
                  "想確認監控有沒有在跑：執行 python3 audit.py resources，會列出最後一次取樣時間和最近的事件。"])]

    B += [("h", "2-2. 💤 閒置專案"),
          ("ul", ["完整掃描（和重新檢查）結束時，把有問題的檔案依所在專案分組（git 根目錄，或有 package.json、go.mod 等設定檔的資料夾）。",
                  "git 專案的最後活動：最後一次「真的改程式」的 commit（只動 CI 設定、.env 範本、lockfile、.npmrc 的維護 commit 不算），"
                  "以及目前和 git 不一樣的檔案（沒 commit 的修改、新檔案）的修改時間。沒有改動的檔案不看修改時間，"
                  "因為 checkout / reset / rebase 會改掉它；checkout 這類 git 操作本身也不算。不是 git 的專案看檔案修改時間，"
                  "node_modules、建置輸出、lockfile、.env*、CI 設定、secaudit 處理紀錄、封存產生的 .archive-日期.dmg / .md 這類常被工具或修復動作改動的檔案不算。"
                  "修復動作改過的檔案會記下內容雜湊（data/touched.json），內容還是修復時那樣就不算你在開發；你一改就照常算。",
                  "超過 %d 天沒有更新、而且現在沒有程式（終端機、編輯器、dev server）開在裡面，就列在報告的「💤 閒置專案」，"
                  "問題旁邊也會標「💤 專案閒置 N 天」。天數可以在「常駐監控設定」修改。" % cfg.get("idle_project_days", 30),
                  "「📦 批次封存成加密 DMG」：每個專案在旁邊（同一層資料夾）產生一個 AES-256 加密、壓縮的 DMG，密碼存進 1Password。"
                  "唯讀掛載後逐檔比對 sha256，再確認原資料夾在這段期間沒有被改過，全部一致才刪除原資料夾。"
                  "預覽之後專案有更新、或有程式開在裡面，都不會處理。雲端硬碟裡只在雲端的檔案，會在封存前自動下載（下載不到就不封存）。"
                  "預覽依位置分類（iCloud、外接磁碟、~/projects…），可以整類勾選。需要 Touch ID 授權。",
                  "~/.lmstudio 這類家目錄底下的隱藏資料夾是工具自己管理的，不會被當成專案。"
                  "雲端硬碟裡的專案只看修改時間，不執行 git 指令（git 會讀檔案內容，會觸發下載）。",
                  "還原：雙擊 DMG、輸入 1Password「secaudit 封存專案：路徑」項目裡的密碼，把檔案複製回原本位置。"])]

    from .actions import ARCHIVE_WORKERS as _aw, DOWNLOAD_WORKERS as _dw
    B += [("h", "2-3. 修復動作留下的處理紀錄"),
          ("ul", ["每次修復動作處理了某個檔案，都會在那個資料夾留下 secaudit-處理紀錄.md（同一個資料夾的紀錄會一直往後加），"
                  "寫明處理前、處理後、怎麼還原，以及依據哪份報告、用什麼授權。",
                  "閒置專案封存的紀錄放在 DMG 旁邊，檔名和 DMG 相同（專案名稱.archive-日期.md）。",
                  "紀錄不含任何機密值（金鑰都已遮罩），也不含 DMG 密碼；之後找檔案或交給 AI 時，可以從這裡知道當時怎麼處理的。",
                  "批次封存閒置專案時，最多 %d 個專案同時封存；雲端專案在背景先下載（同時 %d 個），下載完再排進封存。"
                  "按下執行後，會先為每個勾選的專案在 1Password 建立 DMG 密碼並讀回確認（這幾分鐘請留在電腦前，"
                  "看到 1Password 的授權視窗請按允許）；全部建好後發 Telegram 通知，之後的下載、建立 DMG、驗證、刪除都不需要你在場，"
                  "完成後再通知一次。封存失敗的專案留下的 1Password 項目，備註會寫明可以刪除。" % (_aw, _dw),
                  "卡住偵測：建立 / 掛載 DMG 時每 5 秒檢查 hdiutil 的 CPU 與輸出檔大小，連續 10 分鐘（掛載 5 分鐘）沒有變化就自動終止並重試一次，"
                  "還是不行就標成失敗、資料夾保留，worker 繼續處理下一個。畫面上任何一行超過 5 分鐘沒有進度會標紅。",
                  "執行被中斷或有項目沒處理時，到「🛠 處理」→「📜 執行紀錄」按「🔁 再執行一次」，會重新預覽還沒處理的項目。"])]

    B += [("h", "2-5. 📦 依專案整理的供應鏈問題"),
          ("ul", ["報告的「📦 依專案」頁籤把套件漏洞、專案指定的執行環境版本，依所在專案（git 根目錄）合併，風險高的專案排前面。",
                  "每個專案有「📋 複製給 AI Agent」：複製一段修復指示（漏洞清單、要升級到的最小版本、怎麼驗證、"
                  "用 bash ~/op-env-run.sh -e 執行、先不要 commit），貼給那個專案的 AI 就能直接開始；也可以下載成 .md。"])]

    B += [("h", "2-4. 寫死的機密 → 1Password + .env.tpl"),
          ("ul", ["依照 ~/projects/ENV_1PASSWORD_GUIDE.md：值放進 1Password vault「Dev Env」（每個專案一筆 env | ~/<專案>/.env），"
                  "專案的 .env.tpl 加上 op:// 引用；明文 .env 整份轉成 .env.tpl，op inject 還原後逐字比對一致才刪除原檔。",
                  "Python / JS / TS / Go / shell / docker compose / 文件裡「整個字串就是機密」的寫法，自動改成讀環境變數並做語法檢查；"
                  "其他情況只搬值，改法寫在處理紀錄。改寫前原檔存成 1Password 文件，還原只要一行 op document get。",
                  "處理後執行專案要用 bash ~/op-env-run.sh -e <指令>；專案根目錄的 secaudit-處理紀錄.md 寫了 pm2、docker、CI、VS Code 怎麼調整，以及怎麼還原。",
                  "預覽依處理方式分類；「含機密的檔案」預覽裡，App 自己的憑證、本機開發帳密、第三方範例這幾類可以整類標記為已確認無害。",
                  "修復動作一次只跑一個；跑的時候可以把下一個動作「排入佇列」（排隊時就授權），前一個完成後自動開始，在「📜 執行紀錄」可以取消排隊。"])]

    B += [("h", "3. 每次掃描後的處理流程"),
          ("ol", ["把結果和上一次比對：清單快照（MCP、LaunchAgent、擴充功能…）的新增、移除、修改，以及新出現或已解決的問題。"
                  "比對時忽略單純的修改時間變化，只看內容雜湊、大小、權限與指令。",
                  "依規則標記 ⚠️：高敏感區段（開機自動執行、MCP、hooks、允許清單、shell 啟動檔、擴充功能、Telegram 設定…）"
                  "的新增或修改，以及新的高 / 中風險問題。這個標記不受 AI 判斷影響。",
                  ("請 AI（%s）把每個變動分成 A 你本人操作 / B 程式自動更新 / C 可疑。AI 只能建議唯讀的檢查指令，"
                   "若輸出刪除或停用類指令會被自動隱藏。" % model) if llm else "AI 摘要已關閉。",
                  "有變動才發 Telegram；沒有變動不會打擾你。",
                  "你在報告中標記為「已確認無害」的問題會移出風險清單；指向檔案的標記綁定檔案內容，檔案一改變標記就失效並重新警示。"
                  "標記清單本身也受監看，新增或移除標記都會列為 ⚠️ 變動。",
                  "產出三份報告：.html（給你看，可直接下載 Markdown）、.md（給其他 AI 處理）、.json（原始資料）。"
                  "排程與即時監看的快速掃描若沒有變動，只更新狀態、不另存報告。報告保留 %d 天，完整掃描保留 %d 天。"
                  % (cfg.get("report_keep_days", 30), cfg.get("full_report_keep_days", 90))])]

    B += [("h", "4. 哪些資料會離開這台電腦"),
          ("table", ["送到哪裡", "送出什麼", "不會送出"], [
              ["OSV.dev（Google 維護的漏洞資料庫）" if online else "OSV.dev（已關閉）", "套件名稱與版本", "程式碼、路徑、專案名稱"],
              ["endoflife.date、nodejs.org" if online else "endoflife.date、nodejs.org（已關閉）", "只下載公開的版本清單", "你的版本號與路徑"],
              [("Ollama（%s）" % host) if llm else "Ollama（已關閉）", "變動清單：路徑、指令片段、檔案指紋（機密已遮罩）", "檔案內容、完整機密值"],
              ["GitHub API / CISA（漏洞快訊）", "只有下載公開漏洞清單，不上傳任何資料", "—"],
              ["Telegram", "警示摘要、漏洞快訊", "完整機密值"],
          ]),
          ("ul", ["Telegram 與 Ollama 的金鑰由 1Password 載入記憶體，不寫入磁碟。",
                  "瀏覽器 cookie 只讀網域與時間，絕不讀取或解密 cookie 值。",
                  "報告中的機密一律遮罩（例如 sk-ant****a1b2）；報告檔案權限為 600（只有你能讀）。"])]

    B += [("h", "5. 風險等級的意思"),
          ("table", ["等級", "意思", "建議處理時間"], [
              ["高", "已經外洩、可被直接利用，或疑似已被入侵（明文金鑰、惡意套件、可疑的開機自動執行、隱藏位置的未簽章程式、勒索信）", "今天；勒索跡象請立刻中斷網路"],
              ["（版本問題）", "執行環境 / 映像停止維護：有已公開漏洞的證據（例如錯過官方安全更新、套件有 CVE）才算高風險，單純停止維護算中風險", "—"],
              ["中", "攻擊者容易利用的設定（權限過寬、未鎖版本的 MCP、長期未用的登入 session、高權限擴充功能）", "本週"],
              ["低", "最佳實務建議（版本小落後、檔案權限、一般擴充功能）", "有空時"],
              ["資訊", "清單，請確認你都認得（例如所有 LaunchAgent）", "掃過一遍即可"],
          ])]

    B += [("h", "6. 收到 Telegram 警示時怎麼做"),
          ("ol", ["先看「⚡ 即時監看觸發」和 ⚠️ 項目：是不是你剛剛做的操作（安裝工具、改設定、裝擴充功能）？是的話就不用處理。",
                  "收到「新出現的常駐程式」或「程式持續大量使用 CPU」：看細節裡的啟動時間、由誰啟動、簽章和位置。"
                  "是你剛開的程式就不用處理；不認得的，先記下路徑再結束它，並檢查 LaunchAgent / LaunchDaemon 有沒有新的自動執行項目。",
                  "看 AI 的分類：B（程式自動更新）通常沒事，但仍可用報告中的唯讀指令確認來源。",
                  "C（可疑）或你完全不認得的變動：先不要刪除，用報告裡的唯讀指令查看內容、程式簽章與修改時間，"
                  "記下路徑與時間（之後追查需要）。",
                  "確認是惡意的：停用並移除該項目 → 從另一台乾淨的裝置更換重要帳號密碼、登出所有瀏覽器 session、"
                  "撤銷並重新產生 API 金鑰 → 跑一次完整掃描確認沒有其他殘留。",
                  "不確定時，把這份報告的 .md 檔交給其他 AI 或資安人員協助判斷（機密已遮罩）。"])]
    return B


# ---------------------------------------------------------------- render
def to_md(blocks):
    out = []
    for b in blocks:
        k = b[0]
        if k == "h":
            out += ["## " + b[1] if b[1].startswith("這份") else "### " + b[1], ""]
        elif k == "p":
            out += [b[1], ""]
        elif k == "ul":
            out += ["- " + x for x in b[1]] + [""]
        elif k == "ol":
            out += ["%d. %s" % (i + 1, x) for i, x in enumerate(b[1])] + [""]
        elif k == "mermaid":
            out += ["**%s**" % b[1], "", "```mermaid", b[2], "```", ""]
        elif k == "table":
            cell = lambda s: str(s).replace("|", "\\|")
            out += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])]
            out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in b[2]] + [""]
    return "\n".join(out)


def to_html(blocks, esc, open_=True):
    p = ['<details class="sop"%s><summary><h2 style="display:inline">%s</h2></summary>' % (" open" if open_ else "", esc(blocks[0][1]))]
    for b in blocks[1:]:
        k = b[0]
        if k == "h":
            p.append("<h3>%s</h3>" % esc(b[1]))
        elif k == "p":
            p.append('<p class="muted">%s</p>' % esc(b[1]))
        elif k == "mermaid":
            # Web UI 會用內建的 Mermaid 畫成圖；離線打開報告時顯示原始碼（也可以貼到任何支援 Mermaid 的編輯器）
            p.append('<div class="mmd"><b>%s</b><pre class="mermaid" style="white-space:pre-wrap;font-size:12px">%s</pre>'
                     '<div class="muted mmd-note" style="font-size:12px">這是 Mermaid 流程圖原始碼，在 Web UI 的「📖 運作 SOP」頁籤會顯示成圖。</div></div>'
                     % (esc(b[1]), esc(b[2])))
        elif k in ("ul", "ol"):
            p.append("<%s>%s</%s>" % (k, "".join("<li>%s</li>" % esc(x) for x in b[1]), k))
        elif k == "table":
            p.append("<table><tr>%s</tr>%s</table>" % (
                "".join("<th>%s</th>" % esc(c) for c in b[1]),
                "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc(c) for c in r) for r in b[2])))
    p.append("</details>")
    return "".join(p)
