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

    B += [("h", "1. 什麼時候會執行"),
          ("table", ["觸發方式", "頻率", "做什麼"], [
              ["⚡ 即時監看", ("每 %d 秒" % wi) if watch_on else "（已關閉）",
               "檢查約 100 個關鍵位置（開機自動執行、AI 設定、~/.ssh、/Users/Shared、瀏覽器擴充功能…）的檔案大小、修改時間、inode（不讀內容）。發現不一樣時，"
               "等 20 秒沒有新變動（最久 90 秒）再跑一次「不連網的快速掃描」，把同一批變動合併成一則通知。"],
              ["🔁 快速掃描", "每 %d 分鐘" % q, "固定位置檢查 + AI 對話紀錄 + 執行環境版本。"],
              ["🗂 完整掃描", "每天 %02d:00" % h, "快速掃描的全部內容 + 遍歷你勾選的資料夾 + 專案套件 CVE 查詢。"
               "常駐程式第一次啟動時也會先做一次，建立比對基準。"],
              ["🧯 漏洞快訊", ("每 %d 小時" % cfg.get("vulnfeed_hours", 6)) if cfg.get("vulnfeed_hours", 6) else "（已關閉）",
               "抓取 GitHub Advisory Database 與 CISA KEV 的新漏洞，比對你專案的套件版本與本機軟體；"
               "有影響到你的會以 🔴 標出要升級到哪個版本，再推送 Telegram 摘要。"],
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
              ["入侵跡象：暫存 / 共享 / 隱藏資料夾裡的執行檔（含簽章檢查）", "✅", "✅", "✅"],
              ["勒索軟體跡象：勒索信檔名、大量「原檔名.怪副檔名」", "桌面、文件、下載、圖片", "桌面、文件、下載、圖片", "＋所有勾選的資料夾（含 NAS）"],
              ["瀏覽器登入 session、擴充功能、遠端除錯、cookie 外流跡象", "✅", "✅", "✅"],
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

    B += [("h", "3. 每次掃描後的處理流程"),
          ("ol", ["把結果和上一次比對：清單快照（MCP、LaunchAgent、擴充功能…）的新增、移除、修改，以及新出現或已解決的問題。"
                  "比對時忽略單純的修改時間變化，只看內容雜湊、大小、權限與指令。",
                  "依規則標記 ⚠️：高敏感區段（開機自動執行、MCP、hooks、允許清單、shell 啟動檔、擴充功能、Telegram 設定…）"
                  "的新增或修改，以及新的高 / 中風險問題。這個標記不受 AI 判斷影響。",
                  ("請 AI（%s）把每個變動分成 A 你本人操作 / B 程式自動更新 / C 可疑。AI 只能建議唯讀的檢查指令，"
                   "若輸出刪除或停用類指令會被自動隱藏。" % model) if llm else "AI 摘要已關閉。",
                  "有變動才發 Telegram；沒有變動不會打擾你。",
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
              ["中", "攻擊者容易利用的設定（權限過寬、未鎖版本的 MCP、長期未用的登入 session、高權限擴充功能）", "本週"],
              ["低", "最佳實務建議（版本小落後、檔案權限、一般擴充功能）", "有空時"],
              ["資訊", "清單，請確認你都認得（例如所有 LaunchAgent）", "掃過一遍即可"],
          ])]

    B += [("h", "6. 收到 Telegram 警示時怎麼做"),
          ("ol", ["先看「⚡ 即時監看觸發」和 ⚠️ 項目：是不是你剛剛做的操作（安裝工具、改設定、裝擴充功能）？是的話就不用處理。",
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
        elif k in ("ul", "ol"):
            p.append("<%s>%s</%s>" % (k, "".join("<li>%s</li>" % esc(x) for x in b[1]), k))
        elif k == "table":
            p.append("<table><tr>%s</tr>%s</table>" % (
                "".join("<th>%s</th>" % esc(c) for c in b[1]),
                "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc(c) for c in r) for r in b[2])))
    p.append("</details>")
    return "".join(p)
