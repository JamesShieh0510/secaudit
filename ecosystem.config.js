// PM2 設定：pm2 start ecosystem.config.js && pm2 save
// 有 .env.tpl 時：用 1Password CLI（op inject）把機密讀進記憶體，不會在磁碟產生 .env。
// 沒有 .env.tpl 時：從環境變數或專案目錄的 .env 讀取（明文，請自行評估風險）。
const fs = require("fs");
const path = require("path");
const useOp = fs.existsSync(path.join(__dirname, ".env.tpl"));

module.exports = {
  apps: [
    {
      name: "secaudit",
      cwd: __dirname,
      script: "audit.py",
      interpreter: "python3",
      args: useOp ? "--op-env .env.tpl daemon" : "daemon",
      autorestart: true,
      restart_delay: 60000,      // 1Password 授權失敗時程式不會結束（會自己跳提醒重試），這裡只處理其他意外狀況
      max_restarts: 100000,      // 不放棄重試，解鎖後就會自動跑起來
      min_uptime: 60000,
      env: { PYTHONUNBUFFERED: "1", SECAUDIT_DATA: path.join(__dirname, "data") },
    },
  ],
};
