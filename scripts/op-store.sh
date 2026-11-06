#!/bin/bash
# 把機密存進 1Password，並在 .tpl 檔加上 op:// 引用。vault 預設 Personal，可用 OP_VAULT 指定。
#
# 用法：
#   bash scripts/op-store.sh "<項目標題>" 變數1 變數2 ... [--tpl <範本檔>]
# 例：
#   OP_VAULT="Personal" bash scripts/op-store.sh "secaudit" \
#        TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID OLLAMA_API_KEY --tpl .env.tpl
#
# 安全性：
# - 每個值都用隱藏輸入（read -s），不會出現在畫面、shell history 或指令參數（ps 看不到）。
# - 值經由 stdin 交給 python 組成 JSON，再用 stdin 交給 `op item create -`，全程不寫入檔案。
set -euo pipefail
umask 077

VAULT="${OP_VAULT:-Personal}"
TITLE="${1:?用法：op-store.sh <標題> 變數... [--tpl 檔案]}"
shift
VARS=()
TPL=""
while [ $# -gt 0 ]; do
  case "${1}" in
    --tpl) TPL="${2:?--tpl 需要檔案路徑}"; shift 2 ;;
    *) [[ "${1}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "❌ 變數名稱不合法：${1}"; exit 1; }
       VARS+=("${1}"); shift ;;
  esac
done
[ ${#VARS[@]} -gt 0 ] || { echo "❌ 至少要一個變數名稱"; exit 1; }

if op item get "${TITLE}" --vault "${VAULT}" --format json >/dev/null 2>&1; then
  echo "❌ ${VAULT} 裡已經有「${TITLE}」。請改用 1Password App 編輯，或換一個標題。"
  exit 1
fi

# 逐一隱藏輸入，用 NUL 分隔後交給 python（值不經過指令參數）
PAYLOAD=""
for v in "${VARS[@]}"; do
  read -rsp "輸入 ${v}（不會顯示）： " val; echo
  [ -n "${val}" ] || { echo "❌ ${v} 是空的，已取消"; exit 1; }
  PAYLOAD+="${v}"$'\x1f'"${val}"$'\x1e'
  unset val
done

ID=$(printf '%s' "${PAYLOAD}" | python3 -I -c '
import json, sys
title = sys.argv[1]
fields = []
for rec in sys.stdin.read().split("\x1e"):
    if not rec:
        continue
    k, v = rec.split("\x1f", 1)
    t = "STRING" if k.endswith(("_ID", "_HOST", "_URL", "_MODEL")) else "CONCEALED"
    fields.append({"id": k, "label": k, "type": t, "value": v})
print(json.dumps({"title": title, "category": "API_CREDENTIAL", "fields": fields}))
' "${TITLE}" | op item create --vault "${VAULT}" --format json - | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
unset PAYLOAD

echo "✅ 已建立 1Password 項目：${VAULT} / ${TITLE}（id: ${ID}）"

if [ -n "${TPL}" ]; then
  touch "${TPL}"
  for v in "${VARS[@]}"; do
    if grep -q "^${v}=" "${TPL}"; then
      echo "⚠️ ${TPL} 已有 ${v}，未覆蓋（請手動改成 {{ op://${VAULT}/${ID}/${v} }}）"
    else
      echo "${v}={{ op://${VAULT}/${ID}/${v} }}" >> "${TPL}"
    fi
  done
  echo "✅ 已更新 ${TPL}（只寫入 op:// 引用，沒有明文值）"
fi
