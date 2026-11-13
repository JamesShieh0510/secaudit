"""把 GitHub 監控（ghwatch）累積的警示轉成報告裡的問題。

實際抓 GitHub 的動作在常駐排程的背景執行緒跑（ghwatch.poll），這裡只讀結果，所以掃描不會被網路拖慢；
抓取暫時失敗時，之前的警示仍會繼續列出（不會被誤判成「已解決」）。
"""
import time

from . import ghwatch
from .core import Finding, ScanContext

CAT = "GitHub 監控"


def check_github(ctx: ScanContext, cfg=None):
    if cfg is None:
        from .app import load_config
        cfg = load_config()
    gw = cfg.get("github_watch") or {}
    accounts = [a for a in gw.get("accounts") or [] if a.get("login")]
    # 監控設定也列入清單快照：有人把某個組織拿掉、或整個關掉，會被當成變動通知
    ctx.inv("GitHub 監控設定", "（總開關）", "開啟" if gw.get("enabled") else "關閉")
    for a in accounts:
        ctx.inv("GitHub 監控設定", a["login"], "%s：%s" % ("開啟" if a.get("enabled", True) else "停用",
                                                         "、".join(a.get("owners") or []) or "（沒有指定組織）"))
    _githook_findings(ctx)
    if not gw.get("enabled") or not accounts:
        return
    st = ghwatch.load_alerts()
    marks = ghwatch.load_marks()
    now = time.time()
    n_auto = n_manual = 0
    for key, a in sorted(st["alerts"].items(), key=lambda kv: -kv[1].get("last", 0)):
        state, info = ghwatch.alert_state(key, a, marks)
        if state == "manual":
            # 手動標記也列入清單快照：有人把警示標掉會被當成變動通知（避免惡意程式偷偷消警示）
            n_manual += 1
            ctx.inv("GitHub 監控手動標記", key[:200], "%s：%s" % ({"fixed": "已處理", "false_positive": "誤判"}.get(info.get("kind"), ""),
                                                            info.get("note") or "（沒有備註）"))
            continue
        if state == "auto":
            n_auto += 1
            continue
        detail = a.get("detail", "")
        if a.get("count", 1) > 1:
            detail += "（累計 %d 次，最近一次 %s）" % (a["count"], time.strftime("%m-%d %H:%M", time.localtime(a["last"])))
        if (a.get("check") or {}).get("note"):
            detail += "\n目前狀態：" + a["check"]["note"]
        ctx.add(Finding(rule=a.get("rule", "gh-alert"), severity=a.get("severity", "medium"), category=CAT,
                        title=a.get("title", key), path=a.get("path", ""), detail=detail.strip(),
                        evidence=a.get("evidence", ""), why=a.get("why", ""), fix=a.get("fix", "")))
    if n_auto or n_manual:
        ctx.add(Finding(rule="gh-resolved", severity="info", category=CAT,
                        title="GitHub 監控：%d 筆警示已處理完畢（自動確認 %d、手動標記 %d）" % (n_auto + n_manual, n_auto, n_manual),
                        detail="自動確認：攻擊用的分支已刪除、workflow 已還原、PR 已關閉、協作者已移除等。同一個 repo 之後再有新動靜，會重新列出。",
                        fix="到 🐙 GitHub 頁籤勾「顯示已處理」可以看到每一筆的處理原因，也可以撤銷。"))
    s = st.get("status") or {}
    for err in s.get("errors") or []:
        ctx.add(Finding(rule="gh-watch-error", severity="medium", category=CAT, title="GitHub 監控無法完整執行：" + err[:160],
                        why="這段期間這個帳號 / 組織沒有被監控。",
                        fix="確認 gh auth status 顯示這個帳號已登入、token 有 repo 與 read:org 權限；或在 1Password 設定 GH_TOKEN_<帳號>。"))
    interval = max(5, int(gw.get("interval_min") or 15))
    if s.get("at") and now - s["at"] > max(3 * interval * 60, 3600):
        ctx.add(Finding(rule="gh-watch-stale", severity="medium", category=CAT,
                        title="GitHub 監控已經 %d 分鐘沒有更新" % int((now - s["at"]) / 60),
                        why="常駐程式可能卡住或網路中斷，這段時間沒有在監控。", fix="到 ⚙️ 設定 → GitHub 監控按「立即檢查」看錯誤訊息。"))


def _githook_findings(ctx):
    """git pull / clone 時 hook 發現的問題（最近 14 天），以及 hook 有沒有裝好。"""
    from . import githook
    seen = set()
    for r in reversed(githook.load_recent(14)):
        for i in r.get("items") or []:
            key = (r.get("repo"), i.get("title"))
            if key in seen:
                continue
            seen.add(key)
            ctx.add(Finding(rule="gh-pull-" + ("high" if i.get("severity") == "high" else "medium"), severity=i.get("severity", "medium"),
                            category=CAT, title="git %s：%s" % ("clone" if r.get("old") == "0" * 40 else "pull", i.get("title", "")),
                            path=r.get("repo", ""),
                            detail="%s %s 拉下來的改動（%s..%s，來源 %s）。%s" % (
                                time.strftime("%m-%d %H:%M", time.localtime(r.get("t", 0))), r.get("hook", ""),
                                (r.get("old") or "")[:8], (r.get("new") or "")[:8], r.get("remote", ""), i.get("detail", "")),
                            evidence=i.get("evidence", ""),
                            why="這些位置的內容會在 npm install、打開 VS Code 或 CI 觸發時自動執行。",
                            fix="確認這些改動是誰、為什麼加的（git log -p 看完整內容）；不認得就先不要執行，並通知 repo 的管理者。"))
    st = githook.status()
    ctx.inv("GitHub 監控設定", "git pull 檢查（全域 hook）", "已安裝" if st["installed"] else "未安裝（core.hooksPath=%s）" % (st["hooksPath"] or "未設定"))
    if not st["installed"]:
        ctx.add(Finding(rule="gh-pull-hook-missing", severity="info", category=CAT, title="git pull 檢查沒有安裝",
                        detail="目前全域 core.hooksPath：%s" % (st["hooksPath"] or "未設定"),
                        why="安裝後每次 git pull / clone 都會檢查拉下來的 workflow、安裝腳本、VS Code 自動執行設定。",
                        fix="執行 python3 audit.py git-hooks 安裝（python3 audit.py git-hooks --uninstall 可移除）。"))
