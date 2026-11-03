// secaudit 修復動作的 Touch ID 授權小工具。
// 用法：touchid "<顯示在系統對話框的原因>"   → 結束碼 0 = 通過，1 = 取消 / 失敗 / 逾時，2 = 這台 Mac 現在不能用 Touch ID
//      touchid --check                      → 只檢查能不能用 Touch ID，不跳出對話框
// 只接受生物辨識（Touch ID / Apple Watch 不算），不提供「改用密碼」的退路：修改系統的動作必須有人實際按下指紋。
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
let args = CommandLine.arguments
let ctx = LAContext()
ctx.localizedFallbackTitle = ""   // 隱藏「輸入密碼」按鈕
var err: NSError?

guard ctx.canEvaluatePolicy(policy, error: &err) else {
    FileHandle.standardError.write(("unavailable: " + (err?.localizedDescription ?? "unknown") + "\n").data(using: .utf8)!)
    exit(2)
}
if args.count > 1 && args[1] == "--check" {
    print("ok")
    exit(0)
}

let reason = args.count > 1 ? args[1] : "授權 secaudit 修改這台 Mac"
let sem = DispatchSemaphore(value: 0)
var passed = false
var message = ""
ctx.evaluatePolicy(policy, localizedReason: reason) { ok, e in
    passed = ok
    message = e?.localizedDescription ?? ""
    sem.signal()
}
if sem.wait(timeout: .now() + 120) == .timedOut {
    ctx.invalidate()
    FileHandle.standardError.write("timeout\n".data(using: .utf8)!)
    exit(1)
}
if passed {
    print("ok")
    exit(0)
}
FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
exit(1)
