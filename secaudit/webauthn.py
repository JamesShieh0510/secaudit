"""YubiKey（WebAuthn / FIDO2）授權：只用標準庫，簽章交給 macOS 內建的 /usr/bin/openssl 驗證。

- 只支援 ES256（ECDSA P-256），所有 FIDO2 / U2F YubiKey 都支援。
- WebAuthn 不接受 IP 位址當 RP ID，所以 RP ID 固定是 localhost，Web UI 要用 http://localhost:<port> 開啟。
- 每一把金鑰的公鑰存在 data/webauthn.json（權限 600）；私鑰永遠不會離開 YubiKey。
- 註冊 / 刪除金鑰本身也是修改授權設定，必須先通過 Touch ID 或已註冊的 YubiKey（由 actions.py 負責）。
"""
import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import tempfile
import threading
import time

from .app import DATA, _read, _write_private

RP_ID = "localhost"
STORE = os.path.join(DATA, "webauthn.json")
CHALLENGE_TTL = 180
_lock = threading.Lock()
_challenges = {}      # challenge(b64url) -> {"purpose", "binding", "created"}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- 最小 CBOR 解碼（WebAuthn 只用到這些型別）
def _cbor(b, i=0):
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        val = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        val = int.from_bytes(b[i:i + n], "big")
        i += n
    else:
        raise ValueError("不支援的 CBOR 長度")
    if mt == 0:
        return val, i
    if mt == 1:
        return -1 - val, i
    if mt == 2:
        return bytes(b[i:i + val]), i + val
    if mt == 3:
        return b[i:i + val].decode("utf-8"), i + val
    if mt == 4:
        out = []
        for _ in range(val):
            x, i = _cbor(b, i)
            out.append(x)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(val):
            k, i = _cbor(b, i)
            v, i = _cbor(b, i)
            out[k] = v
        return out, i
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(ai), i
    raise ValueError("不支援的 CBOR 型別")


def _parse_auth_data(ad):
    if len(ad) < 37:
        raise ValueError("authenticatorData 太短")
    rp_hash, flags, count = ad[:32], ad[32], struct.unpack(">I", ad[33:37])[0]
    out = {"rp_hash": rp_hash, "up": bool(flags & 1), "uv": bool(flags & 4), "count": count}
    if flags & 0x40:   # attested credential data
        i = 37 + 16
        n = struct.unpack(">H", ad[i:i + 2])[0]
        i += 2
        out["cred_id"] = ad[i:i + n]
        out["cose"], _ = _cbor(ad, i + n)
    return out


def _cose_to_pem(cose):
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ValueError("只支援 ES256（P-256）金鑰")
    x, y = cose[-2], cose[-3]
    if len(x) != 32 or len(y) != 32:
        raise ValueError("公鑰長度錯誤")
    der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + x + y
    body = base64.b64encode(der).decode()
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % "\n".join(body[i:i + 64] for i in range(0, len(body), 64))


def _verify_sig(pem, sig, data):
    with tempfile.TemporaryDirectory(prefix="secaudit-wa-") as d:
        paths = {}
        for name, content in (("p.pem", pem.encode()), ("s.bin", sig), ("d.bin", data)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "wb") as fh:
                fh.write(content)
        r = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify", paths["p.pem"], "-signature", paths["s.bin"],
                            paths["d.bin"]], capture_output=True, text=True, timeout=20, env={"PATH": "/usr/bin:/bin"})
        return r.returncode == 0 and "Verified OK" in r.stdout


def _client_data(cdj_b64, typ, challenge, origin):
    raw = unb64u(cdj_b64)
    cd = json.loads(raw.decode("utf-8"))
    if cd.get("type") != typ:
        raise ValueError("clientData 類型錯誤")
    if cd.get("challenge") != challenge:
        raise ValueError("challenge 不符")
    if cd.get("origin") != origin:
        raise ValueError("來源不符（請用 %s 開啟 Web UI）" % origin)
    return raw


# ---------------------------------------------------------------- challenge
def issue(purpose, binding):
    c = b64u(secrets.token_bytes(32))
    with _lock:
        now = time.time()
        for k in [k for k, v in _challenges.items() if now - v["created"] > CHALLENGE_TTL]:
            del _challenges[k]
        _challenges[c] = {"purpose": purpose, "binding": binding, "created": now}
    return c


def _consume(c, purpose, binding):
    with _lock:
        ent = _challenges.pop(c, None)
    if not ent or ent["purpose"] != purpose or ent["binding"] != binding or time.time() - ent["created"] > CHALLENGE_TTL:
        raise ValueError("授權請求已過期或不符，請重新操作")


# ---------------------------------------------------------------- 金鑰清單
def keys():
    return _read(STORE, {}).get("keys", [])


def public_keys():
    return [{"id": k["id"], "name": k["name"], "created": k["created"], "last_used": k.get("last_used", "")} for k in keys()]


def _save(ks):
    _write_private(STORE, {"keys": ks})


def creation_options(port):
    """新增金鑰：回傳 navigator.credentials.create 的參數（二進位欄位用 base64url）。"""
    return {"challenge": issue("register", ""), "rp": {"id": RP_ID, "name": "secaudit"},
            "user": {"id": b64u(hashlib.sha256(b"secaudit-local-user").digest()[:16]), "name": "secaudit", "displayName": "secaudit"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"authenticatorAttachment": "cross-platform", "userVerification": "discouraged",
                                       "residentKey": "discouraged"},
            "excludeCredentials": [{"type": "public-key", "id": k["id"]} for k in keys()],
            "attestation": "none", "timeout": 60000}


def request_options(purpose, binding):
    """授權：回傳 navigator.credentials.get 的參數。沒有註冊任何金鑰時回傳 None。"""
    ks = keys()
    if not ks:
        return None
    return {"challenge": issue(purpose, binding), "rpId": RP_ID, "userVerification": "discouraged", "timeout": 60000,
            "allowCredentials": [{"type": "public-key", "id": k["id"]} for k in ks]}


def check_registration(reg, port):
    """驗證 navigator.credentials.create 的結果，回傳要存的金鑰資料（還沒存）。"""
    origin = "http://localhost:%d" % port
    cdj = _client_data(reg.get("clientDataJSON", ""), "webauthn.create", reg.get("challenge", ""), origin)
    _consume(reg.get("challenge", ""), "register", "")
    att, _ = _cbor(unb64u(reg.get("attestationObject", "")))
    ad = _parse_auth_data(att["authData"])
    if ad["rp_hash"] != hashlib.sha256(RP_ID.encode()).digest():
        raise ValueError("RP ID 不符")
    if not ad["up"] or "cred_id" not in ad:
        raise ValueError("金鑰沒有確認使用者在場（需要觸碰 YubiKey）")
    del cdj
    return {"id": b64u(ad["cred_id"]), "pem": _cose_to_pem(ad["cose"]), "count": ad["count"],
            "name": (str(reg.get("name") or "YubiKey").strip() or "YubiKey")[:40], "created": time.strftime("%Y-%m-%d %H:%M")}


def add_key(entry):
    ks = [k for k in keys() if k["id"] != entry["id"]]
    ks.append(entry)
    _save(ks)


def remove_key(kid):
    ks = keys()
    left = [k for k in ks if k["id"] != kid]
    _save(left)
    return len(left) != len(ks)


def verify_assertion(asr, purpose, binding, port):
    """驗證 navigator.credentials.get 的結果。通過回傳金鑰名稱，失敗丟 ValueError。"""
    origin = "http://localhost:%d" % port
    c = asr.get("challenge", "")
    cdj = _client_data(asr.get("clientDataJSON", ""), "webauthn.get", c, origin)
    _consume(c, purpose, binding)
    ks = keys()
    k = next((x for x in ks if x["id"] == asr.get("id")), None)
    if not k:
        raise ValueError("這把金鑰沒有註冊")
    ad_raw = unb64u(asr.get("authenticatorData", ""))
    ad = _parse_auth_data(ad_raw)
    if ad["rp_hash"] != hashlib.sha256(RP_ID.encode()).digest():
        raise ValueError("RP ID 不符")
    if not ad["up"]:
        raise ValueError("沒有觸碰 YubiKey")
    if not _verify_sig(k["pem"], unb64u(asr.get("signature", "")), ad_raw + hashlib.sha256(cdj).digest()):
        raise ValueError("簽章驗證失敗")
    if ad["count"] and k.get("count") and ad["count"] <= k["count"]:
        raise ValueError("簽章計數器沒有增加，可能是複製的金鑰")
    k["count"] = ad["count"]
    k["last_used"] = time.strftime("%Y-%m-%d %H:%M")
    _save(ks)
    return k["name"]
