"""YubiKey（WebAuthn / FIDO2）授權：只用標準庫，簽章與憑證鏈交給 macOS 內建的 /usr/bin/openssl 驗證。

- 註冊時一定要有 attestation（packed 或 fido-u2f），而且憑證鏈要能追溯到 Yubico 的 FIDO 根憑證
  （secaudit/yubico_fido_roots.pem）。所以只有真的 YubiKey 才能註冊，軟體偽造的金鑰會被拒絕。
  沒有這一步的話，authenticatorData（包括「有觸碰」旗標）都是用戶端自己填的，伺服器無法分辨。
- 只支援 ES256（ECDSA P-256）。
- 一律要求使用者驗證（YubiKey PIN）：只有觸碰不夠，撿到或偷到 YubiKey 的人沒有 PIN 就不能授權。
  因為註冊的金鑰已經驗證過是真的 YubiKey，authenticatorData 裡的 UV 旗標是 YubiKey 簽章保證的。
  只支援 U2F、不支援 PIN 的舊款金鑰無法註冊。
- WebAuthn 不接受 IP 位址當 RP ID，所以 RP ID 固定是 localhost，Web UI 要用 http://localhost:<port> 開啟。
- data/webauthn.json 只存公鑰（權限 600）；私鑰永遠不會離開 YubiKey。
- 註冊 / 刪除金鑰本身也必須先通過 Touch ID 或已註冊的 YubiKey（由 actions.py 負責）。
"""
import base64
import hashlib
import json
import os
import re
import secrets
import struct
import subprocess
import tempfile
import threading
import time

from .app import DATA, _read, _write_private

RP_ID = "localhost"
STORE = os.path.join(DATA, "webauthn.json")
ROOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yubico_fido_roots.pem")
CHALLENGE_TTL = 180
OPENSSL = "/usr/bin/openssl"
_lock = threading.Lock()
_store_lock = threading.Lock()
_challenges = {}      # challenge(b64url) -> {"purpose", "binding", "created"}
# DER：OID 1.3.6.1.4.1.45724.1.1.4，可能接 critical BOOLEAN，再接 OCTET STRING 包著 16 bytes 的 OCTET STRING
_AAGUID_EXT = re.compile(re.escape(bytes.fromhex("060b2b0601040182e51c010104")) + rb"(?:\x01\x01[\x00\xff])?\x04\x12\x04\x10(.{16})", re.S)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- 最小 CBOR 解碼（WebAuthn 只用到這些型別）
def _cbor(b, i=0, depth=0):
    if depth > 8:
        raise ValueError("CBOR 巢狀太深")
    if i >= len(b):
        raise ValueError("CBOR 資料不完整")
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        val = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if i + n > len(b):
            raise ValueError("CBOR 資料不完整")
        val = int.from_bytes(b[i:i + n], "big")
        i += n
    else:
        raise ValueError("不支援的 CBOR 長度")
    if mt == 0:
        return val, i
    if mt == 1:
        return -1 - val, i
    if mt in (2, 3):
        if i + val > len(b):
            raise ValueError("CBOR 長度超過資料")
        raw = bytes(b[i:i + val])
        return (raw if mt == 2 else raw.decode("utf-8")), i + val
    if mt in (4, 5):
        if val > 64:
            raise ValueError("CBOR 元素太多")
        if mt == 4:
            out = []
            for _ in range(val):
                x, i = _cbor(b, i, depth + 1)
                out.append(x)
            return out, i
        out = {}
        for _ in range(val):
            k, i = _cbor(b, i, depth + 1)
            v, i = _cbor(b, i, depth + 1)
            if isinstance(k, (list, dict)):
                raise ValueError("不支援的 CBOR key")
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
        if len(ad) < 55:
            raise ValueError("authenticatorData 太短")
        out["aaguid"] = ad[37:53]
        n = struct.unpack(">H", ad[53:55])[0]
        if 55 + n > len(ad):
            raise ValueError("credential id 長度錯誤")
        out["cred_id"] = ad[55:55 + n]
        out["cose"], _ = _cbor(ad, 55 + n)
        if not isinstance(out["cose"], dict):
            raise ValueError("公鑰格式錯誤")
    return out


def _cose_xy(cose):
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ValueError("只支援 ES256（P-256）金鑰")
    x, y = cose.get(-2), cose.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
        raise ValueError("公鑰長度錯誤")
    return x, y


def _pem(der, label):
    body = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(body[i:i + 64] for i in range(0, len(body), 64)), label)


def _xy_to_pem(x, y):
    return _pem(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + x + y, "PUBLIC KEY")


def _openssl(args, inputs):
    """在暫存資料夾寫入 inputs（{檔名: bytes}），執行 openssl；回傳 (結束碼, 輸出)。"""
    with tempfile.TemporaryDirectory(prefix="secaudit-wa-") as d:
        for name, content in inputs.items():
            with open(os.path.join(d, name), "wb") as fh:
                fh.write(content)
        argv = [OPENSSL] + [os.path.join(d, a[1:]) if a.startswith("@") else a for a in args]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20, env={"PATH": "/usr/bin:/bin"})
        return r.returncode, r.stdout + r.stderr


def _verify_sig(pem, sig, data):
    code, out = _openssl(["dgst", "-sha256", "-verify", "@p.pem", "-signature", "@s.bin", "@d.bin"],
                         {"p.pem": pem.encode(), "s.bin": sig, "d.bin": data})
    return code == 0 and "Verified OK" in out


def _verify_attestation(att, ad_raw, ad, cdh, x, y):
    """確認是真的 YubiKey：attestation 簽章正確，而且憑證鏈追溯到 Yubico 的 FIDO 根憑證。"""
    fmt, st = att.get("fmt"), att.get("attStmt")
    if fmt == "none" or not isinstance(st, dict):
        raise ValueError("瀏覽器沒有提供金鑰的出廠憑證。請在瀏覽器詢問「是否允許查看安全金鑰的品牌和型號」時按允許")
    x5c = st.get("x5c")
    if not isinstance(x5c, list) or not x5c or not all(isinstance(c, bytes) for c in x5c):
        raise ValueError("缺少出廠憑證（不接受自我簽署的 attestation）")
    sig = st.get("sig")
    if not isinstance(sig, bytes):
        raise ValueError("attestation 缺少簽章")
    if fmt == "packed":
        if st.get("alg") != -7:
            raise ValueError("只支援 ES256 的 attestation")
        signed = ad_raw + cdh
    elif fmt == "fido-u2f":
        signed = b"\x00" + ad["rp_hash"] + cdh + ad["cred_id"] + b"\x04" + x + y
    else:
        raise ValueError("不支援的 attestation 格式：%s" % fmt)
    leaf = _pem(x5c[0], "CERTIFICATE").encode()
    code, leaf_pub = _openssl(["x509", "-in", "@leaf.pem", "-pubkey", "-noout"], {"leaf.pem": leaf})
    if code != 0 or "BEGIN PUBLIC KEY" not in leaf_pub:
        raise ValueError("出廠憑證格式錯誤")
    leaf_pub = leaf_pub[leaf_pub.index("-----BEGIN PUBLIC KEY-----"):]
    if not _verify_sig(leaf_pub, sig, signed):
        raise ValueError("attestation 簽章驗證失敗")
    with open(ROOTS, "rb") as fh:
        roots = fh.read()
    files = {"roots.pem": roots, "leaf.pem": leaf}
    args = ["verify", "-CAfile", "@roots.pem"]
    if len(x5c) > 1:
        files["inter.pem"] = "".join(_pem(c, "CERTIFICATE") for c in x5c[1:]).encode()
        args += ["-untrusted", "@inter.pem"]
    code, out = _openssl(args + ["@leaf.pem"], files)
    if code != 0 or not re.search(r":\s*OK\s*$", out.strip()):
        raise ValueError("這把金鑰的出廠憑證不是 Yubico 簽發的（只接受 YubiKey）")
    code, text = _openssl(["x509", "-in", "@leaf.pem", "-noout", "-text"], {"leaf.pem": leaf})
    if code != 0 or re.search(r"CA\s*:\s*TRUE", text):
        raise ValueError("出廠憑證不能是 CA 憑證")
    # FIDO 的 AAGUID 延伸欄位（1.3.6.1.4.1.45724.1.1.4）：有的話必須和 authenticatorData 的 aaguid 一致
    m = _AAGUID_EXT.search(x5c[0])
    if m and fmt == "packed" and m.group(1) != ad.get("aaguid"):
        raise ValueError("出廠憑證的 AAGUID 和金鑰回報的不一致")
    code, subj = _openssl(["x509", "-in", "@leaf.pem", "-noout", "-subject"], {"leaf.pem": leaf})
    return (subj.split("CN=")[-1].strip() if "CN=" in subj else "")[:80]


def _client_data(cdj_b64, typ, challenge, origin):
    raw = unb64u(cdj_b64)
    cd = json.loads(raw.decode("utf-8"))
    if not isinstance(cd, dict):
        raise ValueError("clientData 格式錯誤")
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
    """只回傳通過 attestation 驗證的金鑰；舊版沒驗證過的金鑰不能用來授權。"""
    return [k for k in _read(STORE, {}).get("keys", []) if k.get("attested")]


def public_keys():
    out = [{"id": k["id"], "name": k["name"], "created": k["created"], "last_used": k.get("last_used", ""),
            "model": k.get("model", ""), "valid": bool(k.get("attested"))} for k in _read(STORE, {}).get("keys", [])]
    return out


def _save(ks):
    _write_private(STORE, {"keys": ks})


def creation_options(port):
    """新增金鑰：回傳 navigator.credentials.create 的參數（二進位欄位用 base64url）。"""
    return {"challenge": issue("register", ""), "rp": {"id": RP_ID, "name": "secaudit"},
            "user": {"id": b64u(hashlib.sha256(b"secaudit-local-user").digest()[:16]), "name": "secaudit", "displayName": "secaudit"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"authenticatorAttachment": "cross-platform", "userVerification": "required",
                                       "residentKey": "discouraged"},
            "excludeCredentials": [{"type": "public-key", "id": k["id"]} for k in keys()],
            "attestation": "direct", "timeout": 60000}


def request_options(purpose, binding):
    """授權：回傳 navigator.credentials.get 的參數。沒有註冊任何金鑰時回傳 None。"""
    ks = keys()
    if not ks:
        return None
    return {"challenge": issue(purpose, binding), "rpId": RP_ID, "userVerification": "required", "timeout": 60000,
            "allowCredentials": [{"type": "public-key", "id": k["id"]} for k in ks]}


def check_registration(reg, port):
    """驗證 navigator.credentials.create 的結果，回傳要存的金鑰資料（還沒存）。任何問題都丟 ValueError。"""
    try:
        origin = "http://localhost:%d" % port
        cdj = _client_data(reg.get("clientDataJSON", ""), "webauthn.create", reg.get("challenge", ""), origin)
        _consume(reg.get("challenge", ""), "register", "")
        att, _ = _cbor(unb64u(reg.get("attestationObject", "")))
        if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
            raise ValueError("attestationObject 格式錯誤")
        ad_raw = att["authData"]
        ad = _parse_auth_data(ad_raw)
        if ad["rp_hash"] != hashlib.sha256(RP_ID.encode()).digest():
            raise ValueError("RP ID 不符")
        if not ad["up"] or "cred_id" not in ad:
            raise ValueError("金鑰沒有回報使用者在場")
        if not ad["uv"]:
            raise ValueError("這把金鑰沒有驗證 PIN。請先替 YubiKey 設定 PIN（瀏覽器通常會提示），或改用支援 FIDO2 的 YubiKey")
        x, y = _cose_xy(ad["cose"])
        model = _verify_attestation(att, ad_raw, ad, hashlib.sha256(cdj).digest(), x, y)
    except ValueError:
        raise
    except Exception as e:      # 惡意或損壞的輸入：一律當作驗證失敗
        raise ValueError("註冊資料格式錯誤（%s）" % type(e).__name__)
    name = re.sub(r"[\x00-\x1f\x7f]", "", str(reg.get("name") or "")).strip()[:40] or "YubiKey"
    return {"id": b64u(ad["cred_id"]), "pem": _xy_to_pem(x, y), "count": ad["count"], "name": name, "model": model,
            "attested": True, "created": time.strftime("%Y-%m-%d %H:%M")}


def add_key(entry):
    with _store_lock:
        ks = [k for k in _read(STORE, {}).get("keys", []) if k["id"] != entry["id"]]
        ks.append(entry)
        _save(ks)


def remove_key(kid):
    with _store_lock:
        ks = _read(STORE, {}).get("keys", [])
        left = [k for k in ks if k["id"] != kid]
        _save(left)
        return len(left) != len(ks)


def find_key(kid):
    """刪除用：包含沒通過驗證的舊金鑰（讓使用者能把它們清掉）。"""
    return next((k for k in _read(STORE, {}).get("keys", []) if k["id"] == kid), None)


def verify_assertion(asr, purpose, binding, port):
    """驗證 navigator.credentials.get 的結果。通過回傳金鑰名稱，任何問題都丟 ValueError。"""
    try:
        origin = "http://localhost:%d" % port
        c = asr.get("challenge", "")
        cdj = _client_data(asr.get("clientDataJSON", ""), "webauthn.get", c, origin)
        _consume(c, purpose, binding)
        ad_raw = unb64u(asr.get("authenticatorData", ""))
        ad = _parse_auth_data(ad_raw)
        if ad["rp_hash"] != hashlib.sha256(RP_ID.encode()).digest():
            raise ValueError("RP ID 不符")
        if not ad["up"]:
            raise ValueError("沒有觸碰 YubiKey")
        if not ad["uv"]:
            raise ValueError("沒有輸入 YubiKey PIN")
        with _store_lock:
            ks = _read(STORE, {}).get("keys", [])
            k = next((x for x in ks if x["id"] == asr.get("id") and x.get("attested")), None)
            if not k:
                raise ValueError("這把金鑰沒有註冊，或是舊版未驗證的金鑰（請重新註冊）")
            if not _verify_sig(k["pem"], unb64u(asr.get("signature", "")), ad_raw + hashlib.sha256(cdj).digest()):
                raise ValueError("簽章驗證失敗")
            # 計數器：只要已經看過大於 0 的值，新的值就必須更大（回到 0 也擋），防止複製的金鑰
            if k.get("count", 0) > 0 and ad["count"] <= k["count"]:
                raise ValueError("簽章計數器沒有增加，可能是複製的金鑰")
            k["count"] = max(ad["count"], k.get("count", 0))
            k["last_used"] = time.strftime("%Y-%m-%d %H:%M")
            _save(ks)
            return k["name"]
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("授權資料格式錯誤（%s）" % type(e).__name__)
