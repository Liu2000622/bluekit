# -*- coding: utf-8 -*-
"""
TLS 应用数据解密（基于 NSS SSLKEYLOGFILE），把 HTTPS 流量还原为明文 HTTP，
再交给现有 webshell/隧道分析引擎。这样冰蝎/哥斯拉/CS 等走 TLS 的流量不再是盲区。

支持范围（覆盖现代浏览器/工具默认协商的绝大多数套件）：
  - TLS 1.2：ECDHE/DHE/RSA × AES-128/256-GCM、CHACHA20-POLY1305（AEAD 套件）
  - TLS 1.3：AES-128-GCM / AES-256-GCM / CHACHA20-POLY1305

原理与 Wireshark 一致：从 keylog 里按 ClientHello 的 client_random 找到会话密钥
（TLS 1.2 的 master secret / TLS 1.3 的 traffic secret），派生记录层密钥后逐条
AEAD 解密应用数据。AEAD 的认证标签天然校验密钥/序号是否正确，解错必然抛错，
因此不会产出"看似成功实为乱码"的结果。

对外主入口：
  - KeyLog.load(path/text)                : 解析 keylog
  - decrypt_tls_packets(packets, keylog)  : 输入单条 TCP 流的 PacketInfo 列表，
        若为可解密的 TLS 流则返回"解密后的明文 PacketInfo 列表"，否则返回 None。
"""

import hashlib
import hmac
import os
import struct
from collections import OrderedDict
from typing import Dict, List, Optional

from wsat.core.pcap_utils import PacketInfo

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - 缺依赖时优雅降级
    _HAS_CRYPTO = False

try:
    from Crypto.Cipher import PKCS1_v1_5 as _PKCS1_v15
    from Crypto.PublicKey import RSA as _RSA
    _HAS_RSA = True
except Exception:  # pragma: no cover - 缺依赖时优雅降级
    _HAS_RSA = False


# TLS 记录内容类型
_CT_CHANGE_CIPHER_SPEC = 20
_CT_ALERT = 21
_CT_HANDSHAKE = 22
_CT_APPLICATION_DATA = 23

# 握手消息类型
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2
_HS_FINISHED = 20


# 密码套件参数表：suite_id -> (aead, key_len, fixed_iv_len_tls12, hash_mod)
#   aead: "aesgcm" | "chacha"
#   fixed_iv_len_tls12: TLS 1.2 隐式 IV 长度（GCM=4，ChaCha=12）；TLS 1.3 固定用 12
_SUITES = {
    # --- TLS 1.3 ---
    0x1301: ("aesgcm", 16, 12, hashlib.sha256),  # TLS_AES_128_GCM_SHA256
    0x1302: ("aesgcm", 32, 12, hashlib.sha384),  # TLS_AES_256_GCM_SHA384
    0x1303: ("chacha", 32, 12, hashlib.sha256),  # TLS_CHACHA20_POLY1305_SHA256
    # --- TLS 1.2 AES-GCM ---
    0x009C: ("aesgcm", 16, 4, hashlib.sha256),   # RSA_WITH_AES_128_GCM_SHA256
    0x009D: ("aesgcm", 32, 4, hashlib.sha384),   # RSA_WITH_AES_256_GCM_SHA384
    0x009E: ("aesgcm", 16, 4, hashlib.sha256),   # DHE_RSA_WITH_AES_128_GCM_SHA256
    0x009F: ("aesgcm", 32, 4, hashlib.sha384),   # DHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02B: ("aesgcm", 16, 4, hashlib.sha256),   # ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02C: ("aesgcm", 32, 4, hashlib.sha384),   # ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02F: ("aesgcm", 16, 4, hashlib.sha256),   # ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030: ("aesgcm", 32, 4, hashlib.sha384),   # ECDHE_RSA_WITH_AES_256_GCM_SHA384
    # --- TLS 1.2 ChaCha20-Poly1305 (RFC 7905) ---
    0xCCA8: ("chacha", 32, 12, hashlib.sha256),  # ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xCCA9: ("chacha", 32, 12, hashlib.sha256),  # ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xCCAA: ("chacha", 32, 12, hashlib.sha256),  # DHE_RSA_WITH_CHACHA20_POLY1305
}

# TLS 1.2 CBC 套件（MAC-then-encrypt）：suite_id -> (enc_key_len, mac_hash)。
# 主要用于「服务器 RSA 私钥」解密——RSA 密钥交换常搭配 CBC 套件。TLS 1.2 CBC 的
# PRF 一律用 SHA-256（与 MAC 哈希无关）。仅列 RSA 密钥交换套件（前向保密套件无法
# 用服务器私钥解）。
_CBC_SUITES = {
    0x002F: (16, hashlib.sha1),    # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035: (32, hashlib.sha1),    # TLS_RSA_WITH_AES_256_CBC_SHA
    0x003C: (16, hashlib.sha256),  # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003D: (32, hashlib.sha256),  # TLS_RSA_WITH_AES_256_CBC_SHA256
}

# 支持用 RSA 私钥解密的密钥交换套件（无前向保密）：GCM(RSA) + 上面的 CBC(RSA)
_RSA_KX_SUITES = {0x009C, 0x009D} | set(_CBC_SUITES)


# --- 密钥派生原语 ---

def _p_hash(secret: bytes, seed: bytes, length: int, hashmod) -> bytes:
    """TLS 1.2 PRF 的 P_hash（RFC 5246）。"""
    out = bytearray()
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, hashmod).digest()
        out += hmac.new(secret, a + seed, hashmod).digest()
    return bytes(out[:length])


def tls12_prf(secret: bytes, label: bytes, seed: bytes, length: int, hashmod) -> bytes:
    """TLS 1.2 PRF = P_hash(secret, label + seed)（RFC 5246，AEAD 套件用套件哈希）。"""
    return _p_hash(secret, label + seed, length, hashmod)


def hkdf_expand(secret: bytes, info: bytes, length: int, hashmod) -> bytes:
    """HKDF-Expand（RFC 5869）。"""
    hash_len = hashmod().digest_size
    n = (length + hash_len - 1) // hash_len
    t = b""
    okm = bytearray()
    for i in range(1, n + 1):
        t = hmac.new(secret, t + info + bytes([i]), hashmod).digest()
        okm += t
    return bytes(okm[:length])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int, hashmod) -> bytes:
    """HKDF-Expand-Label（RFC 8446 §7.1）。"""
    full_label = b"tls13 " + label
    hkdf_label = (struct.pack("!H", length)
                  + bytes([len(full_label)]) + full_label
                  + bytes([len(context)]) + context)
    return hkdf_expand(secret, hkdf_label, length, hashmod)


# --- keylog 解析 ---

class KeyLog:
    """NSS Key Log（SSLKEYLOGFILE 格式）：label -> {client_random_hex: secret_bytes}。"""

    def __init__(self):
        self._by_label: Dict[str, Dict[str, bytes]] = {}

    @classmethod
    def load(cls, source) -> "KeyLog":
        """source 可为文件路径或 keylog 文本内容。"""
        kl = cls()
        if source is None:
            return kl
        text = source
        if isinstance(source, (bytes, bytearray)):
            text = source.decode("utf-8", "ignore")
        elif isinstance(source, str) and "\n" not in source and len(source) < 4096:
            import os
            if os.path.exists(source):
                with open(source, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            label, cr_hex, secret_hex = parts
            try:
                secret = bytes.fromhex(secret_hex)
            except ValueError:
                continue
            kl._by_label.setdefault(label, {})[cr_hex.lower()] = secret
        return kl

    def get(self, label: str, client_random: bytes) -> Optional[bytes]:
        return self._by_label.get(label, {}).get(client_random.hex().lower())

    def __bool__(self):
        return bool(self._by_label)


# --- 服务器 RSA 私钥（用于无前向保密的 RSA 密钥交换解密） ---

class RsaKeys:
    """一组服务器 RSA 私钥：解密 TLS RSA 密钥交换中客户端加密的 premaster secret。"""

    def __init__(self):
        self._keys = []

    @classmethod
    def load(cls, source, password=None) -> "RsaKeys":
        """source 可为 PEM/DER 路径、内容（str/bytes）、或它们的列表。"""
        rk = cls()
        if source is None or not _HAS_RSA:
            return rk
        items = source if isinstance(source, (list, tuple)) else [source]
        for item in items:
            rk._add(item, password)
        return rk

    def _add(self, item, password):
        data = item
        # str 且看起来是路径（非 PEM 内容、较短、存在）时按文件读取
        if (isinstance(item, str) and "-----BEGIN" not in item
                and len(item) < 4096 and os.path.exists(item)):
            with open(item, "rb") as f:
                data = f.read()
        try:
            key = _RSA.import_key(data, passphrase=password)
        except (ValueError, IndexError, TypeError):
            return
        if key.has_private():
            self._keys.append(key)

    def decrypt_premaster(self, encrypted: bytes) -> Optional[bytes]:
        """逐个私钥尝试 PKCS#1 v1.5 解密；得到合法 48 字节 premaster 即返回，否则 None。

        错误的密钥/密文因填充或长度不符会被 sentinel 拦下（返回随机数），再由
        「48 字节 + 首字节为 TLS 主版本 0x03」双重校验剔除，故不会产出错误结果。
        """
        for key in self._keys:
            try:
                sentinel = os.urandom(48)
                pms = _PKCS1_v15.new(key).decrypt(encrypted, sentinel)
            except (ValueError, TypeError):
                continue
            if len(pms) == 48 and pms[0] == 0x03 and 0 <= pms[1] <= 4:
                return pms
        return None

    def __bool__(self):
        return bool(self._keys)


def iter_handshake_messages(concat: bytes):
    """把（同一方向）所有握手记录体拼接后逐条产出 (msg_type, msg_body)。"""
    i, n = 0, len(concat)
    while i + 4 <= n:
        htype = concat[i]
        hlen = int.from_bytes(concat[i + 1:i + 4], "big")
        if i + 4 + hlen > n:
            break
        yield htype, concat[i + 4:i + 4 + hlen]
        i += 4 + hlen


_HS_CLIENT_KEY_EXCHANGE = 16


def _extract_encrypted_premaster(direction_buf: bytes) -> Optional[bytes]:
    """从客户端方向字节里取 ClientKeyExchange 的 RSA 加密 premaster（去 2 字节长度前缀）。"""
    hs = bytearray()
    for ctype, _ver, body in iter_tls_records(direction_buf):
        if ctype == _CT_HANDSHAKE:
            hs += body
    for htype, hbody in iter_handshake_messages(bytes(hs)):
        if htype == _HS_CLIENT_KEY_EXCHANGE and len(hbody) >= 2:
            elen = int.from_bytes(hbody[:2], "big")
            # RSA 加密块长度 = 模数字节数（>=128，即 >=1024 位）
            if elen >= 128 and len(hbody) >= 2 + elen:
                return hbody[2:2 + elen]
    return None


# extended_master_secret 扩展类型（RFC 7627）
_EXT_EMS = 0x0017


def _hello_extensions(msg_body: bytes, is_client: bool):
    """遍历 ClientHello/ServerHello（无 4 字节握手头的消息体）的扩展，yield (etype, edata)。"""
    try:
        p = 2 + 32                                  # version + random
        p += 1 + msg_body[p]                        # session_id
        if is_client:
            cs_len = int.from_bytes(msg_body[p:p + 2], "big")
            p += 2 + cs_len                         # cipher_suites
            p += 1 + msg_body[p]                    # compression_methods
        else:
            p += 2 + 1                              # cipher + compression_method
        if p + 2 > len(msg_body):
            return
        ext_total = int.from_bytes(msg_body[p:p + 2], "big")
        p += 2
        end = min(len(msg_body), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(msg_body[p:p + 2], "big")
            elen = int.from_bytes(msg_body[p + 2:p + 4], "big")
            p += 4
            yield etype, msg_body[p:p + elen]
            p += elen
    except IndexError:
        return


def _direction_handshake_msgs(direction_buf: bytes):
    """返回该方向的握手消息列表 [(htype, full_message_bytes), ...]（full 含 4 字节头）。"""
    hs = bytearray()
    for ctype, _ver, body in iter_tls_records(direction_buf):
        if ctype == _CT_HANDSHAKE:
            hs += body
    out = []
    for htype, hbody in iter_handshake_messages(bytes(hs)):
        out.append((htype, bytes([htype]) + len(hbody).to_bytes(3, "big") + hbody))
    return out


def _negotiated_ems(by_dir) -> bool:
    """ClientHello 与 ServerHello 是否都带 extended_master_secret 扩展（RFC 7627）。"""
    ch_ems = sh_ems = False
    for slot in by_dir.values():
        for htype, full in _direction_handshake_msgs(bytes(slot["buf"])):
            body = full[4:]
            if htype == _HS_CLIENT_HELLO:
                ch_ems = ch_ems or any(et == _EXT_EMS for et, _ in _hello_extensions(body, True))
            elif htype == _HS_SERVER_HELLO:
                sh_ems = sh_ems or any(et == _EXT_EMS for et, _ in _hello_extensions(body, False))
    return ch_ems and sh_ems


def _handshake_transcript(by_dir, client_dir) -> Optional[bytes]:
    """拼出握手 transcript（ClientHello + 所有服务端握手消息 + ClientKeyExchange），
    用于 EMS 的 session_hash 计算。无法定位 CH/CKE 时返回 None。"""
    client_msgs = server_msgs = []
    for dk, slot in by_dir.items():
        msgs = _direction_handshake_msgs(bytes(slot["buf"]))
        if dk == client_dir:
            client_msgs = msgs
        else:
            server_msgs = msgs
    ch = next((f for t, f in client_msgs if t == _HS_CLIENT_HELLO), None)
    cke = next((f for t, f in client_msgs if t == _HS_CLIENT_KEY_EXCHANGE), None)
    if ch is None or cke is None:
        return None
    return ch + b"".join(f for _t, f in server_msgs) + cke


# --- TLS 记录 / 握手解析 ---

def iter_tls_records(data: bytes):
    """顺序切分完整 TLS 记录，yield (content_type, version, body_bytes)；末尾残缺忽略。"""
    i = 0
    n = len(data)
    while i + 5 <= n:
        ctype = data[i]
        version = (data[i + 1] << 8) | data[i + 2]
        length = (data[i + 3] << 8) | data[i + 4]
        # 合法记录：类型 20-23，版本 0x03xx，长度 <= 2^14+2048
        if ctype not in (20, 21, 22, 23) or data[i + 1] != 0x03 or length > 18432:
            return
        if i + 5 + length > n:
            return
        yield ctype, version, data[i + 5:i + 5 + length]
        i += 5 + length


def looks_like_tls(data: bytes) -> bool:
    """首字节是否像一条 TLS 握手记录（type=22, ver=0x03xx）。"""
    return len(data) >= 5 and data[0] == _CT_HANDSHAKE and data[1] == 0x03


def _parse_client_hello(body: bytes) -> Optional[bytes]:
    """从 handshake 记录体解析 ClientHello，返回 client_random(32B)。"""
    if len(body) < 6 or body[0] != _HS_CLIENT_HELLO:
        return None
    # handshake header 4B + legacy_version 2B + random 32B
    if len(body) < 4 + 2 + 32:
        return None
    return body[6:38]


def _parse_server_hello(body: bytes):
    """解析 ServerHello，返回 (cipher_suite:int, is_tls13:bool) 或 None。"""
    if len(body) < 6 or body[0] != _HS_SERVER_HELLO:
        return None
    p = 4 + 2 + 32  # handshake header + legacy_version + random
    if p + 1 > len(body):
        return None
    sid_len = body[p]
    p += 1 + sid_len
    if p + 2 > len(body):
        return None
    cipher_suite = (body[p] << 8) | body[p + 1]
    p += 2
    p += 1  # compression method
    is_tls13 = False
    if p + 2 <= len(body):
        ext_total = (body[p] << 8) | body[p + 1]
        p += 2
        end = min(len(body), p + ext_total)
        while p + 4 <= end:
            etype = (body[p] << 8) | body[p + 1]
            elen = (body[p + 2] << 8) | body[p + 3]
            p += 4
            if etype == 0x002B:  # supported_versions
                if elen >= 2 and body[p:p + 2] == b"\x03\x04":
                    is_tls13 = True
                elif elen >= 1:
                    # 服务端 supported_versions 直接是 2 字节选定版本
                    if b"\x03\x04" in body[p:p + elen]:
                        is_tls13 = True
            p += elen
    return cipher_suite, is_tls13


# --- 记录层解密 ---

def _aead_decrypt(aead: str, key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    """AEAD 解密并校验标签；失败抛 ValueError。"""
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    if aead == "aesgcm":
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    else:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


def _xor_iv(iv: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq_bytes))


def _tls13_traffic_keys(secret: bytes, aead: str, key_len: int, hashmod):
    key = hkdf_expand_label(secret, b"key", b"", key_len, hashmod)
    iv = hkdf_expand_label(secret, b"iv", b"", 12, hashmod)
    return key, iv


def _decrypt_tls13_direction(records, secrets, aead, key_len, hashmod):
    """
    TLS 1.3 单方向解密。secrets = [(handshake_secret), (app_secret)]（可含 None）。
    对每条 type=23 记录，用「握手/应用」两套密钥各自序号尝试，AEAD 校验通过者采纳。
    返回解密出的应用层明文片段列表（inner content_type==23）。
    """
    epochs = []  # [(key, iv, seq_counter_index)]
    for sec in secrets:
        if sec is None:
            epochs.append(None)
        else:
            key, iv = _tls13_traffic_keys(sec, aead, key_len, hashmod)
            epochs.append([key, iv, 0])  # 独立 seq

    out = []
    for ctype, _ver, body in records:
        if ctype != _CT_APPLICATION_DATA:
            continue  # ChangeCipherSpec(20) 兼容记录等直接跳过，不占序号
        if len(body) < 17:
            continue
        aad = bytes([_CT_APPLICATION_DATA, 0x03, 0x03]) + struct.pack("!H", len(body))
        decrypted = None
        for ep in epochs:
            if ep is None:
                continue
            key, iv, seq = ep
            nonce = _xor_iv(iv, seq)
            try:
                plain = _aead_decrypt(aead, key, nonce, aad, body)
            except ValueError:
                continue
            ep[2] += 1  # 该 epoch 序号推进
            decrypted = plain
            break
        if decrypted is None:
            continue
        # 去掉尾部零填充，最后一个非零字节是真正的 inner content_type
        idx = len(decrypted) - 1
        while idx >= 0 and decrypted[idx] == 0:
            idx -= 1
        if idx < 0:
            continue
        inner_type = decrypted[idx]
        inner = decrypted[:idx]
        if inner_type == _CT_APPLICATION_DATA:
            out.append(inner)
    return out


def _decrypt_tls12_direction(records, key, iv_fixed, aead, hashmod):
    """
    TLS 1.2 单方向解密：ChangeCipherSpec 之后的记录逐条推进序号，
    对 type=23 应用数据解密。返回明文片段列表。
    """
    out = []
    seq = 0
    started = False
    for ctype, _ver, body in records:
        if not started:
            if ctype == _CT_CHANGE_CIPHER_SPEC:
                started = True
            continue
        # CCS 之后：每条记录（Finished/应用数据/告警）都占一个序号
        rec_seq = seq
        seq += 1
        if ctype != _CT_APPLICATION_DATA:
            continue
        try:
            if aead == "aesgcm":
                # 记录体 = 显式 nonce(8) + 密文 + 标签(16)
                if len(body) < 8 + 16:
                    continue
                explicit = body[:8]
                ct_tag = body[8:]
                nonce = iv_fixed + explicit
                plain_len = len(ct_tag) - 16
            else:
                # ChaCha20（RFC 7905）：无显式 nonce，nonce = write_iv XOR seq
                if len(body) < 16:
                    continue
                ct_tag = body
                nonce = _xor_iv(iv_fixed, rec_seq)
                plain_len = len(ct_tag) - 16
            aad = struct.pack("!Q", rec_seq) + bytes([_CT_APPLICATION_DATA, 0x03, 0x03]) \
                + struct.pack("!H", plain_len)
            plain = _aead_decrypt(aead, key, nonce, aad, ct_tag)
        except ValueError:
            continue
        out.append(plain)
    return out


def _decrypt_tls12_cbc_direction(records, enc_key, mac_key, mac_hashmod):
    """
    TLS 1.2 AES-CBC 单方向解密（MAC-then-encrypt，显式每记录 IV）。
    对每条应用数据：CBC 解密 → 去填充 → 剥离尾部 HMAC 并校验 → 取明文。
    HMAC 校验充当正确性闸门：密钥/序号错误则校验失败并丢弃，绝不产出乱码。
    """
    out = []
    seq = 0
    started = False
    mac_len = mac_hashmod().digest_size
    for ctype, _ver, body in records:
        if not started:
            if ctype == _CT_CHANGE_CIPHER_SPEC:
                started = True
            continue
        rec_seq = seq
        seq += 1
        if ctype != _CT_APPLICATION_DATA:
            continue
        # 记录体 = 显式 IV(16) + 密文(16 的整数倍)
        if len(body) < 32 or (len(body) - 16) % 16 != 0:
            continue
        iv, ct = body[:16], body[16:]
        try:
            plain = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
        except ValueError:
            continue
        pad_len = plain[-1]
        if pad_len + 1 > len(plain):
            continue
        # 校验填充：TLS 要求每个填充字节都等于 pad_len
        if any(b != pad_len for b in plain[-(pad_len + 1):]):
            continue
        content_mac = plain[:len(plain) - pad_len - 1]
        if len(content_mac) < mac_len:
            continue
        content, mac = content_mac[:-mac_len], content_mac[-mac_len:]
        aad = struct.pack("!Q", rec_seq) + bytes([_CT_APPLICATION_DATA, 0x03, 0x03]) \
            + struct.pack("!H", len(content))
        expected = hmac.new(mac_key, aad + content, mac_hashmod).digest()
        if not hmac.compare_digest(expected, mac):
            continue
        out.append(content)
    return out


def _direction_records(concat: bytes):
    return list(iter_tls_records(concat))


def decrypt_tls_packets(packets: List[PacketInfo], keylog: "KeyLog" = None,
                        rsa_keys: "RsaKeys" = None) -> Optional[List[PacketInfo]]:
    """
    输入单条 TCP 流的 PacketInfo 列表；若为可解密的 TLS 流，返回解密后的明文
    PacketInfo 列表（每方向一条，承载还原出的明文 HTTP 字节），否则 None。

    两种密钥来源：
      - keylog（KeyLog）：TLS 1.2 主密钥 / TLS 1.3 流量密钥，覆盖 ECDHE 等前向保密套件；
      - rsa_keys（RsaKeys）：服务器 RSA 私钥，解 RSA 密钥交换的 TLS 1.2 流量（GCM/CBC）。
    """
    if not _HAS_CRYPTO or not (keylog or rsa_keys) or not packets:
        return None

    # 按方向分组、保序拼接，并记录每方向端点与最早时间
    by_dir = OrderedDict()
    for info in packets:
        dk = ((info.src, info.sport), (info.dst, info.dport))
        slot = by_dir.setdefault(dk, {"buf": bytearray(), "time": info.time,
                                      "src": info.src, "sport": info.sport,
                                      "dst": info.dst, "dport": info.dport})
        slot["buf"] += info.load

    # 至少一方向像 TLS 才继续
    if not any(looks_like_tls(bytes(s["buf"])) for s in by_dir.values()):
        return None

    # 找 ClientHello（client_random）与 ServerHello（套件/版本）
    client_random = None
    server_hello = None
    for slot in by_dir.values():
        for ctype, _ver, body in iter_tls_records(bytes(slot["buf"])):
            if ctype != _CT_HANDSHAKE:
                continue
            if client_random is None:
                cr = _parse_client_hello(body)
                if cr:
                    client_random = cr
            if server_hello is None:
                sh = _parse_server_hello(body)
                if sh:
                    server_hello = sh
    if client_random is None or server_hello is None:
        return None
    cipher_suite, is_tls13 = server_hello
    is_cbc = cipher_suite in _CBC_SUITES
    if cipher_suite not in _SUITES and not is_cbc:
        return None
    if is_cbc:
        key_len, mac_hash = _CBC_SUITES[cipher_suite]
        prf_hash = hashlib.sha256          # TLS 1.2 CBC 的 PRF 固定 SHA-256
        mac_len = mac_hash().digest_size
    else:
        aead, key_len, fixed_iv_len, prf_hash = _SUITES[cipher_suite]

    # 判定各方向的 client/server 角色：发出 ClientHello 的一方是 client
    client_dir = None
    for dk, slot in by_dir.items():
        for ctype, _ver, body in iter_tls_records(bytes(slot["buf"])):
            if ctype == _CT_HANDSHAKE and _parse_client_hello(body):
                client_dir = dk
                break
        if client_dir is not None:
            break
    if client_dir is None:
        return None

    # TLS 1.2：先算出全流共用的 master secret 与 key_block（TLS 1.3 各方向单独取密钥）
    key_block = None
    if not is_tls13:
        master = keylog.get("CLIENT_RANDOM", client_random) if keylog else None
        server_random = _extract_server_random(by_dir)
        if master is None and rsa_keys and server_random is not None:
            enc = _extract_encrypted_premaster(bytes(by_dir[client_dir]["buf"]))
            if enc:
                pms = rsa_keys.decrypt_premaster(enc)
                if pms and _negotiated_ems(by_dir):
                    # RFC 7627：master = PRF(pms, "extended master secret", session_hash)
                    transcript = _handshake_transcript(by_dir, client_dir)
                    if transcript:
                        session_hash = prf_hash(transcript).digest()
                        master = tls12_prf(pms, b"extended master secret",
                                           session_hash, 48, prf_hash)
                elif pms:
                    master = tls12_prf(pms, b"master secret",
                                       client_random + server_random, 48, prf_hash)
        if master is None or server_random is None:
            return None
        key_block_len = (2 * mac_len + 2 * key_len) if is_cbc \
            else (2 * key_len + 2 * fixed_iv_len)
        key_block = tls12_prf(master, b"key expansion",
                              server_random + client_random, key_block_len, prf_hash)

    decrypted_packets = []
    for dk, slot in by_dir.items():
        records = _direction_records(bytes(slot["buf"]))
        is_client = (dk == client_dir)
        if is_tls13:
            if not keylog:
                continue
            if is_client:
                secrets = [keylog.get("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random),
                           keylog.get("CLIENT_TRAFFIC_SECRET_0", client_random)]
            else:
                secrets = [keylog.get("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random),
                           keylog.get("SERVER_TRAFFIC_SECRET_0", client_random)]
            if not any(secrets):
                continue
            plains = _decrypt_tls13_direction(records, secrets, aead, key_len, prf_hash)
        elif is_cbc:
            c_mac, s_mac = key_block[:mac_len], key_block[mac_len:2 * mac_len]
            c_key = key_block[2 * mac_len:2 * mac_len + key_len]
            s_key = key_block[2 * mac_len + key_len:2 * mac_len + 2 * key_len]
            if is_client:
                plains = _decrypt_tls12_cbc_direction(records, c_key, c_mac, mac_hash)
            else:
                plains = _decrypt_tls12_cbc_direction(records, s_key, s_mac, mac_hash)
        else:
            c_key = key_block[:key_len]
            s_key = key_block[key_len:2 * key_len]
            c_iv = key_block[2 * key_len:2 * key_len + fixed_iv_len]
            s_iv = key_block[2 * key_len + fixed_iv_len:2 * key_len + 2 * fixed_iv_len]
            if is_client:
                plains = _decrypt_tls12_direction(records, c_key, c_iv, aead, prf_hash)
            else:
                plains = _decrypt_tls12_direction(records, s_key, s_iv, aead, prf_hash)

        if plains:
            merged = b"".join(plains)
            decrypted_packets.append(PacketInfo(
                slot["time"], slot["src"], slot["sport"],
                slot["dst"], slot["dport"], merged))

    if not decrypted_packets:
        return None
    decrypted_packets.sort(key=lambda p: p.time)
    return decrypted_packets


def _extract_server_random(by_dir) -> Optional[bytes]:
    for slot in by_dir.values():
        for ctype, _ver, body in iter_tls_records(bytes(slot["buf"])):
            if ctype == _CT_HANDSHAKE and len(body) >= 38 and body[0] == _HS_SERVER_HELLO:
                return body[6:38]
    return None
