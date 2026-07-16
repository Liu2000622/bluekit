# -*- coding: utf-8 -*-
"""
TLS 服务器证书被动指纹：从 ServerHello 之后的 Certificate 握手消息提取叶子证书，
做轻量 X.509 字段解析（CN / 颁发者 CN / 自签判定 / SHA-256），并识别已知 C2 的
默认自签证书（Cobalt Strike / Metasploit）。

不依赖 cryptography（项目打包已排除该重库），只做够用的 DER 扫描：
  - 用 commonName OID(2.5.4.3) 模式提取 CN；
  - subject CN == issuer CN 视作自签（启发式）；
  - Cobalt Strike 默认证书含 'Major Cobalt Strike' / 'cobaltstrike' 且序列号 146473198。
证书是无法解密的 TLS 流里最可靠的被动 C2 信号之一，与 JA3/JA4 互补。
"""

import hashlib

# TLS 记录 / 握手常量
_CT_HANDSHAKE = 22
_HS_CERTIFICATE = 11

# commonName 属性的 DER 前缀：OID 2.5.4.3
_CN_OID = b"\x06\x03\x55\x04\x03"
# DirectoryString 常见编码：UTF8String(0x0C) / PrintableString(0x13) / IA5String(0x16) / T61(0x14)
_STR_TAGS = {0x0C, 0x13, 0x16, 0x14}


def _iter_tls_records(data):
    i, n = 0, len(data)
    while i + 5 <= n:
        ctype = data[i]
        length = (data[i + 3] << 8) | data[i + 4]
        if ctype not in (20, 21, 22, 23) or data[i + 1] != 0x03 or length > 18432:
            return
        if i + 5 + length > n:
            return
        yield ctype, data[i + 5:i + 5 + length]
        i += 5 + length


def _iter_handshake(concat):
    i, n = 0, len(concat)
    while i + 4 <= n:
        htype = concat[i]
        hlen = int.from_bytes(concat[i + 1:i + 4], "big")
        if i + 4 + hlen > n:
            break
        yield htype, concat[i + 4:i + 4 + hlen]
        i += 4 + hlen


def extract_leaf_cert(direction_bytes):
    """从一个 TLS 方向的字节里取 Certificate 消息的第一张（叶子）证书 DER；无则 None。"""
    hs = bytearray()
    for ctype, body in _iter_tls_records(direction_bytes):
        if ctype == _CT_HANDSHAKE:
            hs += body
    for htype, body in _iter_handshake(bytes(hs)):
        if htype != _HS_CERTIFICATE or len(body) < 6:
            continue
        # Certificate: 3B 证书列表总长 + [3B 单证书长 + DER]...
        p = 3
        if p + 3 > len(body):
            return None
        clen = int.from_bytes(body[p:p + 3], "big")
        p += 3
        if clen == 0 or p + clen > len(body):
            return None
        return body[p:p + clen]
    return None


def _extract_cns(der):
    """按 commonName OID 模式提取所有 CN 值（顺序：先 issuer 后 subject）。"""
    cns = []
    idx = 0
    while True:
        pos = der.find(_CN_OID, idx)
        if pos < 0:
            break
        j = pos + len(_CN_OID)
        if j + 2 <= len(der) and der[j] in _STR_TAGS:
            slen = der[j + 1]
            if slen & 0x80 == 0 and j + 2 + slen <= len(der):
                cns.append(der[j + 2:j + 2 + slen].decode("utf-8", "ignore"))
        idx = pos + 1
    return cns


def _serial_int(der):
    """粗取序列号：TBSCertificate 第一个字段为 version(可选)，其后是 serialNumber(INTEGER)。
    直接找到外层 SEQUENCE 后第一个 INTEGER 值。够用于匹配已知固定序列号。"""
    # 外层 SEQUENCE (Certificate) -> 内层 SEQUENCE (TBSCertificate)
    try:
        if der[0] != 0x30:
            return None
        # 跳过外层长度
        p = 1
        p += 1 + (der[p] & 0x7F if der[p] & 0x80 else 0)
        if der[p] != 0x30:   # TBSCertificate SEQUENCE
            return None
        p += 1
        p += 1 + (der[p] & 0x7F if der[p] & 0x80 else 0)
        # 可选 [0] version
        if der[p] == 0xA0:
            vlen = der[p + 1]
            p += 2 + vlen
        if der[p] != 0x02:   # INTEGER (serialNumber)
            return None
        slen = der[p + 1]
        return int.from_bytes(der[p + 2:p + 2 + slen], "big")
    except (IndexError, ValueError):
        return None


# 已知 C2 默认证书。Cobalt Strike 默认自签证书序列号 146473198、CN/O 含 cobaltstrike。
_CS_SERIAL = 146473198


def classify_cert(der):
    """解析证书要点并识别已知 C2 默认证书。返回 dict(cn/issuer_cn/self_signed/sha256/known)。"""
    if not der or len(der) < 16:
        return None
    cns = _extract_cns(der)
    issuer_cn = cns[0] if cns else None
    subject_cn = cns[-1] if cns else None
    self_signed = bool(cns) and issuer_cn == subject_cn
    sha256 = hashlib.sha256(der).hexdigest()
    low = der.lower()
    known = None
    serial = _serial_int(der)
    if b"cobaltstrike" in low or b"major cobalt strike" in low or serial == _CS_SERIAL:
        known = "Cobalt Strike (默认自签证书)"
    elif b"metasploit" in low:
        known = "Metasploit (默认自签证书)"
    return {"cn": subject_cn, "issuer_cn": issuer_cn, "self_signed": self_signed,
            "sha256": sha256, "known": known}
