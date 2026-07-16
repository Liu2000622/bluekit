# -*- coding: utf-8 -*-
"""
JA3 / JA3S 与 JA4 / JA4S TLS 指纹：对无 keylog、无法解密的 TLS 流量，用
ClientHello / ServerHello 的握手参数指纹识别 C2 工具（Cobalt Strike / Metasploit /
Sliver / Havoc / Merlin 等）的加密通信。

JA3  (ClientHello) = md5(SSLVersion,Ciphers,Extensions,SupportedGroups,ECPointFormats)
JA3S (ServerHello) = md5(SSLVersion,Cipher,Extensions)
JA4  (ClientHello, FoxIO) = a_b_c：a 段为可读的 协议/TLS版本/SNI/密码套件数/扩展数/ALPN；
        b 段为「排序后」cipher 列表的 sha256 前 12 位；c 段为「排序后」扩展列表
        （去 SNI/ALPN）+ 原序签名算法的 sha256 前 12 位。
JA4S (ServerHello, FoxIO) = a_b_c：a 段为 协议/TLS版本/扩展数/ALPN；b 段为选定的
        cipher（4 位 hex，不哈希）；c 段为「原序」扩展列表的 sha256 前 12 位。

JA4 相较 JA3 更抗规避：对 cipher/extension 排序后再哈希，Chrome 110+ 的
ClientHello 扩展乱序不再改变指纹；且前 10 位明文可读，便于比对公开指纹库
（如 FoxIO JA4+ 数据库）。GREASE 值（RFC 8701）在两套指纹里都按规范剔除。
"""

import hashlib
import struct

# GREASE 占位值，计算指纹时须剔除
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _u16(d, o):
    return struct.unpack_from(">H", d, o)[0]


def parse_tls_handshake(payload):
    """从 TCP 载荷提取首个 TLS 握手记录 (handshake_type, body)；非 TLS 握手返回 None。"""
    if len(payload) < 9 or payload[0] != 0x16:  # 0x16 = handshake record
        return None
    rec_len = _u16(payload, 3)
    hs = payload[5:5 + rec_len]
    if len(hs) < 4:
        return None
    hs_type = hs[0]
    hs_len = int.from_bytes(hs[1:4], "big")
    return hs_type, hs[4:4 + hs_len]


def _join(nums):
    return "-".join(str(n) for n in nums)


def compute_ja3(payload):
    """从 ClientHello 计算 (ja3_string, md5)；非 ClientHello 或解析失败返回 None。"""
    parsed = parse_tls_handshake(payload)
    if not parsed or parsed[0] != 0x01:
        return None
    body = parsed[1]
    try:
        o = 2 + 32  # client_version(2) + random(32)
        o += 1 + body[o]  # session_id
        cs_len = _u16(body, o)
        o += 2
        ciphers = [c for c in (_u16(body, o + i) for i in range(0, cs_len, 2)) if c not in _GREASE]
        o += cs_len
        o += 1 + body[o]  # compression_methods
        exts, curves, pointfmts = [], [], []
        if o + 2 <= len(body):
            end = o + 2 + _u16(body, o)
            o += 2
            while o + 4 <= end:
                etype, elen = _u16(body, o), _u16(body, o + 2)
                o += 4
                edata = body[o:o + elen]
                o += elen
                if etype in _GREASE:
                    continue
                exts.append(etype)
                if etype == 10 and len(edata) >= 2:      # supported_groups
                    glen = _u16(edata, 0)
                    curves = [g for g in (_u16(edata, 2 + i) for i in range(0, glen, 2))
                              if g not in _GREASE]
                elif etype == 11 and len(edata) >= 1:     # ec_point_formats
                    pointfmts = list(edata[1:1 + edata[0]])
        ja3 = f"{_u16(body, 0)},{_join(ciphers)},{_join(exts)},{_join(curves)},{_join(pointfmts)}"
        return ja3, hashlib.md5(ja3.encode()).hexdigest()
    except (struct.error, IndexError):
        return None


def compute_ja3s(payload):
    """从 ServerHello 计算 (ja3s_string, md5)；非 ServerHello 或解析失败返回 None。"""
    parsed = parse_tls_handshake(payload)
    if not parsed or parsed[0] != 0x02:
        return None
    body = parsed[1]
    try:
        o = 2 + 32
        o += 1 + body[o]  # session_id
        cipher = _u16(body, o)
        o += 2 + 1        # cipher(2) + compression_method(1)
        exts = []
        if o + 2 <= len(body):
            end = o + 2 + _u16(body, o)
            o += 2
            while o + 4 <= end:
                etype, elen = _u16(body, o), _u16(body, o + 2)
                o += 4 + elen
                if etype not in _GREASE:
                    exts.append(etype)
        ja3s = f"{_u16(body, 0)},{cipher},{_join(exts)}"
        return ja3s, hashlib.md5(ja3s.encode()).hexdigest()
    except (struct.error, IndexError):
        return None


# 已知 C2 / 攻击工具的 JA3(S) 指纹。指纹随工具版本与客户端 TLS 库变化，仅作强提示；
# 命中即高危告警，未命中也在报告展示 JA3 供人工比对威胁情报（如 abuse.ch SSLBL）。
_KNOWN_JA3 = {
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (常见默认 Malleable Profile)",
    "72a589da586844d7f0818ce684948eea": "Metasploit / meterpreter (Java payload)",
    "e7d705a3286e19ea42f587b344ee6865": "Metasploit (Ruby/openssl)",
}
_KNOWN_JA3S = {
    "ec74a5c51106f0419184d0dd08fb05bc": "Cobalt Strike (默认自签服务端)",
}


def classify_ja3(md5hash, is_server=False):
    """已知恶意/工具指纹返回其名称，否则 None。"""
    return (_KNOWN_JA3S if is_server else _KNOWN_JA3).get(md5hash)


# ---------------------------------------------------------------------------
# JA4 / JA4S（FoxIO 规范）
# ---------------------------------------------------------------------------

# TLS 版本号 → JA4 两字符标记
_TLS_VERSION_MAP = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                    0x0300: "s3", 0x0002: "s2"}


def _read_vec(data, o, len_bytes):
    """读长度前缀向量：返回 (payload, next_offset)。越界由调用方 try/except 兜底。"""
    n = int.from_bytes(data[o:o + len_bytes], "big")
    o += len_bytes
    return data[o:o + n], o + n


def _u16_list(b):
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b) - 1, 2)]


def _map_tls_version(ver):
    return _TLS_VERSION_MAP.get(ver, "00")


def _alpn_2char(alpn):
    """ALPN 首个协议取「首字符+尾字符」；无 ALPN 返回 '00'。非字母数字回退到字节 hex。"""
    if not alpn:
        return "00"
    first, last = alpn[0], alpn[-1]
    if first.isalnum() and last.isalnum():
        return first + last
    return f"{ord(first):02x}"[0] + f"{ord(last):02x}"[1]


def _iter_extensions(ext_block):
    """逐个产出 (etype, edata)，跳过 GREASE。"""
    eo = 0
    while eo + 4 <= len(ext_block):
        etype = _u16(ext_block, eo)
        elen = _u16(ext_block, eo + 2)
        edata = ext_block[eo + 4:eo + 4 + elen]
        eo += 4 + elen
        if etype not in _GREASE:
            yield etype, edata


def _parse_client_hello(payload):
    """解析 ClientHello 关键字段供 JA4 计算；非 ClientHello / 解析失败返回 None。"""
    parsed = parse_tls_handshake(payload)
    if not parsed or parsed[0] != 0x01:
        return None
    body = parsed[1]
    try:
        legacy_version = _u16(body, 0)
        o = 2 + 32
        o += 1 + body[o]                       # session_id
        cs, o = _read_vec(body, o, 2)          # cipher_suites
        ciphers = [c for c in _u16_list(cs) if c not in _GREASE]
        o += 1 + body[o]                       # compression_methods
        ext_types, sig_algs, sup_versions = [], [], []
        sni_present = False
        sni_host = None
        alpn_first = None
        if o + 2 <= len(body):
            ext_block, _ = _read_vec(body, o, 2)
            for etype, edata in _iter_extensions(ext_block):
                ext_types.append(etype)
                if etype == 0x0000:                                  # server_name
                    sni_present = True
                    # server_name_list: 2B 列表长度，条目 [type(1)][len(2)][name]
                    if len(edata) >= 5 and edata[2] == 0:            # host_name 类型
                        nlen = _u16(edata, 3)
                        sni_host = edata[5:5 + nlen].decode("latin1", "ignore") or None
                elif etype == 0x0010 and len(edata) >= 3:            # ALPN
                    plist, _ = _read_vec(edata, 0, 2)
                    if plist:
                        alpn_first = plist[1:1 + plist[0]].decode("latin1", "ignore")
                elif etype == 0x000d and len(edata) >= 2:            # signature_algorithms
                    sa, _ = _read_vec(edata, 0, 2)
                    sig_algs = [v for v in _u16_list(sa) if v not in _GREASE]
                elif etype == 0x002b and len(edata) >= 1:            # supported_versions
                    sv, _ = _read_vec(edata, 0, 1)
                    sup_versions = [v for v in _u16_list(sv) if v not in _GREASE]
        return {"legacy_version": legacy_version, "ciphers": ciphers,
                "ext_types": ext_types, "sni": sni_present, "sni_host": sni_host,
                "alpn": alpn_first, "sig_algs": sig_algs, "sup_versions": sup_versions}
    except (struct.error, IndexError):
        return None


def extract_sni(payload):
    """从 ClientHello 提取 SNI 主机名（server_name 扩展）；无 / 非 ClientHello 返回 None。"""
    ch = _parse_client_hello(payload)
    return ch.get("sni_host") if ch else None


def _parse_server_hello(payload):
    """解析 ServerHello 关键字段供 JA4S 计算；非 ServerHello / 解析失败返回 None。"""
    parsed = parse_tls_handshake(payload)
    if not parsed or parsed[0] != 0x02:
        return None
    body = parsed[1]
    try:
        legacy_version = _u16(body, 0)
        o = 2 + 32
        o += 1 + body[o]                       # session_id
        cipher = _u16(body, o)
        o += 2 + 1                             # cipher(2) + compression_method(1)
        ext_types, sup_version, alpn_first = [], None, None
        if o + 2 <= len(body):
            ext_block, _ = _read_vec(body, o, 2)
            for etype, edata in _iter_extensions(ext_block):
                ext_types.append(etype)
                if etype == 0x002b and len(edata) >= 2:              # supported_versions（单值）
                    sup_version = _u16(edata, 0)
                elif etype == 0x0010 and len(edata) >= 3:            # ALPN（服务端选定）
                    plist, _ = _read_vec(edata, 0, 2)
                    if plist:
                        alpn_first = plist[1:1 + plist[0]].decode("latin1", "ignore")
        return {"legacy_version": legacy_version, "cipher": cipher,
                "ext_types": ext_types, "sup_version": sup_version, "alpn": alpn_first}
    except (struct.error, IndexError):
        return None


def _sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def compute_ja4(payload):
    """从 ClientHello 计算 JA4 指纹字符串（a_b_c）；非 ClientHello / 失败返回 None。"""
    ch = _parse_client_hello(payload)
    if ch is None:
        return None
    version = (_map_tls_version(max(ch["sup_versions"])) if ch["sup_versions"]
               else _map_tls_version(ch["legacy_version"]))
    sni = "d" if ch["sni"] else "i"
    a = (f"t{version}{sni}"
         f"{min(len(ch['ciphers']), 99):02d}"
         f"{min(len(ch['ext_types']), 99):02d}"      # 扩展数含 SNI/ALPN
         f"{_alpn_2char(ch['alpn'])}")
    if ch["ciphers"]:
        b = _sha12(",".join(f"{c:04x}" for c in sorted(ch["ciphers"])))
    else:
        b = "0" * 12
    if ch["ext_types"]:
        exts = sorted(e for e in ch["ext_types"] if e not in (0x0000, 0x0010))
        ext_str = ",".join(f"{e:04x}" for e in exts)
        sig_str = ",".join(f"{s:04x}" for s in ch["sig_algs"])
        c = _sha12(f"{ext_str}_{sig_str}")
    else:
        c = "0" * 12
    return f"{a}_{b}_{c}"


def compute_ja4s(payload):
    """从 ServerHello 计算 JA4S 指纹字符串（a_b_c）；非 ServerHello / 失败返回 None。"""
    sh = _parse_server_hello(payload)
    if sh is None:
        return None
    version = (_map_tls_version(sh["sup_version"]) if sh["sup_version"]
               else _map_tls_version(sh["legacy_version"]))
    a = f"t{version}{min(len(sh['ext_types']), 99):02d}{_alpn_2char(sh['alpn'])}"
    b = f"{sh['cipher']:04x}"
    # JA4S 的扩展保持「原序」（不排序），与 JA4 客户端侧不同
    c = _sha12(",".join(f"{e:04x}" for e in sh["ext_types"])) if sh["ext_types"] else "0" * 12
    return f"{a}_{b}_{c}"


# 已知 C2 / 攻击工具的 JA4 / JA4S 指纹。工具计算并展示每条未识别 TLS 流的 JA4(S)，
# 供人工比对公开指纹库（FoxIO JA4+ DB 等）；此内置表由操作者按威胁情报扩展。
# 说明：JA4 随工具版本 / Go-TLS 版本漂移——表中若填了过期值，只会「漏配」（永不
# 匹配良性流量），绝不会对正常流量误报，故可安全地按情报增量补充。
_KNOWN_JA4 = {}
_KNOWN_JA4S = {}


def classify_ja4(fingerprint, is_server=False):
    """已知 C2 JA4/JA4S 指纹返回其名称，否则 None。"""
    return (_KNOWN_JA4S if is_server else _KNOWN_JA4).get(fingerprint)
