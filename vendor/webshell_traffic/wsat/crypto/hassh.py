# -*- coding: utf-8 -*-
"""HASSH / HASSH-Server 指纹（SSH 版的 JA3）。

前向保密的隧道（chisel 等 SSH-over-WebSocket、裸 SSH）无法离线解密载荷，但 SSH
在密钥交换建立会话密钥**之前**会明文发送一条 ``SSH_MSG_KEXINIT``，其中列出本端
支持的密钥交换 / 加密 / MAC / 压缩算法及其顺序。不同实现（OpenSSH、libssh、Go
``x/crypto/ssh`` 等）的算法列表与排序各不相同，据此可算出稳定的实现指纹：

    hassh        = md5( kex ; enc_c2s ; mac_c2s ; comp_c2s )   # 取自客户端 KEXINIT
    hasshServer  = md5( kex ; enc_s2c ; mac_s2c ; comp_s2c )   # 取自服务端 KEXINIT

chisel 用 Go ``x/crypto/ssh``，会产生一个特征性 HASSH，可把它从 OpenSSH 客户端里
区分出来，并与公开指纹库 / 威胁情报做关联——不解密也能识别工具与实现。
"""

import hashlib

from wsat.core.websocket import parse_ws_frames

SSH_MSG_KEXINIT = 0x14

# 已知 HASSH 指纹表（实测 + 公开库核实）。命中即给出实现/工具归属，供关联定位。
# 按需扩充：把新样本实测值补入本表，或比对公开 HASSH 库（如 hassh.io / abuse.ch）。
_KNOWN_HASSH = {
    "98f63c4d9c87edbd97ed4747fa031019": "Go x/crypto/ssh 客户端（chisel / 多数 Go 隧道）",
}
_KNOWN_HASSH_SERVER = {
    "e00b2581ca92fb8485f19dab86749755": "Go x/crypto/ssh 服务端（chisel 服务端）",
}


def ssh_stream_from_ws(direction_bytes: bytes) -> bytes:
    """从一个方向的字节里剥出被 WebSocket 帧包裹的 SSH 明文流（chisel 用法）。

    跳过 HTTP 升级握手头后，把所有二进制 / continuation 帧的载荷拼接还原为 SSH 字节流。
    """
    sep = direction_bytes.find(b"\r\n\r\n")
    body = direction_bytes[sep + 4:] if sep >= 0 else direction_bytes
    out = bytearray()
    for opcode, _fin, payload in parse_ws_frames(body):
        if opcode in (0x2, 0x0):  # binary / continuation
            out += payload
    return bytes(out)


def _ssh_body(stream: bytes) -> bytes:
    """跳过 ``SSH-...`` 版本标识行，返回其后的 SSH 二进制包区。"""
    if stream[:4] == b"SSH-":
        nl = stream.find(b"\n")
        if nl >= 0:
            return stream[nl + 1:]
    return stream


def find_kexinit(ssh_stream: bytes):
    """在 SSH 明文字节流里定位 SSH_MSG_KEXINIT，返回其 payload；未找到返回 None。

    SSH 二进制包结构（RFC 4253）：uint32 packet_length | byte padding_length |
    payload | random padding。密钥协商完成前的 KEXINIT 为明文。
    """
    data = _ssh_body(ssh_stream)
    i, n = 0, len(data)
    while i + 6 <= n:
        plen = int.from_bytes(data[i:i + 4], "big")
        if plen < 2 or plen > 35000 or i + 4 + plen > n:
            i += 1
            continue
        pad = data[i + 4]
        msg = data[i + 5]
        if msg == SSH_MSG_KEXINIT:
            end = i + 4 + plen - pad
            return data[i + 5:end] if end > i + 5 else None
        i += 4 + plen
    return None


def _namelist(buf: bytes, off: int):
    ln = int.from_bytes(buf[off:off + 4], "big")
    off += 4
    return buf[off:off + ln].decode("latin1", "ignore"), off + ln


def parse_kexinit(payload: bytes):
    """解析 KEXINIT payload，返回各算法 name-list 字符串的字典；结构异常返回 None。"""
    try:
        off = 1 + 16  # msg 类型 + 16 字节 cookie
        kex, off = _namelist(payload, off)
        hostkey, off = _namelist(payload, off)
        enc_cs, off = _namelist(payload, off)
        enc_sc, off = _namelist(payload, off)
        mac_cs, off = _namelist(payload, off)
        mac_sc, off = _namelist(payload, off)
        comp_cs, off = _namelist(payload, off)
        comp_sc, off = _namelist(payload, off)
    except (IndexError, ValueError):
        return None
    return {
        "kex": kex, "hostkey": hostkey,
        "enc_cs": enc_cs, "enc_sc": enc_sc,
        "mac_cs": mac_cs, "mac_sc": mac_sc,
        "comp_cs": comp_cs, "comp_sc": comp_sc,
    }


def compute_hassh(kexinit_payload: bytes, is_server: bool = False):
    """由 KEXINIT payload 计算 (hassh_md5, 算法串)。解析失败返回 None。"""
    fields = parse_kexinit(kexinit_payload)
    if not fields:
        return None
    if is_server:
        parts = [fields["kex"], fields["enc_sc"], fields["mac_sc"], fields["comp_sc"]]
    else:
        parts = [fields["kex"], fields["enc_cs"], fields["mac_cs"], fields["comp_cs"]]
    algostr = ";".join(parts)
    return hashlib.md5(algostr.encode("latin1", "ignore")).hexdigest(), algostr


def classify_hassh(md5hash: str, is_server: bool = False):
    """比对已知 HASSH 表，命中返回实现/工具名，否则 None。"""
    table = _KNOWN_HASSH_SERVER if is_server else _KNOWN_HASSH
    return table.get((md5hash or "").lower())


def hassh_from_ws_direction(direction_bytes: bytes, is_server: bool = False):
    """便捷入口：从 WebSocket 包裹的一个方向字节里直接算 HASSH。

    返回 (md5, 算法串, 归属名或None)；该方向无可解析 KEXINIT 时返回 None。
    """
    ssh = ssh_stream_from_ws(direction_bytes)
    kx = find_kexinit(ssh)
    if kx is None:
        return None
    res = compute_hassh(kx, is_server=is_server)
    if res is None:
        return None
    md5, algostr = res
    return md5, algostr, classify_hassh(md5, is_server=is_server)
