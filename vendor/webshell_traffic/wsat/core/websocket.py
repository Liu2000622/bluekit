# -*- coding: utf-8 -*-
"""
WebSocket 帧解析（RFC 6455）：握手升级为 WS 后，控制/数据都以帧承载。此模块把
握手后的字节流拆成帧、去客户端掩码、重组 text/binary 消息，供隧道 / webshell-over-WS
分析surface解码内容——弥补此前只识别 WS 握手、不解帧的盲区。
"""

import re

# 帧操作码
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA
_CONTROL = {OP_CLOSE, OP_PING, OP_PONG}

_WS_UPGRADE_RE = re.compile(rb"upgrade:\s*websocket", re.I)
_WS_KEY_RE = re.compile(rb"sec-websocket-(key|accept):", re.I)


def is_ws_handshake(data: bytes) -> bool:
    """字节是否含 WebSocket 升级握手（请求的 Upgrade 头或响应的 101 + Sec-WebSocket-*）。"""
    head = data[:1024]
    if _WS_UPGRADE_RE.search(head) and _WS_KEY_RE.search(head):
        return True
    return head.startswith(b"HTTP/1.1 101") and _WS_UPGRADE_RE.search(head) is not None


def parse_ws_frames(data: bytes):
    """解析 WebSocket 帧，yield (opcode, fin, payload)；掩码帧自动去掩码。残缺尾部忽略。"""
    i, n = 0, len(data)
    while i + 2 <= n:
        b0, b1 = data[i], data[i + 1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        plen = b1 & 0x7F
        j = i + 2
        if plen == 126:
            if j + 2 > n:
                break
            plen = int.from_bytes(data[j:j + 2], "big")
            j += 2
        elif plen == 127:
            if j + 8 > n:
                break
            plen = int.from_bytes(data[j:j + 8], "big")
            j += 8
        mask = b""
        if masked:
            if j + 4 > n:
                break
            mask = data[j:j + 4]
            j += 4
        if plen > n - j:                 # 声明长度超出剩余字节：残缺，停止
            break
        payload = data[j:j + plen]
        if masked:
            payload = bytes(payload[k] ^ mask[k & 3] for k in range(plen))
        yield opcode, fin, payload
        i = j + plen


def reassemble_ws_messages(frames):
    """把帧序列重组为消息，返回 [(opcode, message_bytes), ...]（仅 text/binary 数据消息，
    合并 continuation，跳过 close/ping/pong 控制帧）。"""
    out = []
    cur_op = None
    buf = bytearray()
    for opcode, fin, payload in frames:
        if opcode in _CONTROL:
            continue
        if opcode == OP_CONTINUATION:
            if cur_op is None:
                continue
            buf += payload
        else:
            if cur_op is not None:       # 上一条未 FIN 收尾，先落一条
                out.append((cur_op, bytes(buf)))
            cur_op = opcode
            buf = bytearray(payload)
        if fin and cur_op is not None:
            out.append((cur_op, bytes(buf)))
            cur_op, buf = None, bytearray()
    if cur_op is not None:
        out.append((cur_op, bytes(buf)))
    return out


def frames_after_handshake(direction_bytes: bytes):
    """跳过 HTTP 升级握手头（首个 \\r\\n\\r\\n）后解析并重组 WS 消息；无握手则从头解析。"""
    sep = direction_bytes.find(b"\r\n\r\n")
    body = direction_bytes[sep + 4:] if sep >= 0 else direction_bytes
    return reassemble_ws_messages(parse_ws_frames(body))


def frame_sizes_after_handshake(direction_bytes: bytes):
    """返回握手后每个数据帧（text/binary/continuation）的载荷长度列表。

    用于对**加密**隧道做元数据 / 行为分析：不看内容，只看帧大小分布与数量。
    """
    sep = direction_bytes.find(b"\r\n\r\n")
    body = direction_bytes[sep + 4:] if sep >= 0 else direction_bytes
    return [len(payload) for opcode, _fin, payload in parse_ws_frames(body)
            if opcode in (OP_TEXT, OP_BINARY, OP_CONTINUATION)]
