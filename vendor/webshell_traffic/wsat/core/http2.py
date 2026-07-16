# -*- coding: utf-8 -*-
"""
HTTP/2 重构：把 h2c（明文 HTTP/2）或 TLS 解密后的 HTTP/2 流量拆帧、HPACK 解头、按
stream 重组为等价的 HTTP/1.1 报文，再交给现有 HTTP 插件识别——填补「h2 承载的
webshell / C2 / 漏洞利用」盲区（scapy 只给原始 TCP 字节，不解 h2 帧与 HPACK）。

依赖 scapy.contrib.http2 做帧结构与 HPACK 解码（延迟导入，仅 h2 流才加载）。
"""

from collections import OrderedDict

from wsat.core.pcap_utils import PacketInfo

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FT_DATA = 0x0
_FT_HEADERS = 0x1
_FT_CONTINUATION = 0x9


def looks_like_http2(data: bytes) -> bool:
    """是否以 HTTP/2 连接前言开头（客户端方向，h2c 或解密后 h2 均先发前言）。"""
    return bytes(data[:24]) == _PREFACE


def _iter_frames(data: bytes):
    """逐个产出 (ftype, flags, stream_id, frame_bytes, payload)；残缺尾部忽略。"""
    i, n = 0, len(data)
    while i + 9 <= n:
        flen = int.from_bytes(data[i:i + 3], "big")
        ftype = data[i + 3]
        flags = data[i + 4]
        sid = int.from_bytes(data[i + 5:i + 9], "big") & 0x7FFFFFFF
        end = i + 9 + flen
        if end > n:
            break
        yield ftype, flags, sid, data[i:end], data[i + 9:end]
        i = end


def _data_payload(flags: int, payload: bytes) -> bytes:
    """DATA 帧去 PADDED 填充后的正文。"""
    if flags & 0x08 and payload:                 # PADDED
        pad = payload[0]
        return payload[1:len(payload) - pad] if pad < len(payload) else b""
    return payload


def _decode_headers(hpack_tbl, frame_bytes):
    """用 HPACK 动态表解码一个 HEADERS/CONTINUATION 帧，返回 [(name, value), ...]。"""
    from scapy.contrib.http2 import H2Frame
    try:
        rep = hpack_tbl.gen_txt_repr(H2Frame(frame_bytes))
    except Exception:  # noqa: BLE001 - HPACK 解码尽力而为，失败跳过该帧
        return []
    out = []
    for line in rep.splitlines():
        if line:
            # 伪首部形如 ":method POST"；普通首部形如 "content-type: value"（名字带尾冒号）
            name, _sep, value = line.partition(" ")
            out.append((name.rstrip(":"), value))
    return out


def _to_http1(headers, body: bytes, is_client: bool) -> bytes:
    """把一条 h2 stream 的头/体渲染为 HTTP/1.1 报文字节。"""
    hd = dict(headers)
    lines = []
    if is_client:
        lines.append(f"{hd.get(':method', 'GET')} {hd.get(':path', '/')} HTTP/1.1")
        if hd.get(":authority"):
            lines.append(f"Host: {hd[':authority']}")
    else:
        lines.append(f"HTTP/1.1 {hd.get(':status', '200')} OK")
    for name, value in headers:
        if not name.startswith(":"):
            lines.append(f"{name}: {value}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "ignore")
    return head + body


def _reconstruct_direction(data: bytes, is_client: bool) -> bytes:
    from scapy.contrib.http2 import HPackHdrTable
    buf = data[len(_PREFACE):] if looks_like_http2(data) else data
    tbl = HPackHdrTable()                        # HPACK 动态表按方向独立维护
    streams = OrderedDict()
    for ftype, flags, sid, frame_bytes, payload in _iter_frames(buf):
        if ftype in (_FT_HEADERS, _FT_CONTINUATION):
            slot = streams.setdefault(sid, {"headers": [], "body": bytearray()})
            slot["headers"].extend(_decode_headers(tbl, frame_bytes))
        elif ftype == _FT_DATA:
            slot = streams.setdefault(sid, {"headers": [], "body": bytearray()})
            slot["body"] += _data_payload(flags, payload)
    msgs = [_to_http1(s["headers"], bytes(s["body"]), is_client)
            for s in streams.values() if s["headers"] or s["body"]]
    return b"".join(msgs)


def reconstruct_http2(directions):
    """directions: {dir_key: bytes}。任一方向以 h2 连接前言开头则重构，返回
    {dir_key: http1_bytes}；否则 None（非 h2，调用方保持原样）。"""
    client_key = next((k for k, v in directions.items() if looks_like_http2(bytes(v))), None)
    if client_key is None:
        return None
    out = OrderedDict()
    for k, v in directions.items():
        out[k] = _reconstruct_direction(bytes(v), is_client=(k == client_key))
    return out


def synth_packets(directions, base_time):
    """把重构后的每方向字节合成为单条 PacketInfo，供 iter_http_transactions 等按包分析。"""
    out = []
    for (s, sp), (d, dp) in directions:
        load = directions[((s, sp), (d, dp))]
        if load:
            out.append(PacketInfo(base_time, s, sp, d, dp, bytes(load)))
    return out
