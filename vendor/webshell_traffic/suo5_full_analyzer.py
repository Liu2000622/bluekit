#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
suo5 隧道协议原语 + 命令行/GUI 入口。

suo5 通过 HTTP(POST，多为 chunked 长连接) 建立全双工 TCP 隧道：
  帧格式 = [4 字节大端总长][1 字节 XOR key][XOR 后的 KLV 载荷]
  KLV    = 重复的 [1 字节 key 长][key][4 字节大端 value 长][value]
  常见键：ac(动作，\\x00=连接建立) / dt(隧道数据) / h(目标host) / p(目标port)

本模块只保留「协议原语 + 特征研判 + 分层还原」，识别/解密/报告统一走
auto_analyzer 引擎与 Suo5Plugin，避免与自动分析维护两套逻辑。
"""
from __future__ import annotations

import argparse
import base64
import struct
import sys

# 供 Suo5Plugin 复用的默认指纹（单独出现不足以判定 suo5，须结合结构与流量特征）
SUO5_DEFAULT_USER_AGENT = ("Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3")
SUO5_ACCEL_BUFFERING_HEADER = "X-Accel-Buffering: no"
_AC_CONNECT = b"\x00"

# suo5 KLV 里合法出现的键（用于压制随机 XOR 偶然解出的“伪 KLV”误报）
_SUO5_KEYS = {"ac", "dt", "h", "p", "s", "r", "id", "n", "st", "m"}


# --------------------------- 协议原语 ---------------------------

def _parse_klv(payload: bytes):
    """解析 XOR 之后的 KLV 载荷为 {key: value_bytes}；结构不合法返回 None。"""
    out = {}
    off, n = 0, len(payload)
    while off < n:
        klen = payload[off]
        off += 1
        if klen == 0 or off + klen > n:
            return None
        key = payload[off:off + klen].decode("latin1")
        off += klen
        if off + 4 > n:
            return None
        vlen = struct.unpack(">I", payload[off:off + 4])[0]
        off += 4
        if off + vlen > n:
            return None
        out[key] = payload[off:off + vlen]
        off += vlen
    return out or None


def _iter_frames_legacy(buf: bytes):
    """
    旧版（suo5 v1.x / classic）线格式：连续 [4 字节大端总长][1 字节 XOR key][XOR 后 KLV]。
    """
    off, n = 0, len(buf)
    frames = []
    while off + 5 <= n:
        data_len = struct.unpack(">I", buf[off:off + 4])[0]
        xor = buf[off + 4]
        start, end = off + 5, off + 5 + data_len
        if data_len <= 0 or end > n:
            break
        dec = bytes(b ^ xor for b in buf[start:end])
        klv = _parse_klv(dec)
        if klv is None:
            break
        frames.append(klv)
        off = end
    return frames


_B64URL_TRANS = bytes.maketrans(b"-_", b"+/")


def _b64url_decode(s: bytes):
    """URL-safe base64 解码（补齐 padding）；失败返回 None。"""
    s = bytes(s).translate(_B64URL_TRANS)
    s += b"=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return None


def _iter_frames_v2(buf: bytes):
    """
    新版（suo5 v2.x）线格式，与 assets/php/suo5.php marshalBase64 一致：
    连续帧 = base64url(6 字节头) + base64url(数据)：
      头 6 字节 = [xk0][xk1][len4]，其中 len4 为「base64 数据串长度」的大端 4 字节，
                 且被 2 字节 XOR key 交替异或（L[i] ^= xk[i%2]）；
      数据      = base64url( XOR2(KLV, xk) )，KLV 与旧版一致（含随机 '_' 垃圾字段）。
    """
    off, n = 0, len(buf)
    frames = []
    while off + 8 <= n:
        hdr = _b64url_decode(buf[off:off + 8])
        if hdr is None or len(hdr) < 6:
            break
        xk = (hdr[0], hdr[1])
        length = struct.unpack(
            ">I", bytes((hdr[2] ^ xk[0], hdr[3] ^ xk[1], hdr[4] ^ xk[0], hdr[5] ^ xk[1])))[0]
        if length <= 0 or off + 8 + length > n:
            break
        raw = _b64url_decode(buf[off + 8:off + 8 + length])
        if raw is None:
            break
        dec = bytes(raw[i] ^ xk[i % 2] for i in range(len(raw)))
        klv = _parse_klv(dec)
        if klv is None:
            break
        frames.append(klv)
        off += 8 + length
    return frames


def iter_suo5_frames(buf: bytes):
    """
    从（已去 chunk 的）字节流中按序解出 suo5 帧，逐个产出 raw-bytes KLV dict。

    自动兼容两种线格式：旧版 raw（v1.x/classic）与新版 base64url（v2.x）。优先取
    能解出「合法 suo5 KLV 结构」的那一种；都不合法时回退到非空的解析结果（供上层
    做形态判断），避免误配。
    """
    legacy = _iter_frames_legacy(buf)
    if is_suo5_frames(legacy):
        yield from legacy
        return
    v2 = _iter_frames_v2(buf)
    if is_suo5_frames(v2):
        yield from v2
        return
    yield from (legacy or v2)


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    off, n = 0, len(body)
    while off < n:
        crlf = body.find(b"\r\n", off)
        if crlf == -1:
            break
        try:
            size = int(body[off:crlf].split(b";", 1)[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = crlf + 2
        out += body[start:start + size]
        off = start + size + 2
    return bytes(out)


def parse_suo5_body(body: bytes, headers_lower: str):
    """把一段 HTTP 报文体解析为 suo5 帧列表（自动处理 chunked）。"""
    buf = _dechunk(body) if "transfer-encoding: chunked" in headers_lower else body
    return list(iter_suo5_frames(buf))


def klv_text(frame: dict) -> dict:
    """把 raw-bytes KLV 转为可读文本（供展示）。"""
    text = {}
    for k, v in frame.items():
        try:
            text[k] = v.decode("utf-8")
        except UnicodeDecodeError:
            text[k] = v.hex()
    return text


def is_suo5_frames(frames) -> bool:
    """帧列表是否呈 suo5 结构：含 ac/dt/h/p 且键均在已知集合内。"""
    for f in frames:
        if not f:
            continue
        if ({"ac", "dt"} & f.keys()) or ({"h", "p"} <= f.keys()):
            if all(len(k) <= 4 for k in f):
                return True
    return False


def looks_like_suo5_bytes(buf: bytes) -> bool:
    """
    裸字节流（如隧道内层）是否本身又是一层 suo5（用于识别嵌套/双重隧道）。

    两种情形：
      1. 内层直接就是 suo5 帧（全双工链式，内层数据即帧）；
      2. 内层是 HTTP 承载的 suo5（半双工链式：内层是对 suo5.php 的 HTTP 请求/响应，
         其报文体才是 suo5 帧）——对每条内层 HTTP 消息体再判一次。
    """
    if not buf:
        return False
    if is_suo5_frames(list(iter_suo5_frames(buf))):
        return True
    try:
        from webshell_crypto import iter_http_messages
    except Exception:
        return False
    for _head, body in iter_http_messages(bytes(buf)):
        if body and is_suo5_frames(list(iter_suo5_frames(body))):
            return True
    return False


# --------------------------- 分层还原 ---------------------------

def reconstruct_inner(req_frames, res_frames):
    """由请求/响应帧还原隧道目标与内层双向字节流。

    返回 (target 'h:p' 或 None, inner_client_bytes, inner_server_bytes)。
    """
    target = None
    inner_client = bytearray()
    for f in req_frames:
        if f.get("ac") == _AC_CONNECT and f.get("h") and f.get("p"):
            target = f["h"].decode("latin1", "ignore") + ":" + f["p"].decode("latin1", "ignore")
        if "dt" in f:
            inner_client += f["dt"]
    inner_server = bytearray()
    for f in res_frames:
        if "dt" in f:
            inner_server += f["dt"]
    return target, bytes(inner_client), bytes(inner_server)


def sniff_inner_protocol(client: bytes, server: bytes) -> str:
    """粗判隧道内层承载的真实协议（据握手 banner）。"""
    def check(b: bytes):
        b = b.lstrip()
        if not b:
            return None
        if b[:4] == b"SSH-":
            return "SSH"
        if b[:3] == b"\x03\x00\x00" or b"mstshash" in b[:80].lower():
            return "RDP"
        if b[:1] == b"\x16" and b[1:2] == b"\x03":
            return "TLS"
        if b[:5] == b"HTTP/" or b[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI"):
            return "HTTP"
        if b[:4] == b"RFB ":
            return "VNC"
        if b[:1] == b"\x05" and len(b) >= 3 and b[1] + 2 <= len(b):
            return "SOCKS5"
        if b[:1] == b"\x04" and len(b) >= 8:
            return "SOCKS4"
        return None

    for b in (client, server):
        proto = check(b)
        if proto:
            return proto
    return "raw/unknown"


# --------------------------- 多特征研判 ---------------------------

def suo5_features(request_bytes: bytes, response_bytes: bytes, packets, headers_lower: str):
    """综合流量特征（不依赖单一 header），返回布尔特征 dict。"""
    loads = [len(getattr(p, "load", b"")) for p in (packets or [])]
    times = [float(p.time) for p in (packets or []) if getattr(p, "time", None) is not None]
    small = sum(1 for n in loads if 0 < n < 512)
    # URI 复用：请求侧重复出现同一 POST/GET 路径
    paths = []
    for line in request_bytes.split(b"\r\n"):
        parts = line.split(b" ")
        if len(parts) >= 3 and parts[0] in (b"POST", b"GET", b"OPTIONS", b"PUT"):
            paths.append(parts[1])
    uri_reuse = bool(paths) and (len(paths) - len(set(paths)) >= 1)
    return {
        "header_ua": SUO5_DEFAULT_USER_AGENT.lower() in headers_lower,
        "header_xaccel": SUO5_ACCEL_BUFFERING_HEADER.lower() in headers_lower,
        "chunked": "transfer-encoding: chunked" in headers_lower,
        "long_lived": len(loads) >= 6,
        "duration_s": (max(times) - min(times)) if len(times) >= 2 else 0.0,
        "bidir": bool(request_bytes) and bool(response_bytes),
        "bidir_small": small >= 4 and bool(request_bytes) and bool(response_bytes),
        "high_freq": len(loads) >= 10,
        "uri_reuse": uri_reuse,
    }


def suo5_confidence(features: dict, structural: bool):
    """
    综合评分给出 (是否判定为 suo5, confidence_label, 命中的特征列表)。

    规则：结构可解（帧解出合法 KLV）即高置信度；否则要求 header 命中 + 至少 2 项
    流量特征（chunked/长连接/双向小包/高频/URI 复用）才判为疑似 suo5；单一 header
    不足以判定。
    """
    _TRAFFIC_LABEL = {
        "chunked": "chunked 流式", "long_lived": "长连接", "bidir_small": "双向小包",
        "high_freq": "高频交互", "uri_reuse": "URI 复用",
    }
    traffic = [k for k in _TRAFFIC_LABEL if features.get(k)]
    header = features.get("header_ua") or features.get("header_xaccel")
    hit_names = []
    if features.get("header_ua"):
        hit_names.append("默认 User-Agent")
    if features.get("header_xaccel"):
        hit_names.append("X-Accel-Buffering: no")
    hit_names += [_TRAFFIC_LABEL[k] for k in traffic]

    if structural:
        return True, "high", ["帧解密出合法 suo5 KLV 结构"] + hit_names
    if header and len(traffic) >= 2:
        return True, "medium", hit_names
    if len(traffic) >= 3:  # 无 header 但流量形态高度吻合
        return True, "low", hit_names
    return False, "low", hit_names


# --------------------------- GUI / CLI 入口（统一走引擎） ---------------------------

def process_pcap_to_excel(input_path, output_path, status_callback=print,
                          cancel_check=None, enable_rules=True, include_filtered=True,
                          high_med_only=False, mask_sensitive=False):
    """suo5 PCAP 分析：统一走 auto_analyzer 引擎，仅启用 Suo5Plugin。"""
    from auto_analyzer import analyze_pcap_auto
    from analyzers.legacy_plugins import Suo5Plugin
    return analyze_pcap_auto(
        input_path, output_path, plugins=[Suo5Plugin()], weak_dict=False,
        status_callback=status_callback, cancel_check=cancel_check,
        enable_rules=enable_rules, include_filtered=include_filtered,
        high_med_only=high_med_only, mask_sensitive=mask_sensitive)


def main():
    parser = argparse.ArgumentParser(description="Analyze suo5 tunnel traffic in a PCAP.")
    parser.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    parser.add_argument("-o", "--output", required=True, help="输出 Excel 报告路径")
    args = parser.parse_args()
    try:
        process_pcap_to_excel(args.input, args.output)
    except FileNotFoundError:
        print(f"[!] 找不到输入文件: {args.input}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
