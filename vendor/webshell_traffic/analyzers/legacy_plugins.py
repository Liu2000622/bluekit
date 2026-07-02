# -*- coding: utf-8 -*-
"""现有 suo5 / 哥斯拉 / 冰蝎分析器的插件适配层。"""
from __future__ import annotations

import base64
import binascii
import re
from collections import OrderedDict
from urllib.parse import unquote, urlsplit

from analyzers.base import AnalysisContext, AnalyzerPlugin, DetectionResult, StreamData
from analysis_record import (
    AnalysisRecord,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DECRYPT_SUCCESS,
    DECRYPT_FAILED,
    DECODE_TEXT,
    DECODE_BINARY_PAYLOAD,
    DECODE_PARTIAL,
    DECODE_GARBLED,
    DECODE_FAILED,
    classify_content,
    content_sha256,
    make_preview,
)
from http_transactions import iter_http_transactions
from pcap_utils import split_http_message
from suo5_full_analyzer import (
    SUO5_ACCEL_BUFFERING_HEADER,
    SUO5_DEFAULT_USER_AGENT,
    is_suo5_frames,
    iter_suo5_frames,
    looks_like_suo5_bytes,
    reconstruct_inner,
    sniff_inner_protocol,
    suo5_confidence,
    suo5_features,
)
from analysis_record import RISK_MEDIUM
from webshell_crypto import behinder_beautify, behinder_decrypt, godzilla_decrypt, iter_http_messages


_HTTP_METHOD_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"OPTIONS ", b"HEAD ")
_DEFAULT_GODZILLA_CRYPTERS = [
    "AES_BASE64 (V4 Default)",
    "XOR_BASE64 (V3 Default)",
    "PHP_EVAL_XOR_BASE64",
]


def _flows(stream: StreamData):
    return list(stream.directions.values())


def _request_response(stream: StreamData):
    request = response = None
    for data in _flows(stream):
        parsed = False
        for head, body in iter_http_messages(bytes(data)):
            parsed = True
            msg = head + b"\r\n\r\n" + body
            if head.startswith(_HTTP_METHOD_PREFIXES) and request is None:
                request = msg
            elif head.startswith(b"HTTP/") and response is None:
                response = msg
        if not parsed and data.startswith(_HTTP_METHOD_PREFIXES):
            request = data
        elif not parsed and data.startswith(b"HTTP/"):
            response = data
    if request is None and stream.directions:
        request = next(iter(stream.directions.values()))
    return request, response


def _request_uri(request: bytes) -> str:
    try:
        first = request.split(b"\r\n", 1)[0].decode("utf-8", "ignore")
        parts = first.split()
        return parts[1] if len(parts) >= 2 else ""
    except Exception:
        return ""


def _looks_base64(body: bytes, min_len: int = 24) -> bool:
    sample = body.strip()
    if len(sample) < min_len:
        return False
    if not re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", sample):
        return False
    try:
        base64.b64decode(sample + b"=" * (-len(sample) % 4), validate=False)
        return True
    except (binascii.Error, ValueError):
        return False


def _encrypted_body(body: bytes) -> bool:
    """
    请求体是否呈「加密载荷」形态：含较长 base64 串、或二进制密文、或 v4 json/image
    自定义传输。用于冰蝎识别（其请求体为裸密文，而非普通表单）。
    """
    if not body or len(body) < 16:
        return False
    if re.search(rb"[A-Za-z0-9+/]{40,}={0,2}", body):        # 长 base64 串（含 json 内嵌）
        return True
    head = body[:256]
    nonprint = sum(1 for c in head if c < 9 or (13 < c < 32) or c >= 127)
    return nonprint / len(head) > 0.15                       # 二进制密文


# ---------------------------------------------------------------------------
# HTTP 事务级记录构建（一次请求/响应 = 一条记录）
# ---------------------------------------------------------------------------

# 家族标记：从「解密后的内容」判定真实家族，避免把 Behinder/Rebeyond 的 Java 载荷
# 误标成 Godzilla（两者同为 md5(key)[:16] + AES/ECB，解密器可互相解开）。
_FAMILY_MARKERS = [
    ("Behinder", ("net/rebeyond/behinder", "rebeyond", "behinder")),
    ("Godzilla", ("methodname", "binarydata", "getbasicsinfo", "parameters")),
]
_ANALYZER_DEFAULT_FAMILY = {"godzilla": "Godzilla", "behinder": "Behinder", "suo5": "suo5"}

# decode_status 合并优先级：一次事务里只要请求或响应解出可读命令即视为有效目标流量。
_DECODE_PRIORITY = {
    DECODE_TEXT: 4,
    DECODE_BINARY_PAYLOAD: 3,
    DECODE_PARTIAL: 2,
    DECODE_GARBLED: 1,
    DECODE_FAILED: 0,
}

_DECODE_REASON = {
    DECODE_BINARY_PAYLOAD: "已解密为二进制/字节码载荷（Java class/序列化/PE），见「载荷结构分析」",
    DECODE_PARTIAL: "已解密但疑似仍为 base64/JSON 内嵌，需二次解码",
    DECODE_GARBLED: "解密结果乱码（疑似密钥错误或非目标流量）",
    DECODE_FAILED: "候选密钥/密码未解出有效内容",
}


def _sniff_family(analyzer: str, texts):
    """依据解密后内容判定家族。返回 (primary, candidates, confidence, evidence)。"""
    default = _ANALYZER_DEFAULT_FAMILY.get(analyzer, analyzer)
    blob = "\n".join(t for t in texts if t).lower()
    hits, evidence = [], []
    for fam, markers in _FAMILY_MARKERS:
        for mk in markers:
            if mk in blob:
                hits.append(fam)
                evidence.append(f"{fam}:命中内容标记 '{mk}'")
                break
    if not hits:
        return default, [default], "medium", f"由 {analyzer} 分析器识别（无内容级家族标记）"
    candidates = list(dict.fromkeys(hits + [default]))
    primary = hits[0]
    confidence = "high" if len(set(hits)) == 1 else "medium"
    return primary, candidates, confidence, "；".join(evidence)


def _merge_classes(cls_req, cls_res):
    """合并请求/响应的分层判定，取优先级最高的 decode_status 作为事务判定。"""
    chosen = None
    for cls in (cls_req, cls_res):
        if cls is None:
            continue
        if chosen is None or _DECODE_PRIORITY.get(cls["decode_status"], 0) > _DECODE_PRIORITY.get(chosen["decode_status"], 0):
            chosen = cls
    if chosen is None:
        return {"decode_status": DECODE_FAILED, "content_type": "unknown",
                "readable_ratio": 0.0, "is_binary": False, "is_garbled": False,
                "next_decode_hint": ""}
    return chosen


def _build_txn_record(stream, txn, analyzer, req_plain, res_plain, algos, detection):
    """把一次已解密的 HTTP 事务构建为一条 AnalysisRecord（含时间/方向/家族/分层）。"""
    client_ip, _client_port = txn.client
    server_ip, server_port = txn.server
    cls_req = classify_content(req_plain) if req_plain else None
    cls_res = classify_content(res_plain) if res_plain else None
    cls = _merge_classes(cls_req, cls_res)
    decode_status = cls["decode_status"]
    valid = decode_status == DECODE_TEXT

    combined = "\n".join(x for x in (req_plain, res_plain) if x)
    primary_family, candidates, fam_conf, fam_ev = _sniff_family(
        analyzer, [req_plain, res_plain])

    if req_plain and res_plain:
        logical = "request+response"
    elif req_plain:
        logical = "request"
    else:
        logical = "response"

    raw_src = txn.request.src_ip if txn.request else (txn.response.src_ip if txn.response else None)
    raw_dst = txn.request.dst_ip if txn.request else (txn.response.dst_ip if txn.response else None)

    note = ""
    uniq_algos = list(dict.fromkeys(a for a in algos if a))
    if uniq_algos:
        note = f"解密算法: {', '.join(uniq_algos)}"

    rec = AnalysisRecord(
        analyzer=analyzer,
        stream_id=stream.stream_id,
        http_transaction_id=f"{stream.stream_id}#tx{txn.index:03d}",
        timestamp=txn.start_time,
        request_time=txn.request_time,
        response_time=txn.response_time,
        last_packet_time=txn.last_packet_time,
        duration_ms=txn.duration_ms,
        packet_start=txn.packet_start,
        packet_end=txn.packet_end,
        method=txn.method or None,
        uri=txn.uri or None,
        src_ip=client_ip or None,
        dst_ip=server_ip or None,
        client_ip=client_ip or None,
        server_ip=server_ip or None,
        server_port=server_port or None,
        raw_src_ip=raw_src,
        raw_dst_ip=raw_dst,
        logical_direction=logical,
        request=req_plain,
        response=res_plain,
        decoded_command=req_plain,
        decoded_response=res_plain,
        content_preview=make_preview(combined),
        content_sha256=content_sha256(combined),
        content_type=cls["content_type"],
        readable_ratio=cls["readable_ratio"],
        is_binary=cls["is_binary"],
        is_garbled=cls["is_garbled"],
        decode_layer=(" / ".join(uniq_algos) or None),
        decode_status=decode_status,
        next_decode_hint=cls.get("next_decode_hint") or None,
        decrypt_status=DECRYPT_SUCCESS,
        is_valid_target_flow=valid,
        confidence=CONFIDENCE_HIGH if valid else CONFIDENCE_MEDIUM,
        detect_confidence=(detection.confidence_label if detection else None),
        primary_family=primary_family,
        candidate_families=candidates,
        family_confidence=fam_conf,
        family_evidence=fam_ev,
        analyst_note=note or None,
    )
    if not valid:
        rec.filter_reason = _DECODE_REASON.get(decode_status)
    return rec


def _decode_transactions(stream, txns, analyzer, decrypt_fn, detection):
    """对每个 HTTP 事务用 decrypt_fn 解密请求/响应体，返回 (records, any_valid)。"""
    records = []
    any_valid = False
    for txn in txns:
        req_plain = res_plain = None
        algos = []
        if txn.request and txn.request.body:
            plain, algo = decrypt_fn(txn.request.body, False)
            if plain:
                req_plain, _ = plain, algos.append(algo)
        if txn.response and txn.response.body:
            plain, algo = decrypt_fn(txn.response.body, True)
            if plain:
                res_plain, _ = plain, algos.append(algo)
        if req_plain is None and res_plain is None:
            continue
        rec = _build_txn_record(stream, txn, analyzer, req_plain, res_plain, algos, detection)
        records.append(rec)
        if rec.is_valid_target_flow:
            any_valid = True
    return records, any_valid


def _pending_record(analyzer, stream, txns, uri, detection, reason):
    """构建「已识别但待补充密钥/试解失败」的记录，同样带上时间/IP 便于进时间线。"""
    txn = txns[0] if txns else None
    if txn is not None:
        client_ip = txn.client[0] or None
        server_ip, server_port = txn.server
        method = txn.method or None
        the_uri = uri or txn.uri or None
        ts = txn.start_time
        req_t = txn.request_time
    else:
        client_ip = stream.key[0][0]
        server_ip, server_port = stream.key[1][0], stream.key[1][1]
        method = None
        the_uri = uri or None
        ts = stream.timestamp
        req_t = None
    family = _ANALYZER_DEFAULT_FAMILY.get(analyzer, analyzer)
    return AnalysisRecord(
        analyzer=analyzer,
        stream_id=stream.stream_id,
        http_transaction_id=(f"{stream.stream_id}#tx{txn.index:03d}" if txn else None),
        timestamp=ts,
        request_time=req_t,
        method=method,
        uri=the_uri,
        src_ip=client_ip,
        dst_ip=server_ip or None,
        client_ip=client_ip,
        server_ip=server_ip or None,
        server_port=server_port or None,
        decrypt_status=DECRYPT_FAILED,
        is_valid_target_flow=False,
        confidence=CONFIDENCE_LOW,
        decode_status=DECODE_FAILED,
        filter_reason=reason,
        detect_confidence=(detection.confidence_label if detection else None),
        primary_family=family,
        candidate_families=[family],
    )


def _suo5_directions(stream: StreamData):
    """按方向重组该流的字节：优先用 packets（引擎与测试均带），回退 directions。"""
    from collections import OrderedDict
    by_dir = OrderedDict()
    for info in (stream.packets or []):
        dk = ((info.src, info.sport), (info.dst, info.dport))
        by_dir.setdefault(dk, bytearray())
        by_dir[dk] += info.load
    if not by_dir and stream.directions:
        for dk, b in stream.directions.items():
            by_dir[dk] = bytearray(bytes(b))
    return by_dir


def _suo5_split(stream: StreamData):
    """把一条 TCP 流拆为 suo5 请求/响应侧：返回 client/server 定位、合并头、帧列表。"""
    client_ip = server_ip = None
    server_port = None
    heads = []
    req_raw = res_raw = b""
    req_frames, res_frames = [], []
    for dk, dbytes in _suo5_directions(stream).items():
        dbytes = bytes(dbytes)
        token = dbytes[:8].split(b" ", 1)[0]
        is_req = token in (b"POST", b"GET", b"PUT", b"OPTIONS", b"HEAD", b"DELETE")
        first_head = b""
        body_all = bytearray()
        parsed = False
        for i, (head, body) in enumerate(iter_http_messages(dbytes)):
            parsed = True
            if i == 0:
                first_head = head
            body_all += body
        if not parsed:
            body_all += dbytes
        if first_head:
            heads.append(first_head)
        frames = list(iter_suo5_frames(bytes(body_all)))
        if is_req:
            req_raw, req_frames = dbytes, frames
            (c, _cp), (s, sp) = dk
            client_ip, server_ip, server_port = c, s, sp
        else:
            res_raw, res_frames = dbytes, frames
    if client_ip is None:  # 未能判定请求方向，回退到规范化 key
        client_ip, server_ip, server_port = stream.key[0][0], stream.key[1][0], stream.key[1][1]
    headers_low = b"\n".join(heads).decode("utf-8", "ignore").lower()
    return client_ip, server_ip, server_port, headers_low, req_raw, res_raw, req_frames, res_frames


def _unwrap_frames(buf):
    """从内层字节解 suo5 帧：先按裸帧，失败再按「HTTP 承载的 suo5」逐消息体解。

    双重/嵌套 suo5 的内层多为对下一跳 suo5.php 的 HTTP 请求/响应，其报文体才是
    真正的 suo5 帧——这里与 looks_like_suo5_bytes 的检测口径保持一致（de-HTTP）。
    """
    if not buf:
        return []
    frames = list(iter_suo5_frames(bytes(buf)))
    if is_suo5_frames(frames):
        return frames
    acc = []
    try:
        for _head, body in iter_http_messages(bytes(buf)):
            if body:
                acc.extend(iter_suo5_frames(bytes(body)))
    except Exception:  # noqa: BLE001 - 内层解析尽力而为
        pass
    return acc if is_suo5_frames(acc) else frames


def _suo5_unwrap_chain(req_frames, res_frames, max_depth=4):
    """
    从最外层帧递归解出 suo5 隧道链（含嵌套/双重）。

    返回 (hops, inner_client_bytes, inner_server_bytes, inner_proto)：
      hops = [target 'h:p' 或 None, ...] 每层隧道的转发目标；
      最内层非 suo5 时给出承载协议与双向字节。
    """
    hops = []
    cur_req, cur_res = req_frames, res_frames
    depth = 0
    while True:
        target, inner_c, inner_s = reconstruct_inner(cur_req, cur_res)
        # 端口 0 / 127.0.0.1:0 是 suo5 的连通性探测连接，不是真实转发目标
        if target and target.endswith(":0"):
            target = None
        hops.append(target)
        nxt_req = _unwrap_frames(inner_c)
        nxt_res = _unwrap_frames(inner_s)
        nested = is_suo5_frames(nxt_req) or is_suo5_frames(nxt_res)
        if nested and depth + 1 < max_depth:
            cur_req, cur_res, depth = nxt_req, nxt_res, depth + 1
            continue
        return hops, inner_c, inner_s, sniff_inner_protocol(inner_c, inner_s)


class Suo5Plugin(AnalyzerPlugin):
    """suo5 隧道：多特征综合研判 + outer/inner 分层还原（含嵌套/双重 suo5）。"""

    name = "suo5"
    category = "tunnel"
    requires_key = False
    can_decrypt = True

    def detect(self, stream: StreamData):
        if not stream.packets and not stream.directions:
            return None
        _c, _s, _sp, headers_low, req_raw, res_raw, req_frames, res_frames = _suo5_split(stream)
        structural = is_suo5_frames(req_frames) or is_suo5_frames(res_frames)
        feats = suo5_features(req_raw, res_raw, stream.packets, headers_low)
        is_suo5, label, hits = suo5_confidence(feats, structural)
        if not is_suo5:
            return None
        conf = {"high": 0.9, "medium": 0.7, "low": 0.55}[label]
        return DetectionResult(
            self.name, conf, label,
            [f"suo5 多特征综合判定（{'结构可解' if structural else '疑似'}）: " + "、".join(hits)],
            {"structural": structural},
        )

    def _times(self, stream):
        times = [float(p.time) for p in (stream.packets or [])
                 if getattr(p, "time", None) is not None]
        if not times:
            return stream.timestamp, stream.timestamp, None
        dur = round((max(times) - min(times)) * 1000, 3) if len(times) >= 2 else None
        return min(times), max(times), dur

    @staticmethod
    def _text(data: bytes, limit=4000):
        if not data:
            return None
        return bytes(data)[:limit].decode("utf-8", "replace")

    def _mk(self, *, client_ip, server_ip, server_port, first_t, last_t, layer, family,
            direction, request, response, target, valid, note, detect_conf, nested=False,
            dstatus=DECODE_TEXT, hint=None, stream_id=None, packet_end=None):
        dur = (round((last_t - first_t) * 1000, 3)
               if first_t is not None and last_t is not None and last_t > first_t else None)
        sid = stream_id or f"{client_ip}->{server_ip}:{server_port}"
        combined = "\n".join(x for x in (request, response) if x)
        return AnalysisRecord(
            analyzer=self.name, stream_id=sid, http_transaction_id=f"{sid}#{layer}",
            timestamp=first_t, request_time=first_t, response_time=last_t,
            last_packet_time=last_t, duration_ms=dur,
            packet_start=0 if packet_end is not None else None, packet_end=packet_end,
            uri=target, src_ip=client_ip, dst_ip=server_ip,
            client_ip=client_ip, server_ip=server_ip, server_port=server_port,
            logical_direction=direction, request=request, response=response,
            decoded_command=request, decoded_response=response,
            content_preview=make_preview(combined), content_sha256=content_sha256(combined),
            content_type="suo5_tunnel", decode_status=dstatus,
            is_valid_target_flow=valid, decrypt_status=DECRYPT_SUCCESS,
            confidence=CONFIDENCE_HIGH if valid else CONFIDENCE_LOW,
            detect_confidence=detect_conf, risk_level=RISK_MEDIUM,
            behavior_tags=["隧道代理/流量转发"],
            primary_family=family, family_confidence=detect_conf,
            candidate_families=([family, "suo5(双重隧道)"] if nested else [family]),
            next_decode_hint=hint, analyst_note=note)

    def _chain_records(self, *, client_ip, server_ip, server_port, hops, fc, fs, proto,
                       first_t, last_t, detect_conf, req_n, res_n, n_conn=1,
                       is_pivot=False, stream_id=None, packet_end=None, emit_inner=True):
        """把一条（可能多跳的）suo5 隧道链渲染为分层记录：外层 + 各内层跳 + 内层内容。"""
        depth = max(1, len(hops))
        nested = depth >= 2
        common = dict(client_ip=client_ip, server_ip=server_ip, server_port=server_port,
                      first_t=first_t, last_t=last_t, detect_conf=detect_conf,
                      nested=nested, stream_id=stream_id, packet_end=packet_end)
        recs = []
        role = "中间跳" if is_pivot else "入口"
        kind = "双重/嵌套 suo5" if nested else "suo5"
        chain_txt = " → ".join(f"[{t or '?'}]" for t in hops) or "[?]"
        summary = (f"{kind} 隧道链[{role}] {client_ip}→{server_ip}:{server_port} 经 {chain_txt} "
                   f"内层={proto} | 连接数={n_conn} 上行帧={req_n} 下行帧={res_n}")
        recs.append(self._mk(
            layer="outer", family="suo5(外层)" if nested else "suo5",
            direction="outer tunnel (client->server)" + (" [pivot]" if is_pivot else ""),
            request=summary, response=None, target=hops[0] if hops else None, valid=True,
            note=f"suo5 隧道链，跳数={depth}，最终内层协议={proto}", **common))
        for i in range(1, len(hops)):
            recs.append(self._mk(
                layer=f"hop{i + 1}", family="suo5(内层)", direction="inner tunnel",
                request=f"suo5 内层隧道[第{i + 1}跳] 目标={hops[i] or '未知'}", response=None,
                target=hops[i], valid=True,
                note="嵌套/双重 suo5：外层隧道内再次承载 suo5", **common))
        if emit_inner:
            recs += self._inner_records(hops=hops, fc=fc, fs=fs, proto=proto, **common)
        return recs

    def _inner_records(self, *, hops, fc, fs, proto, nested, client_ip, server_ip,
                       server_port, first_t, last_t, detect_conf, stream_id, packet_end):
        fct, fst = self._text(fc), self._text(fs)
        combined = "\n".join(x for x in (fct, fst) if x)
        if not combined:
            return []
        fam = "suo5(内层)" if nested else "suo5"
        common = dict(client_ip=client_ip, server_ip=server_ip, server_port=server_port,
                      first_t=first_t, last_t=last_t, detect_conf=detect_conf, nested=nested,
                      stream_id=stream_id, packet_end=packet_end, family=fam,
                      target=hops[-1] if hops else None)
        if classify_content(combined)["decode_status"] == DECODE_TEXT:
            return [self._mk(layer="inner-data", direction=f"inner data [{proto}]",
                             request=fct, response=fst, valid=True,
                             note=f"隧道最终承载: {proto}", **common)]
        # 未解出可读协议：标半解码，不把 base64/编码分片当作明文命令（避免误导）
        return [self._mk(layer="inner-data", direction=f"inner data [{proto}]",
                         request=fct, response=fst, valid=False, dstatus=DECODE_PARTIAL,
                         note="内层未解出可读协议（疑似下一跳 suo5 分片或未识别编码）",
                         hint="内层疑似仍为 suo5/编码数据，需按下一跳会话进一步解码", **common)]

    def analyze(self, stream: StreamData, context: AnalysisContext):
        detection = context.detection or self.detect(stream)
        (client_ip, server_ip, server_port, _hl,
         _rr, _sr, req_frames, res_frames) = _suo5_split(stream)
        hops, fc, fs, proto = _suo5_unwrap_chain(req_frames, res_frames)
        first_t, last_t, _dur = self._times(stream)
        return self._chain_records(
            client_ip=client_ip, server_ip=server_ip, server_port=server_port,
            hops=hops, fc=fc, fs=fs, proto=proto, first_t=first_t, last_t=last_t,
            detect_conf=(detection.confidence_label if detection else None),
            req_n=len(req_frames), res_n=len(res_frames), n_conn=1,
            stream_id=stream.stream_id,
            packet_end=(len(stream.packets) - 1 if stream.packets else None))

    def finalize(self, pairs, context):
        """
        会话级归并：按 (client, server:port, uri) 把 suo5 全双工多连接聚合为会话。

        - 拓扑/隧道链：跨连接聚合（还原完整多跳目标、pivot 中间跳）；
        - 内层内容：逐连接单独还原（suo5 会多路复用子连接，字节层不能跨连接拼接，
          否则会污染成 base64 乱码），可读者去重输出，未解出的分片标半解码。
        """
        sessions = OrderedDict()
        for stream, _recs in pairs:
            (c, s, sp, _hl, rr, _sr, rf, rfr) = _suo5_split(stream)
            line = rr.split(b"\r\n", 1)[0] if rr else b""
            parts = line.split(b" ")
            uri = (parts[1].decode("latin1", "ignore").split("?")[0]
                   if len(parts) >= 2 else "")
            times = [float(p.time) for p in (stream.packets or [])
                     if getattr(p, "time", None) is not None]
            ft = min(times) if times else (stream.timestamp or 0.0)
            lt = max(times) if times else ft
            sess = sessions.setdefault(
                (c, s, sp, uri),
                {"client": c, "server": s, "port": sp, "conns": [], "first": ft, "last": lt})
            sess["conns"].append((ft, rf, rfr))
            sess["first"] = min(sess["first"], ft)
            sess["last"] = max(sess["last"], lt)

        server_ips = {sess["server"] for sess in sessions.values()}
        records = []
        for sess in sessions.values():
            conns = sorted(sess["conns"], key=lambda x: x[0])
            chains = [_suo5_unwrap_chain(rf, rfr) for _ft, rf, rfr in conns]
            # 聚合拓扑：所有连接见到的目标去重、最大跳深
            agg_hops = []
            for hops, _fc, _fs, _p in chains:
                for t in hops:
                    if t and t not in agg_hops:
                        agg_hops.append(t)
            agg_hops = agg_hops or [None]
            proto_final = next((p for _h, _fc, _fs, p in chains if p != "raw/unknown"),
                               "raw/unknown")
            is_pivot = sess["client"] in server_ips
            sid = f"{sess['client']}->{sess['server']}:{sess['port']}"
            req_n = sum(len(rf) for _ft, rf, _rfr in conns)
            res_n = sum(len(rfr) for _ft, _rf, rfr in conns)
            # 会话概览（拓扑，不含内层内容）
            records += self._chain_records(
                client_ip=sess["client"], server_ip=sess["server"], server_port=sess["port"],
                hops=agg_hops, fc=b"", fs=b"", proto=proto_final,
                first_t=sess["first"], last_t=sess["last"], detect_conf="high",
                req_n=req_n, res_n=res_n, n_conn=len(conns), is_pivot=is_pivot,
                stream_id=sid, emit_inner=False)
            # 逐连接可读内层内容（去重）
            seen = set()
            for hops, fc, fs, proto in chains:
                inner = self._inner_records(
                    hops=hops, fc=fc, fs=fs, proto=proto, nested=len(agg_hops) >= 2,
                    client_ip=sess["client"], server_ip=sess["server"],
                    server_port=sess["port"], first_t=sess["first"], last_t=sess["last"],
                    detect_conf="high", stream_id=sid, packet_end=None)
                for rec in inner:
                    sig = (rec.decoded_command or "", rec.decoded_response or "")
                    if sig in seen:
                        continue
                    seen.add(sig)
                    records.append(rec)
        return records


class GodzillaPlugin(AnalyzerPlugin):
    name = "godzilla"
    category = "webshell"
    requires_key = True
    can_decrypt = True

    def detect(self, stream: StreamData):
        request, response = _request_response(stream)
        if not request or not request.startswith(b"POST "):
            return None
        head, req_body = split_http_message(request)
        low = head.lower()
        # 冰蝎标志性请求头出现时，判为冰蝎而非哥斯拉
        if b"application/json, text/javascript" in low:
            return None
        uri = _request_uri(request)
        uri_path = urlsplit(uri).path or uri

        # 形态一：`参数名=base64`（PHP/JSP 的 BASE64 加密器）。参数名为短标识符（如 pass），
        # 借此与冰蝎/其他 webshell 裸 base64（'=' 为填充）区分。
        if b"=" in req_body:
            form_parts = [p for p in req_body.split(b"&") if b"=" in p]
            response_encrypted = False
            if response:
                res_head, res_body = split_http_message(response)
                response_encrypted = _looks_base64(res_body) or (
                    b"content-encoding: gzip" not in res_head.lower()
                    and _encrypted_body(res_body)
                )
            for part in form_parts:
                param, payload = part.split(b"=", 1)
                param_name = param.rsplit(b"&", 1)[-1]
                if not re.match(rb"^[A-Za-z_][A-Za-z0-9_]{0,31}$", param_name):
                    continue
                payload = unquote(payload.decode("utf-8", "ignore")).encode()
                # 只靠请求参数像 base64 太容易撞上正常业务（登录 token、JSON 字段、上传块）。
                # 哥斯拉 HTTP 通信通常请求和响应都呈密文形态；若没有响应侧佐证，只给 RAW
                # 加密体路径处理，不把普通 form 参数标为待解密 webshell。
                common_godzilla_param = param_name.lower() in {b"pass", b"pwd", b"payload", b"data"}
                if _looks_base64(payload) and (response_encrypted or common_godzilla_param):
                    evidence = ["POST 请求体包含疑似哥斯拉 Base64 加密参数"]
                    if response_encrypted:
                        evidence.append("响应体亦呈 Base64/raw 密文形态")
                    if common_godzilla_param:
                        evidence.append("参数名命中 Godzilla 常见 pass/pwd/payload/data")
                    return DetectionResult(
                        self.name, 0.72, CONFIDENCE_HIGH, evidence,
                        {"uri": uri_path, "param": param.decode("utf-8", "ignore")},
                    )
        # 形态二：裸密文（JSP/C# 的 RAW 加密器，body 为二进制 AES）。哥斯拉客户端总会带
        # Content-Type（x-www-form-urlencoded / octet-stream），冰蝎则不带，据此区分。
        head_sample = req_body[:256]
        nonprint = sum(1 for c in head_sample if c < 9 or (13 < c < 32) or c >= 127)
        binary_body = bool(head_sample) and nonprint / len(head_sample) > 0.15
        ordinary_form = re.match(rb"^[A-Za-z_][A-Za-z0-9_]{0,31}=", req_body) and not binary_body
        if b"\ncontent-type:" in b"\n" + low and binary_body and _encrypted_body(req_body) and not ordinary_form:
            return DetectionResult(
                self.name, 0.6, CONFIDENCE_MEDIUM,
                ["POST 请求体为裸密文（疑似哥斯拉 RAW 加密器）", "含 Content-Type 请求头"],
                {"uri": uri_path},
            )
        return None

    def analyze(self, stream: StreamData, context: AnalysisContext):
        detection = context.detection or self.detect(stream)
        uri = ""
        if detection:
            uri = str(detection.metadata.get("uri") or "")
        if not uri:
            request, _ = _request_response(stream)
            uri = urlsplit(_request_uri(request or b"")).path

        candidate_keys = context.candidate_keys()
        txns = iter_http_transactions(stream.packets)

        if not candidate_keys:
            return [_pending_record(self.name, stream, txns, uri, detection,
                                    "已识别哥斯拉流量，待补充连接密码/密钥")]
        if not txns:
            return [_pending_record(self.name, stream, txns, uri, detection,
                                    "已识别哥斯拉流量，但无法按 HTTP 事务重组")]

        # 逐 HTTP 事务出记录；加密器（AES/XOR、raw/base64）由引擎自动判定。
        last_records = []
        for key in candidate_keys:
            def _dec(body, is_resp, _k=key):
                return godzilla_decrypt(body, _k, is_response=is_resp)
            records, any_valid = _decode_transactions(stream, txns, self.name, _dec, detection)
            if any_valid:
                for r in records:
                    if r.is_valid_target_flow:
                        r.analyst_note = (r.analyst_note or "") + f"；自动试解命中密钥: {key}"
                return records
            if records:
                last_records = records

        if last_records:
            return last_records  # 二进制载荷/半解码/乱码记录已各自带 filter_reason
        return [_pending_record(self.name, stream, txns, uri, detection,
                                "已识别哥斯拉流量，但候选密钥试解失败")]


class BehinderPlugin(AnalyzerPlugin):
    name = "behinder"
    category = "webshell"
    requires_key = True
    can_decrypt = True

    def detect(self, stream: StreamData):
        request, _response = _request_response(stream)
        if not request or not request.startswith(b"POST "):
            return None
        head, req_body = split_http_message(request)
        # 冰蝎客户端标志性请求头（v2/v3/v4 默认均带此 Accept，哥斯拉/正常业务不带），
        # 是与哥斯拉裸密文流量最可靠的区分点——先据此确认，再放宽对报文体形态的要求。
        low_head = head.lower()
        behinder_accept = b"application/json, text/javascript" in low_head
        # 旧 Rebeyond/冰蝎 2.x 风格：无 v4 Accept 指纹，但常见 text/html;charset=utf-8 +
        # Accept-Encoding:utf-8 + no-cache/Pragma + PHPSESSID，body 是大段 raw/base64 AES。
        legacy_rebeyond = (
            b"content-type: text/html;charset=utf-8" in low_head
            and b"accept-encoding: utf-8" in low_head
            and b"cache-control: no-cache" in low_head
            and b"pragma: no-cache" in low_head
            and len(req_body.strip()) >= 128
        )
        # 冰蝎 v4 另一常见形态：Content-Type: application/octet-stream + 纯 base64/裸密文
        # body，Accept 伪装成浏览器。为压制普通 octet-stream 上传/API 的误报，额外要求
        # 目标 URI 呈脚本形态（.jsp/.php/.aspx 等），并在 analyze 阶段以「能否解出结构化
        # 明文」二次确认，未解出者只进过滤明细、不污染成功结果。
        uri_path = urlsplit(_request_uri(request)).path.lower()
        script_uri = bool(re.search(
            r"\.(jsp|jspx|php|php\d|phtml|asp|aspx|ashx|asmx|cfm|do|action)$", uri_path))
        octet_stream_shell = (
            b"content-type: application/octet-stream" in low_head
            and script_uri
            and len(req_body.strip()) >= 64
        )
        if not (behinder_accept or legacy_rebeyond or octet_stream_shell):
            return None
        # 排除普通表单（短参数名=值&...），冰蝎请求体是裸密文（raw/base64/json 传输）
        if re.match(rb"^[A-Za-z_][A-Za-z0-9_]{0,32}=[^=]", req_body):
            return None
        # 报文体须为裸密文形态：纯 base64 / 二进制密文 / json 传输内嵌长 base64；
        # 普通业务 AJAX 的短 JSON（即使带同款 Accept 头）不满足，避免误标。
        body_strip = req_body.strip()
        pure_b64 = len(body_strip) >= 16 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", body_strip)
        if not (pure_b64 or _encrypted_body(req_body)):
            return None
        evidence = ["请求体为裸密文（raw/base64/自定义传输）形态"]
        if behinder_accept:
            evidence.insert(0, "匹配冰蝎默认 Accept 请求头")
        if legacy_rebeyond:
            evidence.insert(0, "匹配旧 Rebeyond/冰蝎 text/html;charset=utf-8 + no-cache 流量形态")
        if octet_stream_shell and not (behinder_accept or legacy_rebeyond):
            evidence.insert(0, "匹配冰蝎 v4 application/octet-stream + 脚本 URI + 裸密文形态")
        if behinder_accept:
            confidence, label = 0.9, CONFIDENCE_HIGH
        elif legacy_rebeyond:
            confidence, label = 0.76, CONFIDENCE_MEDIUM
        else:
            confidence, label = 0.7, CONFIDENCE_MEDIUM
        return DetectionResult(
            self.name, confidence, label, evidence,
            {"uri": _request_uri(request)},
        )

    def analyze(self, stream: StreamData, context: AnalysisContext):
        detection = context.detection
        uri = detection.metadata.get("uri") if detection else None
        candidate_keys = context.candidate_keys()
        txns = iter_http_transactions(stream.packets)

        if not candidate_keys:
            return [_pending_record(self.name, stream, txns, uri, detection,
                                    "已识别冰蝎流量，待补充连接密码")]

        if not txns:
            return [_pending_record(self.name, stream, txns, uri, detection,
                                    "已识别冰蝎流量，但无法按 HTTP 事务重组")]

        last_records = []
        for password in candidate_keys:
            def _dec(body, is_resp, _p=password):
                plain, algo = behinder_decrypt(body, _p)
                return (behinder_beautify(plain) if plain else None), algo
            records, any_valid = _decode_transactions(stream, txns, self.name, _dec, detection)
            if any_valid:
                for r in records:
                    if r.is_valid_target_flow:
                        r.analyst_note = (r.analyst_note or "") + f"；自动试解命中密码: {password}"
                return records
            if records:
                last_records = records

        if last_records:
            return last_records
        return [_pending_record(self.name, stream, txns, uri, detection,
                                "已识别冰蝎流量，但候选密码试解失败")]
