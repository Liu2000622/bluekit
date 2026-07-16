# -*- coding: utf-8 -*-
"""全流量设备告警 Excel 导入：把天眼 / 科来等设备导出的告警列表 xlsx 还原为
HTTP 流，交给与 PCAP 完全相同的插件管线分析。

应急场景里流量不总是 pcap——很多来自天眼、科来等全流量设备直接导出的告警 Excel，
每行是一条告警且携带完整 HTTP 事务字段（请求头/请求体/响应头/响应体/载荷内容/URI/
主机域名）。本模块：

1. 用一套**规范列名 + 别名表**去匹配上传 Excel 的表头，容忍不同设备、不同列数、
   列顺序差异——只要语义列在，缺列也不影响其余分析；
2. 反转义单元格（设备把 CRLF 导成字面 ``\\r\\n``、引号导成 ``\\"``）还原真实报文；
3. 逐行重建请求/响应字节 + 合成 PacketInfo，产出与 pcap 路径一致的 ``StreamData``，
   因此自动分析、批量、导出、可视化报告等**所有面板无需改动即可分析 Excel 流量**。
"""

from collections import OrderedDict
from datetime import datetime

from wsat.analyzers.base import StreamData
from wsat.core.pcap_utils import PacketInfo, stream_info_str

EXCEL_SUFFIXES = (".xlsx", ".xlsm", ".xls")

# 规范列名 -> 候选表头别名（按优先级排列，越靠前越优先匹配）。
# 覆盖天眼（奇安信）/ 科来 / 常见 NDR 设备的中英文列名变体。匹配做归一化（去空格、
# 去标点、小写、全角转半角），因此 “源 IP”“源IP”“Src IP”“sourceIp” 都能命中。
FIELD_ALIASES = OrderedDict([
    ("time", ["最近发生时间", "发生时间", "告警时间", "事件时间", "捕获时间", "开始时间",
              "时间", "date", "time", "timestamp", "starttime"]),
    ("attacker_ip", ["攻击ip", "攻击者ip", "攻击方ip", "源ip", "源地址", "sourceip",
                     "srcip", "source", "src", "攻击源ip"]),
    ("victim_ip", ["受害ip", "受害者ip", "被攻击ip", "目的ip", "目标ip", "目的地址",
                   "资产ip", "destip", "dstip", "dest", "dst", "targetip"]),
    ("src_ip", ["源ip", "源地址", "sourceip", "srcip"]),
    ("dst_ip", ["目的ip", "目标ip", "目的地址", "destip", "dstip", "targetip"]),
    ("src_port", ["源端口", "sourceport", "srcport", "srcp"]),
    ("dst_port", ["目的端口", "目标端口", "destport", "dstport", "端口", "port"]),
    ("host", ["主机域名", "host", "域名", "主机", "hostname", "http_host", "服务器域名"]),
    ("uri", ["uri", "url", "请求url", "请求uri", "请求路径", "路径", "requesturi", "请求地址"]),
    ("method", ["请求方法", "方法", "method", "httpmethod"]),
    ("req_headers", ["请求头", "请求头部", "http请求头", "requestheader", "请求包", "请求报文头"]),
    ("req_body", ["请求体", "请求正文", "请求包体", "requestbody", "post数据", "请求数据"]),
    ("resp_headers", ["响应头", "响应头部", "http响应头", "responseheader", "响应报文头"]),
    ("resp_body", ["响应体", "响应正文", "响应包体", "responsebody", "响应数据"]),
    ("payload", ["载荷内容", "载荷", "payload", "原始数据", "数据包", "报文", "请求内容",
                 "攻击载荷", "packet", "rawdata"]),
    ("webshell_content", ["webshell文件内容", "webshell内容", "webshell"]),
    ("alert_l1", ["一级告警类型", "告警大类", "一级分类", "威胁大类"]),
    ("alert_l2", ["二级告警类型", "告警类型", "二级分类", "攻击类型", "威胁类型"]),
    ("threat_name", ["威胁名称", "规则名称", "告警名称", "事件名称", "攻击名称"]),
    ("attack_result", ["攻击结果", "处置结果", "结果", "攻击状态"]),
    ("severity", ["威胁级别", "威胁等级", "风险级别", "严重级别", "级别", "severity", "risklevel"]),
    ("protocol", ["协议", "应用协议", "protocol", "proto"]),
    ("http_status", ["http状态码", "状态码", "响应码", "statuscode", "status"]),
    ("count", ["次数", "命中次数", "告警次数", "count"]),
    ("rule_id", ["威胁情报ioc/规则id", "规则id", "ruleid", "ioc", "规则编号"]),
])

# 反转义映射：设备把控制字符导成可见转义序列。仅还原这几种已知安全序列。
_ESCAPES = {"r": "\r", "n": "\n", "t": "\t", '"': '"', "\\": "\\", "/": "/", "0": "\x00"}
_HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ", "TRACE ")


def is_excel_file(path) -> bool:
    """按扩展名判断是否为 Excel 流量导入文件。"""
    return str(path).lower().endswith(EXCEL_SUFFIXES)


def _norm(text: str) -> str:
    """表头归一化：全角转半角、去空格/标点/下划线、小写，供别名匹配。"""
    if text is None:
        return ""
    out = []
    for ch in str(text):
        code = ord(ch)
        if code == 0x3000:            # 全角空格
            continue
        if 0xFF01 <= code <= 0xFF5E:  # 全角 ASCII -> 半角
            ch = chr(code - 0xFEE0)
        if ch.isspace() or ch in "_-./:：（）()【】[]":
            continue
        out.append(ch.lower())
    return "".join(out)


def match_columns(headers):
    """把表头列表匹配到规范列名，返回 {规范列名: 列索引}。

    未命中的规范列名不出现在结果里（缺列容忍）；同一物理列可被多个规范列名共享
    （如 “源IP” 同时充当 attacker_ip 与 src_ip）。
    """
    norm_headers = [(_norm(h), i) for i, h in enumerate(headers)]
    mapping = {}
    for field, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            na = _norm(alias)
            hit = next((i for nh, i in norm_headers if nh == na), None)
            if hit is not None:
                mapping[field] = hit
                break
    return mapping


def unescape_cell(value) -> str:
    """还原设备导出的转义单元格：去首尾包裹引号，把字面 ``\\r\\n\\t\\"`` 转回控制字符。

    逐字符单遍扫描，避免 str.replace 串联导致的二次转义；含中文，故不用
    codecs.unicode_escape（会破坏 UTF-8）。
    """
    if value is None:
        return ""
    s = str(value)
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    if "\\" not in s:
        return s
    out = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n and s[i + 1] in _ESCAPES:
            out.append(_ESCAPES[s[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_ts(value):
    """把 ‘2025-05-16 15:43:07’ 等时间字符串解析为 epoch 秒；失败返回 None。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        try:
            return value.timestamp()
        except (ValueError, OverflowError):
            return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except (ValueError, OverflowError):
            continue
    return None


def _to_int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _split_host_port(host):
    """从 ‘1.2.3.4:9080’ 或 ‘aam.icbc’ 拆出 (host, port|None)。"""
    if not host:
        return "", None
    host = host.strip()
    if host.count(":") == 1 and "]" not in host:
        h, _, p = host.partition(":")
        return h, _to_int(p)
    return host, None


def _ensure_header_terminator(head: str) -> str:
    """确保 HTTP 头以空行结尾（\\r\\n\\r\\n），供请求/响应体正确拼接。"""
    if head.endswith("\r\n\r\n"):
        return head
    if "\r\n\r\n" in head:
        return head
    return head.rstrip("\r\n") + "\r\n\r\n"


def _looks_http_request(text: str) -> bool:
    return text.startswith(_HTTP_METHODS)


def _build_request(row) -> str:
    """由行字段重建 HTTP 请求文本。优先 请求头(+请求体)，回退 载荷内容，再回退 URI 合成。"""
    head = unescape_cell(row.get("req_headers"))
    if head:
        req = _ensure_header_terminator(head)
        body = unescape_cell(row.get("req_body"))
        return req + body if body else req
    payload = unescape_cell(row.get("payload"))
    if payload and _looks_http_request(payload):
        return payload
    uri = unescape_cell(row.get("uri")).strip().strip('"') or "/"
    method = (unescape_cell(row.get("method")).strip() or "GET").upper()
    host = _split_host_port(unescape_cell(row.get("host")))[0]
    if uri:
        line = f"{method} {uri} HTTP/1.1\r\n"
        line += f"Host: {host}\r\n" if host else ""
        body = unescape_cell(row.get("req_body"))
        return line + "\r\n" + body
    return payload  # 兜底：非 HTTP 的原始载荷也带上，供 IOC/指纹扫描


def _build_response(row) -> str:
    head = unescape_cell(row.get("resp_headers"))
    if head:
        resp = _ensure_header_terminator(head)
        body = unescape_cell(row.get("resp_body"))
        return resp + body if body else resp
    body = unescape_cell(row.get("resp_body"))
    if body:
        return "HTTP/1.1 200 OK\r\n\r\n" + body
    return ""


def _row_to_stream(row, index):
    """把一行告警字段字典重建为 StreamData；无任何可分析内容时返回 None。"""
    req_text = _build_request(row)
    resp_text = _build_response(row)
    if not req_text and not resp_text:
        return None

    src = (unescape_cell(row.get("src_ip")) or unescape_cell(row.get("attacker_ip"))
           or "0.0.0.0").strip()
    dst = (unescape_cell(row.get("dst_ip")) or unescape_cell(row.get("victim_ip"))
           or "0.0.0.0").strip()
    host_only, host_port = _split_host_port(unescape_cell(row.get("host")))
    sport = _to_int(row.get("src_port"), 40000 + (index % 20000))
    dport = _to_int(row.get("dst_port")) or host_port or 80

    req_bytes = req_text.encode("utf-8", "surrogatepass") if req_text else b""
    resp_bytes = resp_text.encode("utf-8", "surrogatepass") if resp_text else b""

    ts = _parse_ts(row.get("time"))
    directions = OrderedDict()
    packets = []
    if req_bytes:
        directions[((src, sport), (dst, dport))] = req_bytes
        packets.append(PacketInfo(ts or 0, src, sport, dst, dport, req_bytes, 0))
    if resp_bytes:
        directions[((dst, dport), (src, sport))] = resp_bytes
        packets.append(PacketInfo(ts or 0, dst, dport, src, sport, resp_bytes, 0))

    key = tuple(sorted(((src, sport), (dst, dport))))
    stream_id = f"{stream_info_str(key)} [Excel行{index + 1}]"
    stream = StreamData(key=key, stream_id=stream_id, directions=directions,
                        packets=packets, timestamp=ts)
    # 附带原始告警元数据，便于 UI/报告在插件未命中时也能呈现设备判定
    stream.excel_meta = {k: unescape_cell(row.get(k)) for k in (
        "alert_l1", "alert_l2", "threat_name", "attack_result", "severity",
        "protocol", "http_status", "attacker_ip", "victim_ip", "host", "uri",
        "rule_id", "webshell_content") if row.get(k) not in (None, "")}
    return stream


def build_streams_from_excel(path, status_callback=None):
    """读取告警 Excel，返回 (stream_objects, 有效行数)。

    只读模式加载首个 sheet；首行为表头，其余每行重建为一条 HTTP 流。
    """
    import openpyxl

    def _log(msg):
        if status_callback:
            status_callback(msg)

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        ws = wb.active
        rows = ws.iter_rows(values_only=True)
        try:
            header = next(rows)
        except StopIteration:
            return [], 0
        mapping = match_columns(list(header))
        matched = sorted(mapping.keys())
        _log(f"[*] Excel 表头识别到 {len(matched)} 个规范字段: {', '.join(matched)}")
        if not ({"req_headers", "payload", "uri"} & set(mapping)):
            _log("[!] 未匹配到 请求头/载荷内容/URI 任一列，可能非受支持的告警导出格式，"
                 "仍将尽力按现有字段分析。")
        streams = []
        for i, raw in enumerate(rows):
            row = {field: raw[idx] for field, idx in mapping.items()
                   if idx < len(raw)}
            stream = _row_to_stream(row, i)
            if stream is not None:
                streams.append(stream)
        _log(f"[*] Excel 共 {i + 1} 行，重建出 {len(streams)} 条 HTTP 流")
        return streams, i + 1
    finally:
        wb.close()
