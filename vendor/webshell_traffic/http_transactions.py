# -*- coding: utf-8 -*-
"""
按 HTTP 事务重组单条 TCP 流，保留每条请求/响应的包时间与包序号。

自动分析引擎需要「一次 HTTP 请求/响应 = 一条记录」的粒度（而非整条 TCP 流压成一行），
并要求从 PCAP 包时间还原攻击时间线、区分请求/响应方向与 client/server 角色。

本模块在 pcap_utils.PacketInfo（含 time）之上工作：
  1. 把单条 TCP 流的逐包负载按方向分组、保序拼接；
  2. 用 webshell_crypto.iter_http_messages 切分每个方向的 HTTP 消息；
  3. 把每条消息映射回其首/末包的时间与全局序号；
  4. 按时间顺序把请求与其后的响应配对成 HttpTransaction。

非 HTTP 流（如 suo5 二进制隧道）切不出消息时返回空列表，调用方可回退到旧的
按方向拼接路径。
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from webshell_crypto import iter_http_messages


_METHOD_TOKENS = {
    b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS",
    b"DELETE", b"PATCH", b"TRACE", b"CONNECT",
}


@dataclass
class HttpMessage:
    """一条 HTTP 消息（请求或响应）及其在 PCAP 中的时间/包定位。"""

    is_request: bool
    head: bytes
    body: bytes
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    packet_start: Optional[int] = None
    packet_end: Optional[int] = None
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0


@dataclass
class HttpTransaction:
    """一次 HTTP 事务：请求 + 其后配对的响应（任一方可能缺失）。"""

    request: Optional[HttpMessage] = None
    response: Optional[HttpMessage] = None
    index: int = 0

    @property
    def method(self) -> str:
        if not self.request:
            return ""
        token = self.request.head.split(b" ", 1)[0]
        return token.decode("ascii", "ignore")

    @property
    def uri(self) -> str:
        if not self.request:
            return ""
        try:
            first = self.request.head.split(b"\r\n", 1)[0].decode("utf-8", "ignore")
            parts = first.split()
            return parts[1] if len(parts) >= 2 else ""
        except Exception:
            return ""

    @property
    def request_time(self) -> Optional[float]:
        return self.request.start_time if self.request else None

    @property
    def response_time(self) -> Optional[float]:
        return self.response.start_time if self.response else None

    @property
    def start_time(self) -> Optional[float]:
        times = [t for t in (self.request_time, self.response_time) if t is not None]
        return min(times) if times else None

    @property
    def last_packet_time(self) -> Optional[float]:
        times = []
        for m in (self.request, self.response):
            if m and m.end_time is not None:
                times.append(m.end_time)
        return max(times) if times else None

    @property
    def duration_ms(self) -> Optional[float]:
        start = self.start_time
        end = self.last_packet_time
        if start is None or end is None:
            return None
        return round((end - start) * 1000.0, 3)

    @property
    def packet_start(self) -> Optional[int]:
        idxs = [m.packet_start for m in (self.request, self.response)
                if m and m.packet_start is not None]
        return min(idxs) if idxs else None

    @property
    def packet_end(self) -> Optional[int]:
        idxs = [m.packet_end for m in (self.request, self.response)
                if m and m.packet_end is not None]
        return max(idxs) if idxs else None

    @property
    def client(self) -> Tuple[str, int]:
        """发起 HTTP 请求的一方（通常为攻击端）。缺请求时回退到响应目的端。"""
        if self.request:
            return (self.request.src_ip, self.request.src_port)
        if self.response:
            return (self.response.dst_ip, self.response.dst_port)
        return ("", 0)

    @property
    def server(self) -> Tuple[str, int]:
        """Web 服务端（被控 webshell 所在主机）。"""
        if self.request:
            return (self.request.dst_ip, self.request.dst_port)
        if self.response:
            return (self.response.src_ip, self.response.src_port)
        return ("", 0)


def _is_request_head(head: bytes) -> bool:
    token = head[:16].split(b" ", 1)[0]
    return token in _METHOD_TOKENS


def _direction_messages(entries) -> List[HttpMessage]:
    """
    对单个方向的 (global_idx, PacketInfo) 序列切分 HTTP 消息，并映射时间/包序号。
    entries 已按到达顺序排列。
    """
    concat = bytearray()
    checkpoints = []  # (cum_end_offset, global_idx, time)
    src_ip = src_port = dst_ip = dst_port = None
    for gidx, info in entries:
        if src_ip is None:
            src_ip, src_port, dst_ip, dst_port = info.src, info.sport, info.dst, info.dport
        if not info.load:
            continue
        concat += info.load
        checkpoints.append((len(concat), gidx, float(info.time)))
    if not concat or not checkpoints:
        return []
    concat = bytes(concat)

    def locate(offset):
        """返回覆盖 byte offset 的包 (global_idx, time)。"""
        for cum_end, gidx, t in checkpoints:
            if offset < cum_end:
                return gidx, t
        return checkpoints[-1][1], checkpoints[-1][2]

    raw_msgs = list(iter_http_messages(concat))
    if not raw_msgs:
        return []

    # 定位每条消息头在拼接流中的起始偏移（从游标向后查找，避免误匹配前面的内容）
    positions = []
    cursor = 0
    for head, _body in raw_msgs:
        idx = concat.find(head, cursor)
        if idx == -1:
            idx = cursor
        positions.append(idx)
        cursor = idx + max(1, len(head))

    messages = []
    for i, (head, body) in enumerate(raw_msgs):
        start_off = positions[i]
        end_off = (positions[i + 1] - 1) if i + 1 < len(positions) else (len(concat) - 1)
        end_off = max(start_off, end_off)
        s_gidx, s_time = locate(start_off)
        e_gidx, e_time = locate(end_off)
        messages.append(HttpMessage(
            is_request=_is_request_head(head),
            head=head, body=body,
            start_time=s_time, end_time=e_time,
            packet_start=s_gidx, packet_end=e_gidx,
            src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
        ))
    return messages


def iter_http_transactions(packets) -> List[HttpTransaction]:
    """
    把单条 TCP 流的 PacketInfo 列表重组为按时间排序的 HTTP 事务列表。

    packets : list[PacketInfo]，同一条 TCP 流（两个方向混在一起、按到达顺序）。
    返回    : list[HttpTransaction]，请求与其后首个响应配对；无请求的孤立响应、
              无响应的孤立请求也会各自成为一条事务。非 HTTP 流返回 []。
    """
    if not packets:
        return []

    by_dir = OrderedDict()
    for gidx, info in enumerate(packets):
        dk = ((info.src, info.sport), (info.dst, info.dport))
        by_dir.setdefault(dk, []).append((gidx, info))

    all_msgs: List[HttpMessage] = []
    for entries in by_dir.values():
        all_msgs.extend(_direction_messages(entries))
    if not all_msgs:
        return []

    all_msgs.sort(key=lambda m: (
        m.start_time if m.start_time is not None else 0.0,
        m.packet_start if m.packet_start is not None else 0,
    ))

    transactions: List[HttpTransaction] = []
    pending_req: Optional[HttpMessage] = None
    for m in all_msgs:
        if m.is_request:
            if pending_req is not None:
                transactions.append(HttpTransaction(request=pending_req))
            pending_req = m
        else:
            if pending_req is not None:
                transactions.append(HttpTransaction(request=pending_req, response=m))
                pending_req = None
            else:
                transactions.append(HttpTransaction(response=m))
    if pending_req is not None:
        transactions.append(HttpTransaction(request=pending_req))

    for i, txn in enumerate(transactions):
        txn.index = i + 1
    return transactions
