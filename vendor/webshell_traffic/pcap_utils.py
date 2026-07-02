# -*- coding: utf-8 -*-
"""
PCAP / TCP 流处理公共工具。

各 webshell 分析器与分类器统一在此完成「按 TCP 流分组、按方向拼接」，
并提供流式读取（PcapReader）以降低大文件内存占用、支持进度与取消：

  - stream_key / direction_key      : 流标识
  - reassemble_streams              : 拼接每个方向的 TCP 负载（接受可迭代包源）
  - group_packets_by_stream         : 按流分组保留数据包
  - group_packets_streaming         : 按流分组保留「轻量包信息」（省内存）
  - split_http_message              : 切分 HTTP 头部/报文体
  - iter_pcap_packets               : 流式逐包读取，支持进度回调与取消
"""

from collections import defaultdict, OrderedDict, namedtuple

from scapy.all import TCP, IP, Raw, PcapReader


class AnalysisCancelled(Exception):
    """分析被用户取消时抛出。"""


# 轻量包信息：仅保留分析所需字段，避免长期驻留 scapy Packet 对象
PacketInfo = namedtuple("PacketInfo", "time src sport dst dport load")


def stream_key(packet):
    """返回与方向无关的规范化流标识：sorted((src,sport),(dst,dport))。"""
    ip, tcp = packet[IP], packet[TCP]
    return tuple(sorted(((ip.src, tcp.sport), (ip.dst, tcp.dport))))


def direction_key(packet):
    """返回区分方向的标识：((src,sport),(dst,dport))。"""
    ip, tcp = packet[IP], packet[TCP]
    return ((ip.src, tcp.sport), (ip.dst, tcp.dport))


def _iter_tcp_packets(packets, require_raw):
    for p in packets:
        if not (p.haslayer(IP) and p.haslayer(TCP)):
            continue
        if require_raw and not p.haslayer(Raw):
            continue
        yield p


def iter_pcap_packets(path, cancel_check=None, progress_callback=None, progress_interval=5000):
    """
    用 PcapReader 流式逐包读取 PCAP，逐个 yield，不构造完整 PacketList。

    cancel_check      : 可选回调，返回 True 时抛出 AnalysisCancelled 中止读取。
    progress_callback : 可选回调 fn(已读包数)，每 progress_interval 个包调用一次。
    """
    count = 0
    with PcapReader(path) as reader:
        for pkt in reader:
            count += 1
            if cancel_check is not None and (count & 0xFF) == 0 and cancel_check():
                raise AnalysisCancelled()
            if progress_callback is not None and count % progress_interval == 0:
                progress_callback(count)
            yield pkt


def reassemble_streams(packets, stream_filter=None, sort_by_time=False):
    """
    将数据包按 TCP 流分组，把每个方向的 Raw 负载按顺序拼接为完整字节流。
    接受任意可迭代包源（列表或 iter_pcap_packets 生成器）。

    返回 OrderedDict[stream_key, dict[direction_key, bytes]]，保持首次出现顺序。
    """
    source = _iter_tcp_packets(packets, require_raw=True)
    if sort_by_time:
        source = sorted(source, key=lambda p: p.time)

    streams = OrderedDict()
    for p in source:
        sk = stream_key(p)
        if stream_filter is not None and sk not in stream_filter:
            continue
        if sk not in streams:
            streams[sk] = defaultdict(bytes)
        streams[sk][direction_key(p)] += bytes(p[Raw].load)
    return streams


def group_packets_by_stream(packets):
    """按 TCP 流分组、保留数据包列表（不拼接）。"""
    streams = defaultdict(list)
    for p in _iter_tcp_packets(packets, require_raw=True):
        streams[stream_key(p)].append(p)
    return streams


def extract_packet_info(packet):
    """把 scapy 包提取为轻量 PacketInfo；非 TCP/IP/Raw 返回 None。"""
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return None
    ip, tcp = packet[IP], packet[TCP]
    return PacketInfo(float(packet.time), ip.src, tcp.sport, ip.dst, tcp.dport, bytes(packet[Raw].load))


def group_packets_streaming(packets):
    """
    流式按 TCP 流分组，每流保留 PacketInfo 列表（轻量，省内存）。
    返回 (dict[stream_key, list[PacketInfo]], 已处理包数)。
    """
    streams = defaultdict(list)
    count = 0
    for packet in packets:
        count += 1
        info = extract_packet_info(packet)
        if info is None:
            continue
        sk = tuple(sorted(((info.src, info.sport), (info.dst, info.dport))))
        streams[sk].append(info)
    return streams, count


def split_http_message(raw: bytes):
    """切分 HTTP 报文为 (头部 bytes, 报文体 bytes)；找不到空行分隔时报文体为空。"""
    sep = raw.find(b'\r\n\r\n')
    if sep == -1:
        return raw, b''
    return raw[:sep], raw[sep + 4:]


def stream_info_str(sk) -> str:
    """把 stream_key 渲染为可读的 'ip:port <-> ip:port' 文本。"""
    return f"{sk[0][0]}:{sk[0][1]} <-> {sk[1][0]}:{sk[1][1]}"
