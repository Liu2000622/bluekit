# -*- coding: utf-8 -*-
"""自动识别 + 插件化多类型分析调度引擎。"""

import glob
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import List, Optional

from wsat.analyzers import get_default_plugins
from wsat.analyzers.base import AnalysisContext, DetectionResult, StreamData
from wsat.core.analysis_record import DECODE_BINARY_PAYLOAD, DECODE_PARTIAL, AnalysisRecord
from wsat.core.dns_tunnel import detect_dns_tunnels
from wsat.core.excel_ingest import build_streams_from_excel, is_excel_file
from wsat.core.pcap_utils import (
    AnalysisCancelled,
    extract_dns_query,
    extract_packet_info,
    iter_pcap_packets,
    reassemble_by_seq,
    stream_info_str,
)
from wsat.core.rule_engine import annotate_records
from wsat.crypto.tls_decrypt import KeyLog, RsaKeys, decrypt_tls_packets
from wsat.report.report_writer import risk_counts, route_records, write_analysis_report

# 内置弱口令字典：哥斯拉/冰蝎等的连接密码常用默认/弱值。命中即自动解密；
# 未命中只是试解失败，无副作用，故可放心扩充。
DEFAULT_WEAK_KEYS = [
    "pass", "key", "admin", "shell", "rebeyond", "password", "123456", "admin123",
    "cmd", "test", "hack", "hacker", "root", "webshell", "godzilla", "behinder",
    "c", "a", "x", "1", "123", "888", "888888", "000000", "111111", "666666",
    "guest", "system", "manager", "wwwroot", "backdoor", "p@ssw0rd", "admin888",
    "qwerty", "abc123", "123456789", "cai", "chopper", "antsword",
]

DEFAULT_CRYPTERS = [
    "AES_BASE64 (V4 Default)",
    "XOR_BASE64 (V3 Default)",
    "PHP_EVAL_XOR_BASE64",
]


@dataclass
class AutoAnalysisResult:
    """自动分析结果，供 CLI/GUI/测试复用。"""

    records: List[AnalysisRecord] = field(default_factory=list)
    alerts: List[dict] = field(default_factory=list)
    type_distribution: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    output_path: Optional[str] = None


def _normalize_list(values) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        parts = []
        for item in values.split(","):
            item = item.strip()
            if item:
                parts.append(item)
        return parts
    return [str(v).strip() for v in values if str(v).strip()]


def load_weak_key_dictionary(source=True) -> List[str]:
    """
    加载弱口令候选。

    source=True/'weak' 使用内置字典；source 为路径时按行读取；source=False 禁用。
    """
    if not source:
        return []
    if source is True or source == "weak":
        return list(DEFAULT_WEAK_KEYS)
    if isinstance(source, (list, tuple, set)):
        return _normalize_list(source)
    if isinstance(source, str) and os.path.exists(source):
        with open(source, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return _normalize_list(source)


# 单次分析累积在内存中的重组载荷软上限。TCP 流重组需要把每条流的载荷
# 留在内存里做归并，超大抓包会撑爆内存；到达上限即停止继续吃包，只分析
# 已读入的部分（返回 capped=True 由调用方告警），而不是 OOM 崩溃。
_MAX_REASSEMBLY_BYTES = 1_500_000_000  # ~1.5 GB


def _rebuild_directions(packets):
    """由 PacketInfo 列表按方向保序拼接出 directions（TLS 解密后的合成包已完整）。"""
    directions = OrderedDict()
    for info in packets:
        dk = ((info.src, info.sport), (info.dst, info.dport))
        directions[dk] = directions.get(dk, b"") + info.load
    return directions


def _extract_candidate_keys(streams, cap=30):
    """从抓包里提取可能的连接密码候选：webshell 的密码常等于脚本文件名 / 参数名 /
    URI 短 token（如 /godzilla.jsp → 'godzilla'、pass=... → 'pass'）。命中即多一次
    自动解密机会；未命中只是多试几次，无副作用。返回去重、按出现顺序的候选列表。"""
    cands, seen = [], set()

    def _add(tok):
        if tok and 1 <= len(tok) <= 20 and re.fullmatch(r"[A-Za-z0-9_]+", tok):
            low = tok.lower()
            if low not in seen:
                seen.add(low)
                cands.append(tok)

    for st in streams:
        for data in st.directions.values():
            d = bytes(data)[:4096]
            if not d.startswith((b"POST ", b"GET ", b"PUT ")):
                continue
            line = d.split(b"\r\n", 1)[0].decode("latin1", "ignore")
            parts = line.split()
            if len(parts) >= 2:
                path = parts[1].split("?")[0].rstrip("/")
                stem = path.split("/")[-1].split(".")[0]
                _add(stem)
            for m in re.finditer(rb"[?&\r\n]([A-Za-z_][A-Za-z0-9_]{0,19})=", d):
                _add(m.group(1).decode("latin1", "ignore"))
            if len(cands) >= cap:
                return cands[:cap]
    return cands[:cap]


def _maybe_reconstruct_http2(directions, packets):
    """若为 HTTP/2 流（h2c 或解密后 h2），把帧重组为 HTTP/1.1 方向 + 合成包；否则 None。"""
    from wsat.core.http2 import reconstruct_http2, synth_packets
    h2dirs = reconstruct_http2(directions)
    if h2dirs is None:
        return None
    base_time = packets[0].time if packets else 0
    return h2dirs, synth_packets(h2dirs, base_time)


def _reassemble_directions_by_seq(packets):
    """按方向分组后，用 TCP 序列号重组每个方向（处理乱序 / 重传 / 重叠）。"""
    by_dir = OrderedDict()
    for info in packets:
        dk = ((info.src, info.sport), (info.dst, info.dport))
        by_dir.setdefault(dk, []).append(info)
    directions = OrderedDict()
    for dk, infos in by_dir.items():
        directions[dk] = reassemble_by_seq(infos)
    return directions


def _load_streams(input_path, cancel_check=None, progress_callback=None,
                  max_bytes=_MAX_REASSEMBLY_BYTES, keylog=None, tls_keys=None):
    streams = OrderedDict()
    dns_queries = []
    total = 0
    acc_bytes = 0
    capped = False
    for packet in iter_pcap_packets(
        input_path,
        cancel_check=cancel_check,
        progress_callback=progress_callback,
    ):
        total += 1
        info = extract_packet_info(packet)
        if info is None:
            # 非 TCP 载荷包：顺带收集 UDP DNS 查询供隧道检测（不进 TCP 流水线）
            dq = extract_dns_query(packet)
            if dq is not None:
                dns_queries.append(dq)
            continue
        sk = tuple(sorted(((info.src, info.sport), (info.dst, info.dport))))
        if sk not in streams:
            streams[sk] = {"packets": [], "timestamp": info.time}
        streams[sk]["packets"].append(info)
        acc_bytes += len(info.load)
        if max_bytes and acc_bytes > max_bytes:
            capped = True
            break

    stream_objects = []
    tls_decrypted = 0
    for sk, item in streams.items():
        packets = item["packets"]
        directions = None
        # TLS 预解密：提供 keylog 或服务器 RSA 私钥时，尝试把 HTTPS 流还原为明文 HTTP
        if keylog or tls_keys:
            try:
                dec = decrypt_tls_packets(packets, keylog, rsa_keys=tls_keys)
            except Exception:  # noqa: BLE001 - 解密异常不得中断整次分析
                dec = None
            if dec:
                packets = dec
                directions = _rebuild_directions(dec)
                tls_decrypted += 1
        if directions is None:
            # 按 TCP 序列号重组（乱序 / 重传 / 重叠更可靠）
            directions = _reassemble_directions_by_seq(packets)
        # HTTP/2 重构：h2c 或解密后的 h2 → 还原为 HTTP/1.1，让现有插件可识别
        h2dirs = _maybe_reconstruct_http2(directions, packets)
        if h2dirs is not None:
            directions, packets = h2dirs
        stream_objects.append(StreamData(
            key=sk,
            stream_id=stream_info_str(sk),
            directions=directions,
            packets=packets,
            timestamp=item["timestamp"],
        ))
    return stream_objects, total, capped, tls_decrypted, dns_queries


def _best_detection(stream: StreamData, plugins, status_callback=None):
    best_plugin = None
    best_detection = None
    for plugin in plugins:
        try:
            detection = plugin.detect(stream)
        except Exception as exc:  # noqa: BLE001 - 单插件识别异常不得中断整次分析
            if status_callback:
                status_callback(f"[!] 插件 {plugin.name} 识别流 {stream.stream_id} 异常，已跳过该插件: {exc}")
            continue
        if detection is None:
            continue
        if best_detection is None or detection.confidence > best_detection.confidence:
            best_plugin = plugin
            best_detection = detection
    return best_plugin, best_detection


def _ranked_detections(stream: StreamData, plugins, status_callback=None):
    """返回该流所有命中的 (plugin, detection)，按检测置信度降序。"""
    hits = []
    for plugin in plugins:
        try:
            detection = plugin.detect(stream)
        except Exception as exc:  # noqa: BLE001 - 单插件识别异常不得中断整次分析
            if status_callback:
                status_callback(f"[!] 插件 {plugin.name} 识别流 {stream.stream_id} 异常，已跳过该插件: {exc}")
            continue
        if detection is not None:
            hits.append((plugin, detection))
    hits.sort(key=lambda pd: pd[1].confidence, reverse=True)
    return hits


def _distribution_entry(distribution, plugin):
    entry = distribution.setdefault(plugin.name, {
        "流量类型": plugin.name,
        "类别": plugin.category,
        "命中流数": 0,
        "可解密": "是" if plugin.can_decrypt else "否",
        "成功解密记录数": 0,
        "载荷记录数": 0,
        "半解码记录数": 0,
        "过滤/待补充数": 0,
        "仅检测告警数": 0,
    })
    return entry


def _make_alert(stream: StreamData, plugin, detection: DetectionResult, status="仅检测告警"):
    return {
        "流量类型": plugin.name,
        "类别": plugin.category,
        "时间": stream.timestamp,
        "流ID": stream.stream_id,
        "源IP": stream.key[0][0],
        "目的IP": stream.key[1][0],
        "置信度": detection.confidence_label,
        "状态": status,
        "识别依据": "；".join(detection.evidence),
    }


# 设备告警级别 -> 内部置信度标签，保留传感器的严重性判定
_SEVERITY_MAP = {"危急": "high", "严重": "high", "高危": "high", "高": "high",
                 "中危": "medium", "中": "medium", "低危": "low", "低": "low"}


def _device_alert(stream):
    """把 Excel 行携带的设备原始判定还原为一条告警，保留传感器 ground-truth。

    Excel 导入的每行本身就是全流量设备的一条告警，即便我方插件未独立复检出来，
    也应完整呈现设备判定（威胁名称/类型/结果/级别），供应急人员逐条研判。
    """
    meta = getattr(stream, "excel_meta", None)
    if not meta:
        return None
    l2 = meta.get("alert_l2") or meta.get("alert_l1") or "设备告警"
    basis = []
    for label, key in (("威胁名称", "threat_name"), ("一级", "alert_l1"),
                       ("攻击结果", "attack_result"), ("级别", "severity"),
                       ("主机", "host"), ("URI", "uri"), ("规则", "rule_id")):
        if meta.get(key):
            basis.append(f"{label}={meta[key]}")
    return {
        "流量类型": l2,
        "类别": "设备告警",
        "时间": stream.timestamp,
        "流ID": stream.stream_id,
        "源IP": meta.get("attacker_ip") or stream.key[0][0],
        "目的IP": meta.get("victim_ip") or stream.key[1][0],
        "置信度": _SEVERITY_MAP.get((meta.get("severity") or "").strip(), "medium"),
        "状态": f"设备判定·{meta.get('attack_result') or '未知'}",
        "识别依据": "；".join(basis) or "设备告警",
        "威胁名称": meta.get("threat_name"),
        "二级告警类型": l2,
    }


def _scan_ja3(stream):
    """对未被插件识别的 TLS 流提取 JA3/JA3S + JA4/JA4S 指纹与 SNI，比对威胁情报后告警。

    命中来源：JA3/JA4(S) 指纹命中已知 C2 表、SNI 命中域名观察名单、对端 IP 命中 IP
    观察名单（后两者来自 --intel / rules/threat_intel.json）。四种指纹始终一并计算并
    写入告警依据，便于分析人员比对公开指纹库（FoxIO JA4+ DB）。
    """
    from wsat.crypto.ja3 import (
        classify_ja3,
        classify_ja4,
        compute_ja3,
        compute_ja3s,
        compute_ja4,
        compute_ja4s,
        extract_sni,
    )
    ja3 = ja3s = ja4 = ja4s = sni = None
    ja3_name = ja3s_name = ja4_name = ja4s_name = None
    cert_alert = None
    for data in stream.directions.values():
        if not data or data[0] != 0x16:  # 仅 TLS 握手方向
            continue
        if ja3 is None:
            r = compute_ja3(data)
            if r:
                ja3, ja3_name = r[1], classify_ja3(r[1])
        if ja4 is None:
            fp = compute_ja4(data)
            if fp:
                ja4, ja4_name = fp, classify_ja4(fp)
        if sni is None:
            sni = extract_sni(data)
        if ja3s is None:
            r = compute_ja3s(data)
            if r:
                ja3s, ja3s_name = r[1], classify_ja3(r[1], is_server=True)
        if ja4s is None:
            fp = compute_ja4s(data)
            if fp:
                ja4s, ja4s_name = fp, classify_ja4(fp, is_server=True)
        if cert_alert is None:
            cert_alert = _scan_server_cert(data)

    name = ja3_name or ja4_name or ja3s_name or ja4s_name or (cert_alert[0] if cert_alert else None)
    if not name:
        return None
    ev = []
    for label, val, hit in (("JA3", ja3, ja3_name), ("JA4", ja4, ja4_name),
                            ("JA3S", ja3s, ja3s_name), ("JA4S", ja4s, ja4s_name)):
        if val:
            ev.append(f"{label}={val}" + (f"→{hit}" if hit else ""))
    if sni:
        ev.append(f"SNI={sni}")
    if cert_alert:
        ev.append(cert_alert[1])
    return {
        "流量类型": name,
        "类别": "c2",
        "时间": stream.timestamp,
        "流ID": stream.stream_id,
        "源IP": stream.key[0][0],
        "目的IP": stream.key[1][0],
        "置信度": "中",
        "状态": "TLS 指纹/证书命中已知 C2 工具，流量加密未解密",
        "识别依据": "；".join(ev),
    }


def _scan_server_cert(data):
    """从 TLS 握手方向提取服务器证书并识别已知 C2 默认自签证书（如 Cobalt Strike）。

    返回 (name, evidence) 或 None。用于 _scan_ja3 补充证书维度的判据。
    """
    from wsat.crypto.tls_cert import classify_cert, extract_leaf_cert
    der = extract_leaf_cert(data)
    if der is None:
        return None
    info = classify_cert(der)
    if not info or not info.get("known"):
        return None
    return info["known"], (f"服务器证书={info['known']}"
                           f"（CN={info.get('cn') or '?'}, sha256={info['sha256'][:16]}…）")


def _host_from_stream(stream):
    """提取流的目标主机名：优先 TLS SNI，其次 HTTP 请求的 Host 头。"""
    from wsat.crypto.ja3 import extract_sni
    for data in stream.directions.values():
        if not data:
            continue
        if data[0] == 0x16:
            host = extract_sni(data)
            if host:
                return host
        else:
            m = re.search(rb"\r\n[Hh]ost:\s*([^\r\n]+)", data[:2048])
            if m:
                return m.group(1).decode("latin1", "ignore").strip().split(":")[0]
    return None


def _scan_intel_iocs(stream):
    """对每条流（不限是否被识别）比对威胁情报的「值型 IOC」：对端 IP 名单、SNI/Host
    域名名单。命中即产出告警——弥补 _scan_ja3 只覆盖未识别 TLS 流的盲区。"""
    from wsat.crypto.threat_intel import match_ip, match_sni
    ip_hit = ip_name = None
    for ip in (stream.key[0][0], stream.key[1][0]):
        hit = match_ip(ip)
        if hit:
            ip_hit, ip_name = ip, hit
            break
    host = _host_from_stream(stream)
    host_name = match_sni(host)
    if not (ip_name or host_name):
        return None
    ev = []
    if host_name:
        ev.append(f"HOST/SNI={host}→{host_name}")
    if ip_name:
        ev.append(f"对端IP={ip_hit}→{ip_name}")
    return {
        "流量类型": host_name or ip_name,
        "类别": "c2",
        "时间": stream.timestamp,
        "流ID": stream.stream_id,
        "源IP": stream.key[0][0],
        "目的IP": stream.key[1][0],
        "置信度": "中",
        "状态": "命中威胁情报观察名单（域名/IP IOC）",
        "识别依据": "；".join(ev),
    }


def analyze_pcap_auto(input_path, output_path=None, *, keys=None, weak_dict=True,
                      crypters=None, plugins=None, status_callback=print,
                      cancel_check=None, enable_rules=True, include_filtered=True,
                      high_med_only=False, mask_sensitive=False, keylog=None,
                      tls_keys=None, intel=None):
    """
    自动分析 PCAP：单次流式读入、插件识别、路由分析、合并报告。

    keylog: 可选，NSS SSLKEYLOGFILE 路径或内容 / KeyLog 实例。提供后会先尝试
            解密 TLS 应用数据，把 HTTPS 流还原为明文 HTTP 再参与识别与解密。
    tls_keys: 可选，服务器 RSA 私钥（PEM 路径 / 内容 / 列表 / RsaKeys 实例）。用于解密
            RSA 密钥交换的 TLS 1.2 流量（无前向保密的场景，如持有被控服务器私钥）。
    intel: 可选，额外威胁情报 JSON 文件路径，指纹合并进内置 JA3/JA4 已知表。
    """
    # 加载威胁情报指纹（默认文件 + 可选追加），填充 JA3/JA4 已知表供 _scan_ja3 使用
    from wsat.crypto.threat_intel import load_default_intel, load_intel_file
    load_default_intel()
    if intel:
        n = load_intel_file(intel)
        status_callback(f"[*] 已从 '{intel}' 加载 {n} 条威胁情报指纹")

    plugins = list(plugins or get_default_plugins())
    key_candidates = _normalize_list(keys)
    weak_keys = load_weak_key_dictionary(weak_dict)
    crypter_candidates = _normalize_list(crypters) or list(DEFAULT_CRYPTERS)
    if keylog is not None and not isinstance(keylog, KeyLog):
        keylog = KeyLog.load(keylog)
    if tls_keys is not None and not isinstance(tls_keys, RsaKeys):
        tls_keys = RsaKeys.load(tls_keys)

    try:
        if is_excel_file(input_path):
            # 全流量设备（天眼/科来等）导出的告警 Excel：每行还原为一条 HTTP 流，
            # 走与 pcap 完全相同的插件管线，所有分析面板无需改动即可分析。
            status_callback(f"[*] 识别为告警 Excel，导入 '{input_path}' ...")
            streams, total = build_streams_from_excel(input_path, status_callback)
            capped, tls_decrypted, dns_queries = False, 0, []
        else:
            status_callback(f"[*] 流式读取 '{input_path}'，按 TCP 流重组 ...")
            streams, total, capped, tls_decrypted, dns_queries = _load_streams(
                input_path,
                cancel_check=cancel_check,
                progress_callback=lambda n: status_callback(f"[*] 已读取 {n} 个包 ..."),
                keylog=keylog,
                tls_keys=tls_keys,
            )
        if tls_decrypted:
            status_callback(f"[*] 已用 keylog/私钥解密 {tls_decrypted} 条 TLS 流为明文 HTTP")
        if capped:
            status_callback(
                f"[!] 抓包过大，重组载荷已达内存上限 "
                f"(~{_MAX_REASSEMBLY_BYTES // (1024*1024)}MB)，仅分析已读入的部分。"
                f"建议先按 IP/端口/时间切分 PCAP 后再分析。")
        if is_excel_file(input_path):
            status_callback(f"[*] 共读取 {total} 行告警，重建出 {len(streams)} 条 HTTP 流")
        else:
            status_callback(f"[*] 共读取 {total} 个包，重组出 {len(streams)} 条 TCP 流")
        # 从抓包提取候选密码并入弱口令池（仅在启用弱口令试解时）——提升哥斯拉/冰蝎
        # 在「密码等于文件名/参数名」等常见情形下的自动解密率
        if weak_dict:
            extra = _extract_candidate_keys(streams)
            if extra:
                seen = {k.lower() for k in weak_keys}
                weak_keys = weak_keys + [k for k in extra if k.lower() not in seen]
        records = []
        alerts = []
        distribution = OrderedDict()
        detected_streams = 0
        plugin_errors = 0
        plugin_outputs = OrderedDict()  # plugin -> [(stream, records), ...]

        def _ctx(det_plugin, det):
            return AnalysisContext(
                keys=key_candidates,
                weak_keys=weak_keys if det_plugin.requires_key else [],
                crypters=crypter_candidates,
                status_callback=status_callback,
                detection=det,
            )

        def _emit_alert(alert):
            """把告警计入 alerts 与类型分布（含 DNS/JA3/IOC 等非插件告警）。"""
            alerts.append(alert)
            entry = distribution.setdefault(alert["流量类型"], {
                "流量类型": alert["流量类型"], "类别": alert.get("类别", "c2"),
                "命中流数": 0, "可解密": "否", "成功解密记录数": 0, "载荷记录数": 0,
                "半解码记录数": 0, "过滤/待补充数": 0, "仅检测告警数": 0})
            entry["命中流数"] += 1
            entry["仅检测告警数"] += 1

        for stream in streams:
            # Excel 导入：先保留设备的原始告警判定（每行一条），我方插件再叠加解密/解码增值
            dev_alert = _device_alert(stream)
            if dev_alert:
                _emit_alert(dev_alert)

            # 值型 IOC（域名/IP 观察名单）横切所有流量，不限是否被插件识别
            ioc_alert = _scan_intel_iocs(stream)
            if ioc_alert:
                _emit_alert(ioc_alert)

            ranked = _ranked_detections(stream, plugins, status_callback)
            if not ranked:
                # 无明文插件命中：若为加密 TLS 流，尝试 JA3/JA4 指纹 + 证书识别已知 C2 工具
                ja3_alert = _scan_ja3(stream)
                if ja3_alert:
                    alerts.append(ja3_alert)
                continue
            detected_streams += 1

            # 解密验证优先：多个插件命中同一条流时，优先采纳「能解出有效明文」的可解密插件，
            # 纠正高置信度插件（如误命中的 suo5/菜刀）对其它家族（如哥斯拉）的误报。
            chosen = None
            analyzed = {}  # plugin.name -> records（避免回退时重复 analyze）
            for plugin, detection in ranked:
                if not plugin.can_decrypt:
                    continue
                try:
                    recs = plugin.analyze(stream, _ctx(plugin, detection))
                except Exception as exc:  # noqa: BLE001 - 该插件解密异常，尝试下一候选
                    status_callback(
                        f"[!] 插件 {plugin.name} 分析流 {stream.stream_id} 异常，尝试其它候选: {exc}")
                    continue
                analyzed[plugin.name] = recs
                if any(r.is_valid_target_flow for r in recs):
                    chosen = (plugin, detection, recs)
                    break

            if chosen is not None:
                plugin, detection, plugin_records = chosen
                if ranked[0][0].name != plugin.name:
                    status_callback(
                        f"[i] {stream.stream_id} 置信度最高的 {ranked[0][0].name} 未解出有效明文，"
                        f"改采纳能解密的 {plugin.name}（解密验证优先，纠正误报）")
                entry = _distribution_entry(distribution, plugin)
                entry["命中流数"] += 1
                status_callback(
                    f"[+] {stream.stream_id} type={plugin.name} "
                    f"detect_confidence={detection.confidence_label} category={plugin.category}")
                plugin_outputs.setdefault(plugin, []).append((stream, plugin_records))
                continue

            # 无插件解出有效明文：回退到置信度最高的候选（保持原有告警/待补充行为）
            plugin, detection = ranked[0]
            entry = _distribution_entry(distribution, plugin)
            entry["命中流数"] += 1
            status_callback(
                f"[+] {stream.stream_id} type={plugin.name} "
                f"detect_confidence={detection.confidence_label} category={plugin.category}")

            if not plugin.can_decrypt:
                alerts.append(_make_alert(stream, plugin, detection))
                entry["仅检测告警数"] += 1
                continue

            if plugin.name in analyzed:
                plugin_records = analyzed[plugin.name]
            else:
                try:
                    plugin_records = plugin.analyze(stream, _ctx(plugin, detection))
                except Exception as exc:  # noqa: BLE001 - 单条流分析异常不得中断整次分析
                    plugin_errors += 1
                    status_callback(
                        f"[!] 插件 {plugin.name} 分析流 {stream.stream_id} 异常，已跳过该流: {exc}")
                    alerts.append(_make_alert(stream, plugin, detection, status=f"分析异常: {exc}"))
                    entry["仅检测告警数"] += 1
                    continue
            plugin_outputs.setdefault(plugin, []).append((stream, plugin_records))

        # 会话级归并：允许插件把跨 TCP 连接的分片（如 suo5 全双工多连接、双重隧道）
        # 合并为会话级记录；无 finalize 的插件直接汇总其逐流记录。
        finalize_ctx = AnalysisContext(
            keys=key_candidates, weak_keys=weak_keys, crypters=crypter_candidates,
            status_callback=status_callback)
        for plugin, pairs in plugin_outputs.items():
            finalize = getattr(plugin, "finalize", None)
            if callable(finalize):
                try:
                    plugin_records = list(finalize(pairs, finalize_ctx))
                except Exception as exc:  # noqa: BLE001
                    plugin_errors += 1
                    status_callback(f"[!] 插件 {plugin.name} 会话归并异常，回退按流记录: {exc}")
                    plugin_records = [r for _s, rs in pairs for r in rs]
            else:
                plugin_records = [r for _s, rs in pairs for r in rs]
            records.extend(plugin_records)
            entry = _distribution_entry(distribution, plugin)
            for r in plugin_records:
                if r.is_valid_target_flow:
                    entry["成功解密记录数"] += 1
                elif r.decode_status == DECODE_BINARY_PAYLOAD:
                    entry["载荷记录数"] += 1
                elif r.decode_status == DECODE_PARTIAL:
                    entry["半解码记录数"] += 1
                else:
                    entry["过滤/待补充数"] += 1

        # DNS 隧道检测（独立于 TCP 流水线，产出仅检测告警）
        for a in detect_dns_tunnels(dns_queries):
            alerts.append(a)
            entry = distribution.setdefault(a["流量类型"], {
                "流量类型": a["流量类型"], "类别": a["类别"], "命中流数": 0,
                "可解密": "否", "成功解密记录数": 0, "载荷记录数": 0,
                "半解码记录数": 0, "过滤/待补充数": 0, "仅检测告警数": 0,
            })
            entry["命中流数"] += 1
            entry["仅检测告警数"] += 1

        if enable_rules:
            annotate_records(records)

        main, payloads, partial, filtered = route_records(records)
        stats = {
            "PCAP文件": input_path,
            "总包数": total,
            "TCP流数": len(streams),
            "识别命中流数": detected_streams,
            "未命中流数": max(0, len(streams) - detected_streams),
            "TLS解密流数": tls_decrypted,
            "确认可读明文记录数": len(main),
            "二进制/字节码载荷记录数": len(payloads),
            "半解码记录数": len(partial),
            "乱码/失败/待补充记录数": len(filtered),
            "仅检测告警数": len(alerts),
            "插件分析异常流数": plugin_errors,
            # 兼容旧字段
            "成功解密记录数": len(main),
            "过滤/失败/待补充记录数": len(records) - len(main),
        }
        stats.update(risk_counts(records))

        result = AutoAnalysisResult(records, alerts, distribution, stats, output_path)
        if output_path:
            write_analysis_report(
                records,
                output_path,
                stats,
                include_filtered=include_filtered,
                high_med_only=high_med_only,
                mask_sensitive=mask_sensitive,
                type_distribution=distribution,
                suspicious_alerts=alerts,
            )
            status_callback(f"[*] 自动分析报告已保存到 '{output_path}'。")
            # 同时生成自包含 HTML 可视化报告（同名 .html），失败不影响主报告
            try:
                from wsat.report.html_report import write_html_report
                html_path = os.path.splitext(output_path)[0] + ".html"
                write_html_report(result, html_path)
                status_callback(f"[*] HTML 可视化报告已保存到 '{html_path}'。")
            except Exception as exc:  # noqa: BLE001
                status_callback(f"[!] HTML 报告生成失败: {exc}")

        return result
    except AnalysisCancelled:
        status_callback("[!] 分析已被用户取消。")
        return AutoAnalysisResult(stats={"已取消": True}, output_path=output_path)


# --- 批量 / 目录分析 ---

_PCAP_EXTS = ("*.pcap", "*.pcapng", "*.cap", "*.xlsx", "*.xlsm", "*.xls")


def expand_pcap_inputs(inp):
    """把输入展开为 pcap 文件列表：目录（递归扫描）/ 通配符 / 单文件。"""
    if isinstance(inp, (list, tuple)):
        files = []
        for item in inp:
            files.extend(expand_pcap_inputs(item))
        # 去重保序
        seen, out = set(), []
        for f in files:
            if f not in seen:
                seen.add(f)
                out.append(f)
        return out
    if os.path.isdir(inp):
        files = []
        for ext in _PCAP_EXTS:
            files += glob.glob(os.path.join(inp, "**", ext), recursive=True)
        return sorted(files)
    matches = glob.glob(inp, recursive=True)
    if matches:
        return sorted(m for m in matches if os.path.isfile(m))
    return [inp] if os.path.exists(inp) else []


def _safe_name(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[^0-9A-Za-z._-]+", "_", stem).strip("_") or "capture"


def analyze_batch(inputs, output_dir=None, *, status_callback=print, **auto_kwargs):
    """
    批量分析多个 pcap（目录 / 通配符 / 列表），逐个产出报告并返回汇总。

    返回 (results, summary)：
      results = [(pcap_path, AutoAnalysisResult), ...]
      summary = 文件数 / 有命中文件数 / 总记录数 / 总告警数
    """
    paths = expand_pcap_inputs(inputs)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    results = []
    for p in paths:
        out = os.path.join(output_dir, f"{_safe_name(p)}.xlsx") if output_dir else None
        status_callback(f"[*] 分析 {os.path.basename(p)} ...")
        result = analyze_pcap_auto(p, out, status_callback=status_callback, **auto_kwargs)
        results.append((p, result))
    summary = {
        "文件数": len(paths),
        "有命中文件数": sum(1 for _p, r in results if r.stats.get("识别命中流数")),
        "总记录数": sum(len(r.records) for _p, r in results),
        "总告警数": sum(len(r.alerts) for _p, r in results),
    }
    return results, summary

