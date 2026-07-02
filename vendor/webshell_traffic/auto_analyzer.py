# -*- coding: utf-8 -*-
"""自动识别 + 插件化多类型分析调度引擎。"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import os
from typing import Iterable, List, Optional

from analyzers import get_default_plugins
from analyzers.base import AnalysisContext, DetectionResult, StreamData
from analysis_record import AnalysisRecord, DECODE_BINARY_PAYLOAD, DECODE_PARTIAL
from pcap_utils import AnalysisCancelled, extract_packet_info, iter_pcap_packets, stream_info_str
from report_writer import risk_counts, route_records, write_analysis_report
from rule_engine import annotate_records


DEFAULT_WEAK_KEYS = [
    "pass",
    "key",
    "admin",
    "shell",
    "rebeyond",
    "password",
    "123456",
    "admin123",
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


def _load_streams(input_path, cancel_check=None, progress_callback=None):
    streams = OrderedDict()
    total = 0
    for packet in iter_pcap_packets(
        input_path,
        cancel_check=cancel_check,
        progress_callback=progress_callback,
    ):
        total += 1
        info = extract_packet_info(packet)
        if info is None:
            continue
        sk = tuple(sorted(((info.src, info.sport), (info.dst, info.dport))))
        dk = ((info.src, info.sport), (info.dst, info.dport))
        if sk not in streams:
            streams[sk] = {
                "directions": OrderedDict(),
                "packets": [],
                "timestamp": info.time,
            }
        streams[sk]["directions"][dk] = streams[sk]["directions"].get(dk, b"") + info.load
        streams[sk]["packets"].append(info)
    stream_objects = []
    for sk, item in streams.items():
        stream_objects.append(StreamData(
            key=sk,
            stream_id=stream_info_str(sk),
            directions=item["directions"],
            packets=item["packets"],
            timestamp=item["timestamp"],
        ))
    return stream_objects, total


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


def analyze_pcap_auto(input_path, output_path=None, *, keys=None, weak_dict=True,
                      crypters=None, plugins=None, status_callback=print,
                      cancel_check=None, enable_rules=True, include_filtered=True,
                      high_med_only=False, mask_sensitive=False):
    """
    自动分析 PCAP：单次流式读入、插件识别、路由分析、合并报告。
    """
    plugins = list(plugins or get_default_plugins())
    key_candidates = _normalize_list(keys)
    weak_keys = load_weak_key_dictionary(weak_dict)
    crypter_candidates = _normalize_list(crypters) or list(DEFAULT_CRYPTERS)

    try:
        status_callback(f"[*] 流式读取 '{input_path}'，按 TCP 流重组 ...")
        streams, total = _load_streams(
            input_path,
            cancel_check=cancel_check,
            progress_callback=lambda n: status_callback(f"[*] 已读取 {n} 个包 ..."),
        )
        status_callback(f"[*] 共读取 {total} 个包，重组出 {len(streams)} 条 TCP 流")
        records = []
        alerts = []
        distribution = OrderedDict()
        detected_streams = 0
        plugin_errors = 0
        plugin_outputs = OrderedDict()  # plugin -> [(stream, records), ...]

        for stream in streams:
            plugin, detection = _best_detection(stream, plugins, status_callback)
            if plugin is None:
                continue

            detected_streams += 1
            entry = _distribution_entry(distribution, plugin)
            entry["命中流数"] += 1
            # 明确区分「检测置信度」（识别层）与后续的「攻击风险」（研判层），避免歧义
            status_callback(
                f"[+] {stream.stream_id} type={plugin.name} "
                f"detect_confidence={detection.confidence_label} category={plugin.category}"
            )

            if not plugin.can_decrypt:
                alerts.append(_make_alert(stream, plugin, detection))
                entry["仅检测告警数"] += 1
                continue

            context = AnalysisContext(
                keys=key_candidates,
                weak_keys=weak_keys if plugin.requires_key else [],
                crypters=crypter_candidates,
                status_callback=status_callback,
                detection=detection,
            )
            try:
                plugin_records = plugin.analyze(stream, context)
            except Exception as exc:  # noqa: BLE001 - 单条流分析异常不得中断整次分析
                plugin_errors += 1
                status_callback(
                    f"[!] 插件 {plugin.name} 分析流 {stream.stream_id} 异常，已跳过该流: {exc}"
                )
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

        if enable_rules:
            annotate_records(records)

        main, payloads, partial, filtered = route_records(records)
        stats = {
            "PCAP文件": input_path,
            "总包数": total,
            "TCP流数": len(streams),
            "识别命中流数": detected_streams,
            "未命中流数": max(0, len(streams) - detected_streams),
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

        return AutoAnalysisResult(records, alerts, distribution, stats, output_path)
    except AnalysisCancelled:
        status_callback("[!] 分析已被用户取消。")
        return AutoAnalysisResult(stats={"已取消": True}, output_path=output_path)

