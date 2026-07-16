# -*- coding: utf-8 -*-
"""
轻量国际化：面向用户的字符串按 key 查表，支持中文（默认）/ 英文切换。
语言可用环境变量 WSA_LANG=en 或 set_language('en') 指定。

框架先覆盖 CLI 关键输出；未登记的 key 回退到中文表或原样返回，便于渐进扩展。
"""

import os

_STRINGS = {
    "zh": {
        "analysis_summary": "自动分析汇总",
        "report": "报告",
        "json_report": "JSON",
        "csv_report": "CSV",
        "ioc_json": "IOC JSON",
        "ioc_csv": "IOC CSV",
        "ioc_stix": "IOC STIX",
        "batch_summary": "批量分析汇总",
        "batch_total": "共 {files} 个 PCAP，{hit} 个有命中，总记录 {records}，总告警 {alerts}",
        "input_not_found": "找不到输入文件",
        "interrupted": "已中断。",
        "type_line": "{typ}: 命中 {streams} 流，成功记录 {ok}，过滤/待补充 {filtered}，告警 {alerts}",
        "no_pcap_found": "未找到任何 PCAP 文件",
    },
    "en": {
        "analysis_summary": "Auto-analysis summary",
        "report": "Report",
        "json_report": "JSON",
        "csv_report": "CSV",
        "ioc_json": "IOC JSON",
        "ioc_csv": "IOC CSV",
        "ioc_stix": "IOC STIX",
        "batch_summary": "Batch analysis summary",
        "batch_total": "{files} PCAP(s), {hit} with hits, {records} records, {alerts} alerts",
        "input_not_found": "Input file not found",
        "interrupted": "Interrupted.",
        "type_line": "{typ}: {streams} stream(s), {ok} decoded, {filtered} filtered/pending, {alerts} alerts",
        "no_pcap_found": "No PCAP files found",
    },
}

_LANG = os.environ.get("WSA_LANG", "zh").lower()
if _LANG not in _STRINGS:
    _LANG = "zh"


def set_language(lang):
    """设置当前语言（zh/en）；未知语言忽略。"""
    global _LANG
    if lang in _STRINGS:
        _LANG = lang


def get_language():
    return _LANG


def t(key, **kwargs):
    """按 key 取当前语言字符串；缺失回退中文表或原 key。支持 {name} 占位替换。"""
    table = _STRINGS.get(_LANG, _STRINGS["zh"])
    s = table.get(key)
    if s is None:
        s = _STRINGS["zh"].get(key, key)
    return s.format(**kwargs) if kwargs else s
