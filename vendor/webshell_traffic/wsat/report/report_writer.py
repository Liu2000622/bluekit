# -*- coding: utf-8 -*-
"""
多 Sheet 分析报告写入。

Sheet 顺序（便于应急研判，从结论到明细）：
  1. 攻击摘要      —— 高/中/低危行为聚合，快速定位关键行为
  2. 攻击时间线    —— 有风险的行为按时间排序，还原攻击链路
  3. 原始解密结果  —— 全部成功解密的有效目标流量（含风险字段）
  4. 过滤与失败明细 —— 假握手/URI 撞车/乱码/疑似非目标（默认不进摘要）
  5. 统计信息

依据 AnalysisRecord.is_valid_target_flow 分流；风险字段由 rule_engine 预先标注。
"""

import copy
import glob
import os
import re
import threading
from datetime import datetime

import openpyxl
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font, PatternFill

from wsat.core.analysis_record import (
    DECODE_BINARY_PAYLOAD,
    DECODE_PARTIAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
)
from wsat.report.attack_chain import build_attack_chains

_FILL_HIGH = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
_FILL_MED = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
_HEADER_FONT = Font(bold=True)

_RISK_ORDER = {RISK_INFO: 0, RISK_LOW: 1, RISK_MEDIUM: 2, RISK_HIGH: 3}
_RISKY_LEVELS = (RISK_HIGH, RISK_MEDIUM, RISK_LOW)


def _fmt_ts(ts):
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (ValueError, OSError, OverflowError):
        return str(ts)


def _join(values):
    return ", ".join(values) if values else ""


def _clean(value):
    """
    去除 Excel/XML 不允许的控制字符（0x00-0x08、0x0B-0x0C、0x0E-0x1F）。
    真实解密内容可能含二进制/控制字节，openpyxl 会拒绝写入并抛
    IllegalCharacterError，这里统一清洗，避免报告生成崩溃。
    """
    if not isinstance(value, str):
        return value
    return ILLEGAL_CHARACTERS_RE.sub("�", value)


# Excel 单元格硬上限（.xlsx 规范：32767 字符）——这是 Excel 自身限制，非本工具截断
_XLSX_MAX = 32767


class _OverflowSink:
    """
    单元格超限内容的外落写盘器：完整内容写为 .txt，供单元格标注路径。

    目录：与 Excel 同级、以 Excel 文件名（去扩展名）命名，
    如 result/报告.xlsx → result/报告/cell_0001.txt。目录按需创建；
    重写同名报告时会清掉目录里上一次生成的 cell_*.txt，避免残留混淆。
    """

    def __init__(self, xlsx_path):
        stem = os.path.splitext(os.path.basename(xlsx_path))[0]
        self._dir = os.path.join(os.path.dirname(os.path.abspath(xlsx_path)), stem)
        self._rel_dir = stem
        self._count = 0

    def save(self, text):
        """完整内容写盘，返回相对 Excel 所在目录的路径（写进单元格标注）。"""
        if self._count == 0:
            os.makedirs(self._dir, exist_ok=True)
            for stale in glob.glob(os.path.join(self._dir, "cell_*.txt")):
                os.remove(stale)
        self._count += 1
        name = f"cell_{self._count:04d}.txt"
        with open(os.path.join(self._dir, name), "w",
                  encoding="utf-8", errors="replace") as f:
            f.write(text)
        return os.path.join(self._rel_dir, name)

    def save_binary(self, data):
        """把二进制文件载荷落盘为对应类型文件，返回 (相对路径, ext, label)。
        Java class 额外落盘 javap/CFR 反编译文本（<name>.decompiled.txt）。"""
        from wsat.report.payload_extractor import save_payload
        os.makedirs(self._dir, exist_ok=True)
        abs_path, ext, label = save_payload(data, self._dir, base="payload")
        # 内存马研判：Java class 走结构解析，其它载荷（.NET 程序集 / PHP 脚本文件等）
        # 走文本特征识别；非内存马返回 None，不产文件。
        from wsat.report.memshell import analyze_memshell, format_verdict
        verdict = format_verdict(analyze_memshell(data))
        if ext == "class":
            from wsat.report.class_decompiler import decompile_file
            deco = decompile_file(abs_path)
            if verdict or deco:
                with open(abs_path + ".decompiled.txt", "w",
                          encoding="utf-8", errors="replace") as f:
                    if verdict:
                        f.write("===== 内存马研判 =====\n" + verdict + "\n\n")
                    if deco:
                        f.write(deco)
        elif verdict:
            with open(abs_path + ".memshell.txt", "w", encoding="utf-8", errors="replace") as f:
                f.write("===== 内存马研判 =====\n" + verdict + "\n")
        return os.path.join(self._rel_dir, os.path.basename(abs_path)), ext, label


# 外落写盘器按线程隔离：GUI 各标签页的分析跑在独立后台线程、可并发，
# 用模块级全局会让两个报告争抢同一个 sink（超限 txt 落错目录/中途被置空）。
_overflow_state = threading.local()


def _get_overflow_sink():
    return getattr(_overflow_state, "sink", None)


def _set_overflow_sink(sink):
    _overflow_state.sink = sink


def _cell(value):
    """
    写入单元格的完整内容：不做任何人为截断/隐藏，仅清洗 Excel 非法控制字符。
    超过 Excel 硬上限 32767 字符时，完整内容外落为 .txt（Excel 同级同名目录），
    单元格头部标注外落路径，其后保留尽量多的内容前缀。
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    cleaned = _clean(value)
    if len(cleaned) > _XLSX_MAX:
        sink = _get_overflow_sink()
        rel_path = sink.save(value) if sink else None
        if rel_path:
            note = (f"[超过 Excel 单元格上限 32767 字符，完整内容(共 {len(cleaned)} 字符)"
                    f"已保存至: {rel_path}]\n")
        else:
            note = (f"[超过 Excel 单元格上限 32767 字符，完整长度 {len(cleaned)}，"
                    f"以下为截断内容]\n")
        cleaned = note + cleaned[:_XLSX_MAX - len(note)]
    return cleaned


# 兼容旧调用名：一律输出完整内容（不再截断）
def _excerpt(text, limit=None):
    return _cell(text)


# 提取可读字符串（ASCII 可打印 + 中文），用于把二进制/字节码载荷里的
# 类名/方法名/命令等有意义内容surface出来，避免整格显示为替换符乱码
_READABLE_RE = re.compile(r"[\x20-\x7e一-鿿]{3,}")


def _content_cell(value):
    """
    写入「解密内容」单元格：完整、不人为截断（仅超 Excel 硬上限时外落 .txt
    并标注路径）。若内容含大量不可显示字节
    （如冰蝎/哥斯拉的 Java 字节码载荷，转码后为替换符），则在完整内容之前先
    提取并置顶可读字符串（类名/方法名/命令等），既可读又不隐藏原始内容。
    """
    if not value:
        return ""
    if not isinstance(value, str):
        value = str(value)
    cleaned = _clean(value)
    if cleaned.count("�") / max(len(cleaned), 1) > 0.15:
        readable = " ".join(_READABLE_RE.findall(cleaned)).strip()
        return _cell("[可读字符串]\n" + (readable or "(无)") +
                     "\n\n[原始内容(含二进制/不可显示字节)]\n" + cleaned)
    return _cell(cleaned)


def _fmt_dur(ms):
    return "" if ms is None else f"{ms:.1f}"


def _srv(record):
    """服务端 IP:端口 展示。"""
    ip = record.server_ip or record.dst_ip or ""
    if not ip:
        return ""
    return f"{ip}:{record.server_port}" if record.server_port else ip


def _client(record):
    return record.client_ip or record.src_ip or ""


def _loc(record):
    """记录定位：优先 HTTP 事务号，回退流ID。"""
    return record.http_transaction_id or record.stream_id or ""


def _style_header(sheet):
    for cell in sheet[1]:
        cell.font = _HEADER_FONT


def _risk_fill(risk_level):
    if risk_level == RISK_HIGH:
        return _FILL_HIGH
    if risk_level == RISK_MEDIUM:
        return _FILL_MED
    return None


def _apply_row_fill(sheet, risk_level):
    fill = _risk_fill(risk_level)
    if fill:
        for cell in sheet[sheet.max_row]:
            cell.fill = fill


# 敏感字段脱敏：对 password/key/token 等键后的值打码
_SENSITIVE_RE = re.compile(r'(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|key)\b(\s*[=:]\s*)(\S+)')


def _mask_text(text):
    if not text:
        return text
    return _SENSITIVE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)


def _masked_records(records):
    """返回脱敏后的记录副本（不修改原记录）。"""
    masked = []
    for r in records:
        m = copy.copy(r)
        m.request = _mask_text(r.request)
        m.response = _mask_text(r.response)
        m.content = _mask_text(r.content)
        m.evidence_excerpt = _mask_text(r.evidence_excerpt)
        masked.append(m)
    return masked


def split_records(records):
    valid = [r for r in records if r.is_valid_target_flow]
    filtered = [r for r in records if not r.is_valid_target_flow]
    return valid, filtered


def route_records(records):
    """
    按解码分层把记录分流到四个去处：
      main     : 可读明文有效目标流量（→ 原始解密结果）
      payloads : 二进制/字节码载荷（→ 载荷结构分析）
      partial  : 半解码（base64/JSON 内嵌，→ 半解码明细）
      filtered : 乱码/解密失败/待补充等（→ 过滤与失败明细）
    """
    main, rest = [], []
    for r in records:
        (main if r.is_valid_target_flow else rest).append(r)
    payloads = [r for r in rest if r.decode_status == DECODE_BINARY_PAYLOAD]
    partial = [r for r in rest if r.decode_status == DECODE_PARTIAL]
    filtered = [r for r in rest
                if r.decode_status not in (DECODE_BINARY_PAYLOAD, DECODE_PARTIAL)]
    return main, payloads, partial, filtered


# --- 各 Sheet ---

def _row_time(r):
    """记录用于时间线排序的时间：优先请求时间，回退时间戳/响应时间。"""
    for t in (r.request_time, r.timestamp, r.response_time):
        if t is not None:
            return t
    return None


def _write_attack_summary_sheet(wb, valid_records):
    sheet = wb.active
    sheet.title = "攻击摘要"
    headers = ["首次时间", "最后时间", "分析器", "家族", "客户端IP", "服务端IP", "URI/流",
               "行为分类", "风险等级", "命中规则", "关键证据", "出现次数"]
    sheet.append(headers)

    risky = [r for r in valid_records if r.risk_level in _RISKY_LEVELS]
    groups = {}
    for r in risky:
        client, server = _client(r), _srv(r)
        key = (r.analyzer, client, server, r.uri or r.stream_id, tuple(r.behavior_tags))
        rt = _row_time(r)
        g = groups.get(key)
        if g is None:
            g = {"first": rt, "last": rt, "count": 0,
                 "risk": r.risk_level, "rules": set(), "evidence": r.evidence_excerpt,
                 "analyzer": r.analyzer, "family": r.primary_family or "",
                 "client": client, "server": server,
                 "loc": r.uri or r.stream_id, "tags": r.behavior_tags}
            groups[key] = g
        if rt is not None:
            if g["first"] is None or rt < g["first"]:
                g["first"] = rt
            if g["last"] is None or rt > g["last"]:
                g["last"] = rt
        g["count"] += 1
        g["rules"].update(r.matched_rules)
        if _RISK_ORDER.get(r.risk_level, 0) > _RISK_ORDER.get(g["risk"], 0):
            g["risk"] = r.risk_level
        if not g["evidence"] and r.evidence_excerpt:
            g["evidence"] = r.evidence_excerpt

    ordered = sorted(
        groups.values(),
        key=lambda g: (-_RISK_ORDER.get(g["risk"], 0),
                       g["first"] if g["first"] is not None else 0))
    for g in ordered:
        sheet.append([
            _fmt_ts(g["first"]), _fmt_ts(g["last"]), g["analyzer"], g["family"],
            g["client"] or "", g["server"] or "", g["loc"],
            _join(g["tags"]), g["risk"], _join(sorted(g["rules"])),
            _excerpt(g["evidence"]), g["count"],
        ])
        _apply_row_fill(sheet, g["risk"])
    _style_header(sheet)


def _write_timeline_sheet(wb, valid_records):
    sheet = wb.create_sheet("攻击时间线")
    headers = ["请求时间", "响应时间", "耗时(ms)", "分析器", "家族", "方法", "URI",
               "客户端IP", "服务端IP", "流ID/事务", "行为标签", "风险等级", "风险分",
               "检测置信度", "证据片段", "包范围"]
    sheet.append(headers)
    risky = [r for r in valid_records if r.risk_level in _RISKY_LEVELS]
    risky.sort(key=lambda r: _row_time(r) if _row_time(r) is not None else 0)
    for r in risky:
        pkt_range = (f"{r.packet_start}-{r.packet_end}"
                     if r.packet_start is not None else "")
        sheet.append([
            _fmt_ts(r.request_time if r.request_time is not None else r.timestamp),
            _fmt_ts(r.response_time), _fmt_dur(r.duration_ms),
            r.analyzer, r.primary_family or "", r.method or "", r.uri or "",
            _client(r), _srv(r), _loc(r), _join(r.behavior_tags),
            r.risk_level, r.risk_score, r.detect_confidence or "",
            _excerpt(r.evidence_excerpt), pkt_range,
        ])
        _apply_row_fill(sheet, r.risk_level)
    _style_header(sheet)


def _write_decrypted_sheet(wb, records):
    sheet = wb.create_sheet("原始解密结果")
    headers = ["分析器", "家族", "检测置信度", "HTTP事务", "请求时间", "响应时间",
               "耗时(ms)", "方法", "URI", "客户端IP", "服务端IP", "方向",
               "解密请求(完整)", "解密响应(完整)", "单向内容(完整)", "内容类型", "可读率",
               "攻击风险", "风险分", "行为标签", "命中规则", "证据片段",
               "SHA256", "包范围"]
    sheet.append(headers)
    for r in records:
        pkt_range = (f"{r.packet_start}-{r.packet_end}"
                     if r.packet_start is not None else "")
        sheet.append([
            r.analyzer, r.primary_family or "", r.detect_confidence or r.confidence or "",
            _loc(r),
            _fmt_ts(r.request_time if r.request_time is not None else r.timestamp),
            _fmt_ts(r.response_time), _fmt_dur(r.duration_ms),
            r.method or "", r.uri or "", _client(r), _srv(r),
            r.logical_direction or r.direction or "",
            _content_cell(r.request), _content_cell(r.response), _content_cell(r.content),
            r.content_type or "", (f"{r.readable_ratio:.2f}" if r.readable_ratio else ""),
            r.risk_level, r.risk_score, _join(r.behavior_tags),
            _join(r.matched_rules), _cell(r.evidence_excerpt),
            r.content_sha256 or "", pkt_range,
        ])
        _apply_row_fill(sheet, r.risk_level)
    _style_header(sheet)


def _printable_strings(data, min_len=4, limit=4000):
    """从二进制载荷提取可读 ASCII 字符串（类似 strings），便于快速研判类名/方法名/命令。"""
    out, cur = [], []
    for b in data:
        if 0x20 <= b < 0x7f:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return "\n".join(out)[:limit]


def _payload_view(r):
    """载荷展示：二进制文件载荷给出落盘文件路径 + 可读字符串；文本载荷给完整内容。"""
    raw = getattr(r, "raw_payload", None)
    if raw:
        from wsat.report.payload_extractor import detect_payload_type
        detected = detect_payload_type(raw)
        label = detected[1] if detected else "未识别二进制数据"
        lines = []
        if r.payload_file:
            lines.append(f"[已落盘为文件: {r.payload_file}（{len(raw)} 字节，{label}）]")
        else:
            lines.append(f"[二进制载荷 {len(raw)} 字节，{label}]")
        # Java class：附结构摘要（类名/方法/字符串），完整反汇编见同目录 .decompiled.txt
        if detected and detected[0] == "class":
            from wsat.report.class_decompiler import summarize
            from wsat.report.memshell import analyze_memshell, format_verdict
            verdict = format_verdict(analyze_memshell(raw))
            if verdict:
                lines.append("--- 内存马研判 ---")
                lines.append(verdict)
            summ = summarize(raw)
            if summ:
                lines.append("--- class 结构摘要（完整反汇编见 .decompiled.txt）---")
                lines.append(summ)
            if verdict or summ:
                return _content_cell("\n".join(lines))
        readable = _printable_strings(raw)
        if readable:
            lines.append("--- 可读字符串 ---")
            lines.append(readable)
        return _content_cell("\n".join(lines))
    return _content_cell(r.primary_text())


def _write_payload_structure_sheet(wb, records):
    """二进制/字节码载荷（Java class/序列化/PE）——确认解密但非可读明文。"""
    sheet = wb.create_sheet("载荷结构分析")
    headers = ["分析器", "家族", "时间", "客户端IP", "服务端IP", "方法", "URI",
               "内容类型", "下一步分析建议", "SHA256", "完整内容"]
    sheet.append(headers)
    for r in records:
        sheet.append([
            r.analyzer, r.primary_family or "",
            _fmt_ts(r.request_time if r.request_time is not None else r.timestamp),
            _client(r), _srv(r), r.method or "", r.uri or "",
            r.content_type or "", r.next_decode_hint or "", r.content_sha256 or "",
            _payload_view(r),
        ])
    _style_header(sheet)


def _write_partial_sheet(wb, records):
    """半解码：base64/JSON 内嵌未继续解码，给出下一步解码提示。"""
    sheet = wb.create_sheet("半解码明细")
    headers = ["分析器", "家族", "时间", "客户端IP", "服务端IP", "URI",
               "内容类型", "下一步解码提示", "SHA256", "完整内容"]
    sheet.append(headers)
    for r in records:
        sheet.append([
            r.analyzer, r.primary_family or "",
            _fmt_ts(r.request_time if r.request_time is not None else r.timestamp),
            _client(r), _srv(r), r.uri or "",
            r.content_type or "", r.next_decode_hint or "", r.content_sha256 or "",
            _payload_view(r),
        ])
    _style_header(sheet)


def _write_filtered_sheet(wb, records):
    sheet = wb.create_sheet("过滤与失败明细")
    headers = ["分析器", "家族", "时间", "流ID/事务", "客户端IP", "服务端IP", "URI",
               "解密状态", "解码状态", "检测置信度", "过滤原因", "完整内容"]
    sheet.append(headers)
    for r in records:
        sheet.append([
            r.analyzer, r.primary_family or "",
            _fmt_ts(r.request_time if r.request_time is not None else r.timestamp),
            _loc(r), _client(r), _srv(r), r.uri or "",
            r.decrypt_status, r.decode_status, r.detect_confidence or "",
            r.filter_reason or "", _payload_view(r),
        ])
    _style_header(sheet)


def _write_type_distribution_sheet(wb, distribution):
    sheet = wb.create_sheet("流量类型分布")
    headers = ["流量类型", "类别", "命中流数", "可解密", "成功解密记录数",
               "载荷记录数", "半解码记录数", "过滤/待补充数", "仅检测告警数"]
    sheet.append(headers)
    items = distribution.values() if isinstance(distribution, dict) else distribution
    for item in items:
        sheet.append([
            item.get("流量类型", ""),
            item.get("类别", ""),
            item.get("命中流数", 0),
            item.get("可解密", ""),
            item.get("成功解密记录数", 0),
            item.get("载荷记录数", 0),
            item.get("半解码记录数", 0),
            item.get("过滤/待补充数", 0),
            item.get("仅检测告警数", 0),
        ])
    _style_header(sheet)


def _write_suspicious_alerts_sheet(wb, alerts):
    sheet = wb.create_sheet("可疑流量告警")
    headers = ["流量类型", "类别", "时间", "流ID", "源IP", "目的IP",
               "置信度", "状态", "识别依据"]
    sheet.append(headers)
    for item in alerts:
        sheet.append([
            item.get("流量类型", ""),
            item.get("类别", ""),
            _fmt_ts(item.get("时间")),
            item.get("流ID", ""),
            item.get("源IP", ""),
            item.get("目的IP", ""),
            item.get("置信度", ""),
            item.get("状态", ""),
            _excerpt(item.get("识别依据", ""), 500),
        ])
    _style_header(sheet)


def _write_attack_chain_sheet(wb, records):
    chains = build_attack_chains(records)
    if not chains:
        return
    sheet = wb.create_sheet("攻击链")
    sheet.append(["攻击者", "被控目标", "家族", "首次时间", "最后时间",
                  "事务数", "高危", "中危", "行为序列(按时间)"])
    for c in chains:
        seq = " → ".join(c["commands"][:15])
        if len(c["commands"]) > 15:
            seq += f" …(+{len(c['commands']) - 15})"
        sheet.append([
            c["attacker"], ", ".join(c["targets"]), ", ".join(c["families"]),
            _fmt_ts(c["first_time"]), _fmt_ts(c["last_time"]),
            c["record_count"], c["high_risk"], c["medium_risk"], _cell(seq),
        ])
    _style_header(sheet)


def _write_stats_sheet(wb, stats):
    sheet = wb.create_sheet("统计信息")
    sheet.append(["统计项", "值"])
    for key, value in stats.items():
        sheet.append([key, value])
    _style_header(sheet)


def write_analysis_report(records, output_path, stats=None,
                          include_filtered=True, high_med_only=False,
                          mask_sensitive=False, type_distribution=None,
                          suspicious_alerts=None):
    """
    写出多 Sheet 报告。完整解密内容直接写入 Excel 单元格（不人为截断）；
    仅当超过 Excel 单元格 32767 字符硬上限时，完整内容自动外落为 .txt
    （存于 Excel 同级、以 Excel 文件名命名的目录），并在单元格标注路径。

    include_filtered : 是否输出「过滤与失败明细」Sheet
    high_med_only    : 「原始解密结果」是否只保留中/高危记录
    mask_sensitive   : 是否对 password/key/token 等敏感字段脱敏

    记录按解码分层分流：可读明文→原始解密结果；二进制/字节码载荷→载荷结构分析；
    base64/JSON 半解码→半解码明细；乱码/失败/待补充→过滤与失败明细。
    """
    if mask_sensitive:
        records = _masked_records(records)

    main, payloads, partial, filtered = route_records(records)

    display = main
    if high_med_only:
        display = [r for r in main if r.risk_level in (RISK_HIGH, RISK_MEDIUM)]

    _set_overflow_sink(_OverflowSink(output_path))
    try:
        # 二进制文件载荷（class/gzip/序列化/PE…）落盘为对应类型文件，报告标注路径
        sink = _get_overflow_sink()
        for r in records:
            raw = getattr(r, "raw_payload", None)
            if raw and sink is not None and not r.payload_file:
                rel, ext, _label = sink.save_binary(raw)
                r.payload_file = rel
                if not r.payload_type:
                    r.payload_type = ext
        wb = openpyxl.Workbook()
        _write_attack_summary_sheet(wb, main)   # 复用默认 active
        _write_timeline_sheet(wb, main)
        _write_attack_chain_sheet(wb, main)
        _write_decrypted_sheet(wb, display)
        if payloads:
            _write_payload_structure_sheet(wb, payloads)
        if partial:
            _write_partial_sheet(wb, partial)
        if include_filtered:
            _write_filtered_sheet(wb, filtered)
        if type_distribution is not None:
            _write_type_distribution_sheet(wb, type_distribution)
        if suspicious_alerts is not None:
            _write_suspicious_alerts_sheet(wb, suspicious_alerts)
        if stats:
            _write_stats_sheet(wb, stats)

        wb.save(output_path)
    finally:
        _set_overflow_sink(None)
    return output_path


def risk_counts(records):
    """统计有效目标流量中各风险等级命中数，用于「统计信息」Sheet。"""
    valid = [r for r in records if r.is_valid_target_flow]
    return {
        "高危命中数": sum(1 for r in valid if r.risk_level == RISK_HIGH),
        "中危命中数": sum(1 for r in valid if r.risk_level == RISK_MEDIUM),
        "低危命中数": sum(1 for r in valid if r.risk_level == RISK_LOW),
    }
