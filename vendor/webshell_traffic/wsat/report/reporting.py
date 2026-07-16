# -*- coding: utf-8 -*-
"""
分析结果的纯逻辑渲染与输出路径解析（与 GUI/Tkinter 解耦，可独立测试，
无需加载 Tk）。main.py 从这里导入并复用。

包含两类纯函数：
  - 输出/资源路径：resource_path / app_base_dir / result_dir / make_output_path
  - 结果渲染：analysis_status / build_result_summary / format_records_view /
    high_risk_records / timeline_records / filtered_records /
    build_ioc_summary / build_manifest
"""

import os
import re
import sys
from datetime import datetime

from wsat.core.analysis_record import RISK_HIGH, RISK_MEDIUM
from wsat.report.attack_chain import build_attack_chains
from wsat.report.report_writer import route_records

# --- 输出目录 / 文件命名（打包为 exe/elf 后自动落到应用文件同级 result/ 目录） ---

def _macos_app_parent(exe_dir):
    """
    若 exe_dir 位于 macOS .app 包内（…/<App>.app/Contents/MacOS），
    返回 <App>.app 的父目录（即应用文件的同级目录），否则返回 None。
    """
    if os.path.basename(exe_dir) != "MacOS":
        return None
    contents = os.path.dirname(exe_dir)
    if os.path.basename(contents) != "Contents":
        return None
    app = os.path.dirname(contents)
    if not app.endswith(".app"):
        return None
    return os.path.dirname(app)


def resource_path(name):
    """
    只读随附资源（图标等）的绝对路径。PyInstaller 打包后资源被解压到
    sys._MEIPASS，否则回退为源码目录；与 result/ 输出目录（可写、应用同级）
    是两回事，不要混用。
    """
    # 本模块在 report/ 子包下，源码模式的资源根是其父目录（项目根）
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def app_base_dir():
    """
    应用根目录：报告 result/ 落盘于此。
      - 源码运行：源码目录
      - 打包 Windows(.exe)/Linux(ELF)：可执行文件所在目录
      - macOS(.app)：.app 所在目录（而非包内 Contents/MacOS），
        使 result/ 与应用图标同级、用户可直接看到，
        且不会把报告写进 .app 包内部
    """
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        return _macos_app_parent(exe_dir) or exe_dir
    # 本模块在 report/ 子包下，源码模式的应用根是其父目录（项目根）
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def result_dir():
    """报告输出目录 <应用根>/result（自动创建）。"""
    path = os.path.join(app_base_dir(), "result")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_stem(name):
    return re.sub(r"[^0-9A-Za-z._-]+", "_", str(name or "")).strip("_") or "capture"


def make_output_path(default_output, pcap_path):
    """按「<报告前缀>_<pcap名>_<时间戳>.xlsx」在 result/ 下生成有意义的报告路径。"""
    prefix = _safe_stem(os.path.splitext(os.path.basename(default_output or "analysis_report"))[0])
    pcap = _safe_stem(os.path.splitext(os.path.basename(pcap_path or "capture"))[0])
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(result_dir(), f"{prefix}_{pcap}_{ts}.xlsx")


# --- 分析结果摘要 / IOC / 明细的纯文本渲染（与 GUI widget 解耦，便于测试） ---

def _fmt_epoch(ts):
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (ValueError, OSError, OverflowError):
        return str(ts)


def analysis_status(result):
    """由结果推断分析状态：成功 / 部分成功 / 完成(无命中) / 已取消。"""
    stats = getattr(result, "stats", None) or {}
    if stats.get("已取消"):
        return "已取消"
    if stats.get("插件分析异常流数"):
        return "部分成功（存在插件异常，详见日志）"
    if stats.get("识别命中流数"):
        return "成功"
    return "完成（未发现可疑 webshell / 隧道流量）"


def build_result_summary(result, input_path, output_path, duration=None):
    """构建「分析结果」面板展示的多行摘要文本。"""
    stats = getattr(result, "stats", None) or {}
    records = getattr(result, "records", []) or []
    filtered_cnt = stats.get("乱码/失败/待补充记录数",
                             stats.get("过滤/失败/待补充记录数", 0))
    lines = [
        f"分析状态：{analysis_status(result)}",
        f"PCAP 文件：{os.path.basename(input_path) if input_path else 'N/A'}",
        f"报告路径：{output_path or 'N/A'}",
        f"输出目录：{os.path.dirname(output_path) if output_path else 'N/A'}",
        "",
        (f"总包数：{stats.get('总包数', 'N/A')}    "
         f"TCP 流数：{stats.get('TCP流数', 'N/A')}    "
         f"HTTP 事务记录：{len(records)}    "
         f"检测命中流：{stats.get('识别命中流数', 0)}    "
         f"未命中流：{stats.get('未命中流数', 0)}"),
        (f"高危：{stats.get('高危命中数', 0)}    "
         f"中危：{stats.get('中危命中数', 0)}    "
         f"低危：{stats.get('低危命中数', 0)}"),
        (f"解密成功(可读明文)：{stats.get('成功解密记录数', 0)}    "
         f"二进制载荷：{stats.get('二进制/字节码载荷记录数', 0)}    "
         f"半解码：{stats.get('半解码记录数', 0)}    "
         f"过滤/失败/待补充：{filtered_cnt}    "
         f"仅告警：{stats.get('仅检测告警数', 0)}"),
    ]
    if duration is not None:
        lines.append(f"分析耗时：{duration:.2f} 秒")
    return "\n".join(lines)


def _fmt_record_block(r):
    ts = _fmt_epoch(r.request_time if r.request_time is not None else r.timestamp)
    head = (f"[{ts}] {r.primary_family or r.analyzer} | risk={r.risk_level} | "
            f"detect={r.detect_confidence or '-'} | "
            f"{r.client_ip or '-'} -> {r.server_ip or '-'}:{r.server_port or '-'} | "
            f"{r.method or ''} {r.uri or ''}".rstrip())
    out = [head]
    if r.behavior_tags or r.matched_rules:
        out.append(f"    行为: {', '.join(r.behavior_tags) or '-'}  规则: {', '.join(r.matched_rules) or '-'}")
    cmd = r.decoded_command or r.request
    if cmd:
        out.append(f"    请求: {' '.join(cmd.split())[:240]}")
    resp = r.decoded_response or r.response
    if resp:
        out.append(f"    响应: {' '.join(resp.split())[:240]}")
    if r.filter_reason:
        out.append(f"    过滤原因: {r.filter_reason}")
    return "\n".join(out)


def format_records_view(records, empty="（无记录）"):
    if not records:
        return empty
    return "\n\n".join(_fmt_record_block(r) for r in records)


def high_risk_records(result):
    recs = [r for r in (getattr(result, "records", []) or [])
            if r.is_valid_target_flow and r.risk_level in (RISK_HIGH, RISK_MEDIUM)]
    order = {RISK_HIGH: 0, RISK_MEDIUM: 1}
    recs.sort(key=lambda r: (order.get(r.risk_level, 9),
                             r.request_time if r.request_time is not None else 0))
    return recs


def timeline_records(result):
    recs = [r for r in (getattr(result, "records", []) or []) if r.is_valid_target_flow]
    recs.sort(key=lambda r: (r.request_time if r.request_time is not None
                             else (r.timestamp if r.timestamp is not None else 0)))
    return recs


def filtered_records(result):
    _main, _payloads, _partial, filtered = route_records(
        getattr(result, "records", []) or [])
    return filtered


def build_ioc_dict(result):
    """从记录与告警聚合结构化 IOC（供 JSON/CSV/STIX 导出与文本摘要复用）。"""
    recs = getattr(result, "records", []) or []
    alerts = getattr(result, "alerts", []) or []
    server_ips = sorted({r.server_ip for r in recs if r.server_ip})
    server_endpoints = sorted({f"{r.server_ip}:{r.server_port or ''}".rstrip(':')
                               for r in recs if r.server_ip})
    client_ips = sorted({r.client_ip for r in recs if r.client_ip})
    uris = sorted({r.uri for r in recs if r.uri})
    families = sorted({r.primary_family for r in recs if r.primary_family})
    hashes = sorted({r.content_sha256 for r in recs if r.content_sha256})
    cmds = []
    for r in recs:
        if not r.is_valid_target_flow:
            continue
        # 优先用可读的命令；请求为二进制/字节码载荷（含替换符）时改用响应输出
        for raw in (r.decoded_command, r.decoded_response):
            if not raw or "�" in raw:
                continue
            c = " ".join(raw.split())
            if c and c not in cmds:
                cmds.append(c[:160])
            break
    alert_families = sorted({a.get("流量类型", "") for a in alerts if a.get("流量类型")})
    return {
        "server_ips": server_ips,
        "server_endpoints": server_endpoints,
        "client_ips": client_ips,
        "families": families,
        "uris": uris,
        "commands": cmds,
        "hashes": hashes,
        "alert_families": alert_families,
    }


def build_ioc_summary(result):
    """从记录与告警聚合 IOC 文本摘要：受控服务端 / 攻击端 / 家族 / URI / 命令 / 哈希。"""
    ioc = build_ioc_dict(result)

    def block(title, items, limit=60):
        shown = items[:limit]
        body = "\n".join(f"  {x}" for x in shown) if shown else "  (无)"
        more = f"\n  … 另有 {len(items) - limit} 条" if len(items) > limit else ""
        return f"# {title}（{len(items)}）\n{body}{more}"

    return "\n\n".join([
        block("受控服务端 server_ip:port", ioc["server_endpoints"]),
        block("攻击端 client_ip", ioc["client_ips"]),
        block("命中家族", ioc["families"] + [f"[仅告警] {a}" for a in ioc["alert_families"]]),
        block("URI", ioc["uris"]),
        block("命令样本", ioc["commands"], 40),
        block("内容 SHA-256", ioc["hashes"], 40),
    ])


def build_attack_chain_summary(result):
    """把记录按攻击者聚合为攻击链行为序列文本（供 GUI 面板 / 取证归档）。"""
    chains = build_attack_chains(getattr(result, "records", []) or [])
    if not chains:
        return "（无有效攻击流量）"
    blocks = []
    for c in chains:
        lines = [
            f"# 攻击者 {c['attacker']}  记录 {c['record_count']}  "
            f"高危 {c['high_risk']}  中危 {c['medium_risk']}",
            f"  目标: {', '.join(c['targets']) or '-'}",
            f"  家族: {', '.join(c['families']) or '-'}",
            f"  时间: {_fmt_epoch(c['first_time'])} ~ {_fmt_epoch(c['last_time'])}",
        ]
        if c["commands"]:
            lines.append("  行为序列:")
            for i, cmd in enumerate(c["commands"][:20], 1):
                lines.append(f"    {i}. {cmd}")
            if len(c["commands"]) > 20:
                lines.append(f"    … 另有 {len(c['commands']) - 20} 步")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def build_manifest(result, input_path, output_path, extra_files=None):
    """生成分析包 manifest：结果摘要 + IOC + 打包文件清单，供取证归档自描述。"""
    lines = [
        "Webshell 流量分析 —— 分析包 manifest",
        "生成时间：" + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "=" * 60,
        build_result_summary(result, input_path, output_path),
        "",
        "=" * 60,
        "IOC 摘要",
        "=" * 60,
        build_ioc_summary(result),
        "",
        "=" * 60,
        "攻击链（按攻击者聚合的行为序列）",
        "=" * 60,
        build_attack_chain_summary(result),
    ]
    if extra_files:
        lines += ["", "=" * 60, "打包文件清单", "=" * 60]
        lines += [f"  {p}" for p in extra_files]
    return "\n".join(lines)
