"""WebShell 流量(pcap)分析适配层 —— 集成 Webshell_traffic_analysis_tool 引擎。

该引擎依赖 scapy / pycryptodome(Crypto) / openpyxl（非纯标准库）。因此本 Tab
在缺少依赖时优雅降级：只提示，不影响其它纯标准库 Tab。打包版会内置这些依赖。
"""
from __future__ import annotations

import sys
from pathlib import Path

_VENDOR = Path(__file__).resolve().parent.parent / "vendor" / "webshell_traffic"


def _ensure_path():
    if str(_VENDOR) not in sys.path:
        sys.path.insert(0, str(_VENDOR))


def available() -> tuple[bool, str]:
    """依赖是否齐全。返回 (ok, 缺失说明)。"""
    _ensure_path()
    missing = []
    for mod, pip in (("scapy", "scapy"), ("Crypto", "pycryptodome"),
                     ("openpyxl", "openpyxl")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pip)
    if missing:
        return False, "缺少依赖：" + " ".join(missing) + "  (pip install " + " ".join(missing) + ")"
    try:
        import auto_analyzer  # noqa: F401
    except Exception as e:  # noqa: BLE001
        return False, f"引擎导入失败: {e}"
    return True, ""


def analyze(pcap: str, out_xlsx: str | None = None,
            keys: list[str] | None = None, weak_dict: bool = True):
    """跑全自动分析，返回 (result, log_lines)。"""
    _ensure_path()
    import auto_analyzer
    log: list[str] = []
    result = auto_analyzer.analyze_pcap_auto(
        pcap, out_xlsx, keys=keys, weak_dict=weak_dict,
        status_callback=lambda m: log.append(str(m)))
    return result, log


def _fmt_record(r) -> str:
    parts = [f"[{getattr(r, 'risk_level', '')}] {getattr(r, 'analyzer', '')}"]
    cip = getattr(r, "client_ip", None) or getattr(r, "src_ip", None) or ""
    sip = getattr(r, "server_ip", None) or getattr(r, "dst_ip", None) or ""
    if cip or sip:
        parts.append(f"{cip} -> {sip}")
    if getattr(r, "method", None) or getattr(r, "uri", None):
        parts.append(f"{getattr(r,'method','') or ''} {getattr(r,'uri','') or ''}".strip())
    head = "  ".join(p for p in parts if p)
    body = getattr(r, "decoded_command", None) or getattr(r, "request", None) \
        or getattr(r, "content_preview", None) or getattr(r, "content", None) or ""
    if body:
        body = str(body).strip().replace("\r", "")
        if len(body) > 500:
            body = body[:500] + " …(截断，完整见 Excel)"
        return head + "\n    " + body.replace("\n", "\n    ")
    return head


def render(result, log: list[str]) -> str:
    out = []
    out.append("=" * 68)
    out.append("WebShell 流量分析报告")
    out.append("=" * 68)
    stats = getattr(result, "stats", {}) or {}
    for k, v in stats.items():
        out.append(f"  {k}: {v}")

    dist = getattr(result, "type_distribution", {}) or {}
    if dist:
        out.append("\n[类型分布]")
        for k, v in dist.items():
            out.append(f"  {k}: {v}")

    records = getattr(result, "records", []) or []
    # 按风险排序：先列高危/成功解密
    def rank(r):
        order = {"高危": 0, "HIGH": 0, "中危": 1, "MEDIUM": 1, "低危": 2, "LOW": 2}
        return order.get(getattr(r, "risk_level", ""), 3)
    valid = [r for r in records if getattr(r, "is_valid_target_flow", False)]
    show = sorted(valid or records, key=rank)[:80]
    out.append(f"\n[记录明细]（共 {len(records)} 条，展示 {len(show)} 条，完整见 Excel）")
    for r in show:
        out.append("\n" + _fmt_record(r))

    alerts = getattr(result, "alerts", []) or []
    if alerts:
        out.append(f"\n[仅检测告警] {len(alerts)} 条")
        for a in alerts[:20]:
            out.append(f"  {a}")

    op = getattr(result, "output_path", None)
    if op:
        out.append(f"\n[报告已保存] {op}")
    if log:
        out.append("\n[引擎日志]")
        out.extend("  " + line for line in log[-12:])
    return "\n".join(out)
