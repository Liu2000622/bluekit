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


# 哥斯拉加密器选项（与原版一致）
GODZILLA_CRYPTERS = ["AES_BASE64 (V4 Default)", "XOR_BASE64 (V3 Default)",
                     "PHP_EVAL_XOR_BASE64"]


def manual_decrypt(tool: str, payload: str, key: str = "", crypter: str = "") -> str:
    """手动载荷解密（原版同源函数）。tool: suo5 / godzilla / behinder。"""
    _ensure_path()
    if tool == "suo5":
        from decrypt_suo5_payload import decrypt_hex_string
        return decrypt_hex_string(payload)
    if tool == "godzilla":
        from decrypt_godzilla_payload import godzilla_decode
        return godzilla_decode(payload, key, crypter)
    if tool == "behinder":
        from decrypt_behinder_payload import behinder_decode
        return behinder_decode(payload.strip(), key or "rebeyond")
    raise ValueError(f"未知工具: {tool}")


def pcap_analyze(tool: str, input_path: str, output_path: str,
                 password: str = "", key: str = "", crypter: str = ""):
    """针对指定工具的 PCAP 专项分析（原版同源函数），返回 (result, log)。"""
    _ensure_path()
    log: list[str] = []
    cb = lambda m: log.append(str(m))  # noqa: E731
    if tool == "suo5":
        from suo5_full_analyzer import process_pcap_to_excel
        res = process_pcap_to_excel(input_path, output_path, status_callback=cb)
    elif tool == "godzilla":
        from godzilla_pcap_analyzer import process_godzilla_pcap
        res = process_godzilla_pcap(input_path, output_path, key,
                                    crypter=crypter, status_callback=cb)
    elif tool == "behinder":
        from behinder_pcap_analyzer import process_behinder_pcap
        res = process_behinder_pcap(input_path, output_path, password,
                                    status_callback=cb)
    else:
        raise ValueError(f"未知工具: {tool}")
    return res, log


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
