"""访问日志分析适配层 —— 复用 vendored 的 accesslog-analyzer 引擎。

对 GUI 只暴露一个函数：analyze_paths(paths) -> 文本报告。
"""
from __future__ import annotations

import sys
from pathlib import Path

# 让 vendor 包可导入
_VENDOR = Path(__file__).resolve().parent.parent / "vendor"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

import accesslog_analyzer as ala  # noqa: E402


def analyze_paths(paths: list[str],
                  min_severity: str = "LOW",
                  newpath_min_hits: int = 5,
                  baseline: list[str] | None = None) -> str:
    """解析 paths 下的访问日志，返回可读文本报告。"""
    entries = []
    total_lines = 0
    bad_lines = 0
    for src, lineno, entry, raw in ala.parse_paths(paths):
        total_lines += 1
        if entry is not None:
            entries.append(entry)
        elif raw.strip():
            bad_lines += 1
    if not entries:
        return ("未解析出任何 nginx 访问日志行。\n"
                "请确认日志格式与工具支持的 log_format 一致，或换文件重试。\n"
                f"（读取 {total_lines} 行，其中 {bad_lines} 行无法解析）")

    result = ala.analyze(entries)
    rows = ala.aggregate(result.incidents)

    sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    floor = sev_rank.get(min_severity.upper(), 0)
    rows = [r for r in rows if sev_rank.get(r.severity, 0) >= floor]
    rows.sort(key=lambda r: (-sev_rank.get(r.severity, 0), -r.hits))

    out = []
    out.append("=" * 70)
    out.append(f"访问日志分析报告   解析条目 {len(entries)}   无法解析 {bad_lines}")
    out.append("=" * 70)

    # 异常路径（突发/基线对比）
    try:
        anomalies = ala.detect_anomalous_paths(
            entries,
            None if not baseline else list(_iter_baseline(baseline)),
            min_hits=newpath_min_hits)
        if anomalies:
            out.append("\n[异常/突发路径]（突然出现的可疑 URL）")
            for a in anomalies[:15]:
                out.append(f"  score={a.score:<4} hits={a.hits:<4} ips={a.unique_ips:<3} {a.sample_uri}")
    except Exception as e:
        out.append(f"\n[异常路径检测跳过: {e}]")

    # 攻击命中明细
    out.append(f"\n[攻击命中]（severity >= {min_severity.upper()}，共 {len(rows)} 类）")
    if not rows:
        out.append("  无命中")
    for r in rows[:200]:
        st = ",".join(f"{k}:{v}" for k, v in r.statuses.most_common(3))
        out.append(f"  [{r.severity:<6}] {r.rule_id:<16} hits={r.hits:<4} "
                   f"{r.remote_addr:<15} {r.method} {r.path}")
        out.append(f"           status={st}  ua={r.sample_ua[:60]}")
        out.append(f"           窗口 {r.first_seen} → {r.last_seen}")

    # 高危源 IP 排行
    ip_scores = sorted(result.by_ip.items(), key=lambda kv: -kv[1].score)
    out.append("\n[高危源 IP 排行 Top 15]")
    for ip, s in ip_scores[:15]:
        if s.score <= 0:
            break
        out.append(f"  {ip:<16} score={s.score:<4} 请求={s.total} "
                   f"4xx={s.errors_4xx} 5xx={s.errors_5xx} 认证失败={s.auth_failures}")
    return "\n".join(out)


def _iter_baseline(paths: list[str]):
    for src, lineno, entry, raw in ala.parse_paths(paths):
        if entry is not None:
            yield entry


def log_format_help() -> str:
    return ("支持的 nginx log_format（main）：\n"
            "  $remote_addr - $remote_user [$time_local] \"$request\" "
            "$status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" "
            "\"$http_x_forwarded_for\" $upstream_addr "
            "ups_resp_time: $upstream_response_time request_time: $request_time\n"
            "（解析器也会自动尝试宽松匹配常见变体）")
