# -*- coding: utf-8 -*-
"""
攻击链 / 会话关联：把 HTTP 事务粒度的记录按攻击者 IP 聚合成行为序列画像，
还原"同一攻击者 → 多个被控点 → 一连串命令"的攻击链路，补足单条事务视角的不足。

只依赖 analysis_record（不 import report_writer / reporting），供二者复用避免循环导入。
"""

from wsat.core.analysis_record import RISK_HIGH, RISK_MEDIUM


def _record_time(r):
    if r.request_time is not None:
        return r.request_time
    return r.timestamp if r.timestamp is not None else 0.0


def _command_of(r):
    """取记录里最能代表"这一步做了什么"的可读文本。"""
    for raw in (r.decoded_command, r.request, r.content, r.decoded_response, r.response):
        if raw and "�" not in raw:
            c = " ".join(raw.split())
            if c:
                return c[:120]
    return None


def build_attack_chains(records):
    """
    把有效目标流量按攻击者 client_ip 聚合。返回按危害度排序的画像列表：
      attacker / targets / families / first_time / last_time /
      record_count / high_risk / medium_risk / commands（按时间的行为序列）
    """
    recs = [r for r in (records or []) if getattr(r, "is_valid_target_flow", False)]
    by_attacker = {}
    for r in recs:
        atk = r.client_ip or r.src_ip or "unknown"
        prof = by_attacker.setdefault(atk, {
            "attacker": atk, "targets": set(), "families": set(),
            "records": [], "first_time": None, "last_time": None,
            "high_risk": 0, "medium_risk": 0,
        })
        if r.server_ip:
            prof["targets"].add(f"{r.server_ip}:{r.server_port or ''}".rstrip(":"))
        if r.primary_family:
            prof["families"].add(r.primary_family)
        prof["records"].append(r)
        t = _record_time(r)
        if prof["first_time"] is None or t < prof["first_time"]:
            prof["first_time"] = t
        if prof["last_time"] is None or t > prof["last_time"]:
            prof["last_time"] = t
        if r.risk_level == RISK_HIGH:
            prof["high_risk"] += 1
        elif r.risk_level == RISK_MEDIUM:
            prof["medium_risk"] += 1

    chains = []
    for prof in by_attacker.values():
        ordered = sorted(prof["records"], key=_record_time)
        commands = []
        for r in ordered:
            c = _command_of(r)
            if c:
                commands.append(c)
        chains.append({
            "attacker": prof["attacker"],
            "targets": sorted(prof["targets"]),
            "families": sorted(prof["families"]),
            "first_time": prof["first_time"],
            "last_time": prof["last_time"],
            "record_count": len(prof["records"]),
            "high_risk": prof["high_risk"],
            "medium_risk": prof["medium_risk"],
            "commands": commands,
        })
    # 危害度优先：高危多 / 记录多的攻击者排前
    chains.sort(key=lambda c: (-c["high_risk"], -c["medium_risk"], -c["record_count"]))
    return chains
