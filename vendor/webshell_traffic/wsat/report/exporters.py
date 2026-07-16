# -*- coding: utf-8 -*-
"""
分析结果的机器可读导出：JSON / CSV（记录级），以及 IOC 的 JSON / CSV / STIX 2.1
（见 export_ioc_*）。便于把研判结果接入 SIEM / SOAR / 威胁情报平台做自动化联动。
"""

import csv
import json
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

# CSV 关键字段（一次 HTTP 事务 = 一行）
_CSV_FIELDS = [
    "timestamp", "primary_family", "analyzer", "risk_level", "risk_score",
    "detect_confidence", "client_ip", "server_ip", "server_port",
    "method", "uri", "decode_status", "content_type",
    "decoded_command", "content_sha256", "payload_type", "payload_file",
    "behavior_tags", "matched_rules",
]


def _scalar(v):
    if isinstance(v, (list, tuple)):
        return "|".join(str(x) for x in v)
    return "" if v is None else v


def export_records_json(records, path, *, stats=None, alerts=None, type_distribution=None):
    """完整结构化 JSON：records + stats + alerts + 类型分布。"""
    recs = []
    for r in records:
        d = asdict(r)
        raw = d.pop("raw_payload", None)
        if raw is not None:
            # 二进制原始字节不入 JSON，仅记长度；完整内容见落盘文件 payload_file
            d["raw_payload_len"] = len(raw)
        recs.append(d)
    data = {
        "meta": {"tool": "webshell-traffic-analyzer", "schema": "records-v1"},
        "stats": stats or {},
        "type_distribution": type_distribution or {},
        "alerts": list(alerts or []),
        "records": recs,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    return path


def export_records_csv(records, path, fields=None):
    """扁平 CSV（utf-8-sig，Excel 可直接打开不乱码），一条记录一行。"""
    cols = fields or _CSV_FIELDS
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in records:
            w.writerow([_scalar(getattr(r, c, "")) for c in cols])
    return path


# --- IOC 导出（JSON / CSV / STIX 2.1）---

def export_ioc_json(ioc, path):
    """IOC 聚合字典（reporting.build_ioc_dict 的输出）直接落 JSON。"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": {"tool": "webshell-traffic-analyzer", "schema": "ioc-v1"},
                   "ioc": ioc}, f, ensure_ascii=False, indent=2)
    return path


def export_ioc_csv(ioc, path):
    """IOC 扁平为 (type, value) 两列 CSV。"""
    type_map = [
        ("server_ip", "server_ips"), ("client_ip", "client_ips"),
        ("family", "families"), ("uri", "uris"),
        ("command", "commands"), ("sha256", "hashes"),
        ("alert_family", "alert_families"),
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value"])
        for label, key in type_map:
            for v in ioc.get(key, []):
                w.writerow([label, v])
    return path


def _stix_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_indicator(pattern, name, now):
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now, "modified": now,
        "name": name, "pattern": pattern, "pattern_type": "stix",
        "valid_from": now, "labels": ["malicious-activity"],
    }


def export_ioc_stix(ioc, path):
    """
    导出 STIX 2.1 bundle（indicators）。网络/文件类 IOC 用标准 STIX pattern：
    IP → ipv4-addr/ipv6-addr，内容哈希 → file:hashes.'SHA-256'。
    （URI/命令/家族等非标准可观测项见 JSON/CSV 导出。）
    """
    now = _stix_now()
    objects = []
    for ip in ioc.get("server_ips", []):
        typ = "ipv6-addr" if ":" in ip else "ipv4-addr"
        objects.append(_stix_indicator(f"[{typ}:value = '{ip}']", f"受控服务端 {ip}", now))
    for ip in ioc.get("client_ips", []):
        typ = "ipv6-addr" if ":" in ip else "ipv4-addr"
        objects.append(_stix_indicator(f"[{typ}:value = '{ip}']", f"攻击端 {ip}", now))
    for h in ioc.get("hashes", []):
        objects.append(_stix_indicator(f"[file:hashes.'SHA-256' = '{h}']", f"载荷内容 {h[:12]}", now))
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    return path


def _suricata_escape(s):
    """转义 Suricata content 字符串中的特殊字符。"""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace(";", "|3B|")


def export_suricata(ioc, path, *, alerts=None, sid_base=9000000):
    """
    把 IOC 反向输出为 Suricata 规则，便于融入现有 IDS：恶意 URI(http.uri)、受控
    服务端 IP、C2 的 JA3/JA3S 指纹(ja3.hash/ja3s.hash)、载荷 SHA-256(filesha256)。
    sid 从 sid_base 起自增；使用前须按本地环境调整 $HOME_NET 与 sid 段避免冲突。
    """
    import re
    rules = []
    sid = sid_base

    for uri in ioc.get("uris", []):
        if not uri:
            continue
        sid += 1
        rules.append(
            f'alert http any any -> $HOME_NET any (msg:"[WSA] 疑似 Webshell/恶意访问 URI"; '
            f'flow:established,to_server; http.uri; content:"{_suricata_escape(uri)}"; '
            f'sid:{sid}; rev:1;)')

    for ip in ioc.get("server_ips", []):
        sid += 1
        dst = f"[{ip}]" if ":" in ip else ip
        rules.append(
            f'alert ip any any -> {dst} any (msg:"[WSA] 疑似 C2/Webshell 服务端 {ip}"; '
            f'sid:{sid}; rev:1;)')

    seen = set()
    for a in (alerts or []):
        evidence = a.get("识别依据", "")
        name = _suricata_escape(a.get("流量类型", "C2"))
        # JA3 / JA3S：32 位 md5
        for kind, h in re.findall(r"(JA3S?)=([0-9a-f]{32})", evidence):
            if (kind, h) in seen:
                continue
            seen.add((kind, h))
            sid += 1
            field = "ja3s.hash" if kind == "JA3S" else "ja3.hash"
            rules.append(
                f'alert tls any any -> any any (msg:"[WSA] C2 TLS 指纹 {name}"; '
                f'{field}; content:"{h}"; sid:{sid}; rev:1;)')
        # JA4（客户端）：ja4.hash 关键字（Suricata 7+）；JA4S 暂无标准关键字，故仅导出 JA4
        for fp in re.findall(r"JA4=([a-z0-9]{10}_[0-9a-f]{12}_[0-9a-f]{12})", evidence):
            if ("JA4", fp) in seen:
                continue
            seen.add(("JA4", fp))
            sid += 1
            rules.append(
                f'alert tls any any -> any any (msg:"[WSA] C2 TLS 指纹(JA4) {name}"; '
                f'ja4.hash; content:"{fp}"; sid:{sid}; rev:1;)')

    for h in ioc.get("hashes", []):
        sid += 1
        rules.append(
            f'alert http any any -> any any (msg:"[WSA] 恶意载荷 SHA-256 {h[:16]}"; '
            f'filesha256:{h}; sid:{sid}; rev:1;)')

    header = ("# Suricata 规则集（Webshell 流量分析工具自动生成）\n"
              "# 使用前请：1) 按本地网络调整 $HOME_NET；2) 确认 sid 段(9000000+)不冲突；\n"
              "#           3) filesha256 规则需 Suricata 启用 file-hash 支持。\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
        f.write("\n" if rules else "")
    return path


def export_all(result, base_path, *, ioc=None):
    """把一次分析结果导出为全套机器可读产物（records JSON/CSV + IOC JSON/CSV/STIX +
    Suricata 规则），返回写出的文件路径列表。base_path 为输出前缀（扩展名会被忽略）。

    供 GUI「导出 IOC/IDS 规则」与需要一键落地的场景复用，与 CLI --json/--csv/--ioc-*/
    --suricata 对等。"""
    from wsat.report.reporting import build_ioc_dict
    if ioc is None:
        ioc = build_ioc_dict(result)
    base = os.path.splitext(base_path)[0]
    written = []
    export_records_json(result.records, base + ".records.json", stats=result.stats,
                        alerts=result.alerts, type_distribution=result.type_distribution)
    written.append(base + ".records.json")
    export_records_csv(result.records, base + ".records.csv")
    written.append(base + ".records.csv")
    export_ioc_json(ioc, base + ".ioc.json")
    written.append(base + ".ioc.json")
    export_ioc_csv(ioc, base + ".ioc.csv")
    written.append(base + ".ioc.csv")
    export_ioc_stix(ioc, base + ".ioc.stix.json")
    written.append(base + ".ioc.stix.json")
    export_suricata(ioc, base + ".rules", alerts=result.alerts)
    written.append(base + ".rules")
    return written
