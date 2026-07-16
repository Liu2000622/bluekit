# -*- coding: utf-8 -*-
"""
DNS 隧道检测：把逐条 DNS 查询按注册域聚合，用多特征综合研判是否为
数据外带 / C2 的 DNS 隧道（iodine / dnscat2 / dns2tcp 等的共性）。

判据（组合命中才告警，压制正常 CDN/遥测的误报）：
  - 单一注册域下唯一子域名过多（编码后的数据块各不相同）；
  - 子域标签超长（接近 DNS 63 字节上限）；
  - 子域字符高熵（base32/hex 编码的数据段）；
  - 高比例数据型查询（TXT / NULL / CNAME 常用作数据通道）。

产出与其它隧道插件一致的「仅检测告警」结构，进入报告的可疑流量告警。
"""

import math
from collections import Counter, defaultdict

from wsat.core.pcap_utils import DNS_QTYPES

# TXT / NULL / CNAME 常被 DNS 隧道用作数据承载
_DATA_QTYPES = {16, 10, 5}


def _entropy(s: str) -> float:
    """字符串香农熵（bit/字符）。base32/hex 编码的随机数据熵高。"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _split_domain(qname: str):
    """粗略拆注册域与子域：取末两级为注册域，其余为子域。"""
    labels = [x for x in qname.split(".") if x]
    if len(labels) < 2:
        return qname, ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])


def detect_dns_tunnels(queries, min_unique: int = 8):
    """queries: Iterable[DnsQuery]。返回告警 dict 列表（与插件告警同构）。"""
    by_domain = defaultdict(list)
    for q in queries:
        reg, sub = _split_domain(q.qname)
        by_domain[reg].append((q, sub))

    alerts = []
    for reg, items in by_domain.items():
        subs = [sub for _q, sub in items if sub]
        if not subs:
            continue
        unique_subs = set(subs)
        max_label = max((len(lbl) for s in subs for lbl in s.split(".")), default=0)
        entropies = [_entropy(s.replace(".", "")) for s in subs]
        avg_entropy = sum(entropies) / len(entropies)
        qtypes = Counter(q.qtype for q, _ in items)
        data_ratio = sum(qtypes[t] for t in _DATA_QTYPES) / len(items)

        evidence = []
        score = 0
        if len(unique_subs) >= min_unique:
            evidence.append(f"单域名 {reg} 下 {len(unique_subs)} 个唯一子域名（疑似编码数据块）")
            score += 1
        if max_label >= 40:
            evidence.append(f"超长子域标签（最长 {max_label} 字节，接近 DNS 63 上限）")
            score += 1
        if avg_entropy >= 3.5:
            evidence.append(f"子域名高熵（均 {avg_entropy:.1f} bit/字符，疑似 base32/hex 编码）")
            score += 1
        if data_ratio >= 0.3:
            top = ",".join(DNS_QTYPES.get(t, str(t)) for t, _ in qtypes.most_common(3))
            evidence.append(f"高比例数据型查询（TXT/NULL/CNAME 占 {data_ratio*100:.0f}%，主要 {top}）")
            score += 1

        # 唯一子域名足够多 + 至少一个"编码/数据"特征，才认定为隧道
        if len(unique_subs) >= min_unique and score >= 2:
            srcs = Counter(q.src for q, _ in items)
            alerts.append({
                "流量类型": "DNS 隧道",
                "类别": "tunnel",
                "时间": min(q.time for q, _ in items),
                "流ID": f"{reg} (DNS/UDP)",
                "源IP": srcs.most_common(1)[0][0],
                "目的IP": items[0][0].dst,
                "置信度": "high" if score >= 3 else "medium",
                "状态": "仅检测告警",
                "识别依据": "；".join(evidence),
            })
    return alerts
