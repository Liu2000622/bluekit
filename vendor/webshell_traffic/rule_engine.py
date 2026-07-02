# -*- coding: utf-8 -*-
"""
轻量规则引擎：对解密后的明文做攻击行为识别与风险标注。

规则从 rules/risk_rules.json 加载（配置化，不硬编码在业务逻辑里），对
AnalysisRecord.primary_text() 做正则匹配，填充：
  behavior_tags / risk_level / risk_score / matched_rules /
  evidence_excerpt / analyst_note

设计要点：
  - 命中多条规则时 risk_level 取最高；risk_score 为各命中规则分值之和（封顶 100）；
  - 不覆盖原始解密内容（request/response/content 保持不变）；
  - 只标注有效目标流量（is_valid_target_flow=True），过滤/失败记录不参与。
"""

import os
import re
import json

from analysis_record import RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO

_DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "rules", "risk_rules.json")

# 风险等级排序与分值
_RISK_ORDER = {RISK_INFO: 0, RISK_LOW: 1, RISK_MEDIUM: 2, RISK_HIGH: 3}
_RISK_SCORE = {RISK_INFO: 0, RISK_LOW: 10, RISK_MEDIUM: 25, RISK_HIGH: 40}

_rules_cache = None


def load_rules(path=None, use_cache=True):
    """加载并编译规则。返回规则列表，每条含编译好的正则。"""
    global _rules_cache
    if use_cache and path is None and _rules_cache is not None:
        return _rules_cache

    rules_path = path or _DEFAULT_RULES_PATH
    with open(rules_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    compiled = []
    for rule in data.get("rules", []):
        patterns = rule.get("patterns", [])
        try:
            regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
        except re.error as e:
            # 单条规则正则有误不应拖垮整体
            print(f"[!] 规则 {rule.get('id')} 正则编译失败，已跳过: {e}")
            continue
        compiled.append({
            "id": rule.get("id", "UNKNOWN"),
            "name": rule.get("name", ""),
            "risk_level": rule.get("risk_level", RISK_INFO),
            "behavior": rule.get("behavior", "其他可疑行为"),
            "description": rule.get("description", ""),
            "recommendation": rule.get("recommendation", ""),
            "regexes": regexes,
        })

    if path is None:
        _rules_cache = compiled
    return compiled


def _make_note(hits):
    """根据命中规则生成简短研判说明。"""
    behaviors = sorted({h["behavior"] for h in hits})
    top = max(hits, key=lambda h: _RISK_ORDER.get(h["risk_level"], 0))
    note = f"命中 {len(hits)} 条规则（{'、'.join(behaviors)}），最高风险 {top['risk_level']}。"
    if top.get("recommendation"):
        note += f"建议：{top['recommendation']}"
    return note


def annotate_record(record, rules):
    """对单条记录做风险标注（就地修改并返回）。"""
    text = record.primary_text()
    if not text:
        return record

    hits = []
    evidences = []
    for rule in rules:
        for rx in rule["regexes"]:
            m = rx.search(text)
            if m:
                hits.append(rule)
                evidences.append(m.group(0))
                break  # 一条规则命中一次即可

    if not hits:
        return record

    record.matched_rules = [h["id"] for h in hits]
    record.behavior_tags = sorted({h["behavior"] for h in hits})
    record.risk_level = max((h["risk_level"] for h in hits),
                            key=lambda lv: _RISK_ORDER.get(lv, 0))
    record.risk_score = min(100, sum(_RISK_SCORE.get(h["risk_level"], 0) for h in hits))
    record.evidence_excerpt = "; ".join(dict.fromkeys(evidences))[:300]
    record.analyst_note = _make_note(hits)
    return record


def annotate_records(records, rules=None):
    """对记录列表中的有效目标流量做风险标注。"""
    if rules is None:
        rules = load_rules()
    for r in records:
        if r.is_valid_target_flow:
            annotate_record(r, rules)
    return records
