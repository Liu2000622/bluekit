# -*- coding: utf-8 -*-
"""
准确率评估：对一批「已标注」的 pcap 跑自动分析，对照预期家族/类别，度量
识别准确率 / 误报率 / 漏报率。用作质量回归门禁——改判据后自动量化，防止回退。

标注来源两种：
  1. evaluate(cases)：显式传入 (pcap_path, category, family) 列表（合成基准用）；
  2. evaluate_dir(dir)：扫描目录，按文件名/路径推断标注（真实样本集用）。

category: "webshell" | "normal" | "tunnel"（可按需扩展）。
"""

import glob
import os

from wsat.core.auto_analyzer import analyze_pcap_auto

# 识别结果家族名 → 标准家族（归一化，兼容大小写与别名）
_FAMILY_ALIASES = (
    ("rebeyond", "behinder"),
    ("behinder", "behinder"),
    ("godzilla", "godzilla"),
    ("antsword", "antsword"),
    ("suo5", "suo5"),
    ("chopper", "chopper"),
    ("weevely", "weevely"),
    # C2 家族（别名统一到插件名，供 tunnel 类别对照告警）
    ("cobalt", "cobalt_strike"),
    ("beacon", "cobalt_strike"),
    ("meterpreter", "meterpreter"),
    ("metasploit", "meterpreter"),
    ("havoc", "havoc"),
    ("sliver", "sliver"),
    ("merlin", "merlin"),
)


def normalize_family(name):
    if not name:
        return None
    n = str(name).lower().strip()
    for key, canon in _FAMILY_ALIASES:
        if key in n:
            return canon
    return n


def infer_label(rel_path):
    """从 pcap 相对路径/文件名推断预期 (category, family)；无法判断返回 (None, None)。"""
    p = rel_path.lower()
    if "/normal/" in p or p.startswith("normal/") or "benign" in p:
        return ("normal", None)
    if "behinder" in p or "rebeyond" in p:
        return ("webshell", "behinder")
    if "godzilla" in p:
        return ("webshell", "godzilla")
    if "_ant" in p or "antsword" in p or "/ant." in p or "ant.pcap" in p:
        return ("webshell", "antsword")
    if "chopper" in p or "caidao" in p:
        return ("webshell", "chopper")
    if "weevely" in p:
        return ("webshell", "weevely")
    if "suo5" in p:
        return ("tunnel", "suo5")
    # 新一代开源 C2（多为仅告警）
    if "havoc" in p:
        return ("tunnel", "havoc")
    if "sliver" in p:
        return ("tunnel", "sliver")
    if "merlin" in p:
        return ("tunnel", "merlin")
    if "cobalt" in p or "beacon" in p:
        return ("tunnel", "cobalt_strike")
    if "meterpreter" in p or "metasploit" in p or "_msf" in p:
        return ("tunnel", "meterpreter")
    return (None, None)


def _identified_families(result):
    """从分析结果收集「已解出有效明文」的家族（归一化）。"""
    fams = {normalize_family(rec.primary_family or rec.analyzer)
            for rec in result.records if rec.is_valid_target_flow}
    fams.discard(None)
    return fams


def _recognized_families(result):
    """从分析结果收集「已识别」的家族（归一化）——含仅识别未解密（待补充密码）、
    仅告警、以及有记录但未解出的。与 _identified_families（须解出明文）区分。"""
    fams = {normalize_family(rec.primary_family or rec.analyzer) for rec in result.records}
    fams |= {normalize_family(a.get("流量类型")) for a in (result.alerts or []) if a.get("流量类型")}
    fams |= {normalize_family(k) for k in (result.type_distribution or {})}
    fams.discard(None)
    return fams


def evaluate(cases, analyze_fn=None):
    """
    cases: iterable of (pcap_path, category, family)。
    返回 (metrics, details)：metrics 为各类计数与比率，details 为异常项明细。
    """
    if analyze_fn is None:
        def analyze_fn(p):
            return analyze_pcap_auto(p, None, status_callback=lambda *_: None)

    m = {
        "webshell_total": 0, "webshell_correct": 0, "webshell_wrong": 0, "webshell_missed": 0,
        "webshell_detected": 0, "webshell_recognized": 0,
        "normal_total": 0, "normal_clean": 0, "normal_fp": 0,
        "tunnel_total": 0, "tunnel_correct": 0, "tunnel_missed": 0,
        "errors": 0,
    }
    details = []
    for path, cat, fam in cases:
        try:
            result = analyze_fn(path)
        except Exception as e:  # noqa: BLE001
            m["errors"] += 1
            details.append((path, cat, fam, "ERROR", str(e)))
            continue
        valid = _identified_families(result)
        recognized = _recognized_families(result)
        alert_fams = {normalize_family(a.get("流量类型"))
                      for a in (result.alerts or []) if a.get("流量类型")}
        if cat == "normal":
            m["normal_total"] += 1
            if valid:
                m["normal_fp"] += 1
                details.append((path, cat, fam, "FP(误报)", sorted(valid)))
            else:
                m["normal_clean"] += 1
        elif cat == "webshell":
            m["webshell_total"] += 1
            # 三个层次分开统计：
            #  - recognized: 识别到（detect 命中，含仅识别未解密/待补充密码）；
            #  - detected  : 判为任一 webshell/恶意（有有效明文或告警）；
            #  - correct   : 家族识别正确且解出有效明文。
            # 真实样本按文件名标注家族有噪声（上传样本按工具名标注、加密样本缺密码），
            # 「识别率」最能反映检测能力、对标注噪声最鲁棒，适合做真实样本门禁。
            if recognized:
                m["webshell_recognized"] += 1
            if valid or alert_fams:
                m["webshell_detected"] += 1
            if fam in valid:
                m["webshell_correct"] += 1
            elif valid:
                m["webshell_wrong"] += 1
                details.append((path, cat, fam, "WRONG(识别错家族)", sorted(valid)))
            else:
                m["webshell_missed"] += 1
                details.append((path, cat, fam, "MISSED(漏报)", []))
        elif cat == "tunnel":
            m["tunnel_total"] += 1
            if fam in valid or fam in alert_fams:
                m["tunnel_correct"] += 1
            else:
                m["tunnel_missed"] += 1
                details.append((path, cat, fam, "MISSED(漏报)", sorted(valid | alert_fams)))

    if m["webshell_total"]:
        m["webshell_accuracy"] = round(m["webshell_correct"] / m["webshell_total"], 4)
        m["webshell_detection_rate"] = round(m["webshell_detected"] / m["webshell_total"], 4)
        m["webshell_recognition_rate"] = round(m["webshell_recognized"] / m["webshell_total"], 4)
    if m["normal_total"]:
        m["normal_fp_rate"] = round(m["normal_fp"] / m["normal_total"], 4)
    if m["tunnel_total"]:
        m["tunnel_accuracy"] = round(m["tunnel_correct"] / m["tunnel_total"], 4)
    return m, details


def evaluate_dir(pcap_dir, analyze_fn=None, max_bytes=None):
    """扫描目录下所有 pcap，按文件名标注后评估；无法标注的样本跳过。
    max_bytes 非空时跳过超过该大小的样本，便于门禁控制运行时长。"""
    cases = []
    for path in sorted(glob.glob(os.path.join(pcap_dir, "**", "*.pcap"), recursive=True)
                       + glob.glob(os.path.join(pcap_dir, "**", "*.pcapng"), recursive=True)):
        if max_bytes is not None:
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
            except OSError:
                continue
        cat, fam = infer_label(os.path.relpath(path, pcap_dir))
        if cat:
            cases.append((path, cat, fam))
    return evaluate(cases, analyze_fn)


def format_report(metrics, details):
    """把指标与明细渲染为可读文本报告。"""
    lines = ["===== 准确率评估 ====="]
    if metrics.get("webshell_total"):
        lines.append(f"WebShell 识别率: {metrics['webshell_recognized']}/{metrics['webshell_total']} "
                     f"({metrics.get('webshell_recognition_rate', 0) * 100:.1f}%)（含仅识别未解密）；"
                     f"检出率 {metrics.get('webshell_detection_rate', 0) * 100:.1f}%；"
                     f"家族识别正确 {metrics['webshell_correct']} "
                     f"(准确率 {metrics.get('webshell_accuracy', 0) * 100:.1f}%)，"
                     f"识别错家族 {metrics['webshell_wrong']}，漏报 {metrics['webshell_missed']}")
    if metrics.get("normal_total"):
        lines.append(f"正常流量: {metrics['normal_clean']}/{metrics['normal_total']} 干净，"
                     f"误报 {metrics['normal_fp']} (误报率 {metrics.get('normal_fp_rate', 0) * 100:.1f}%)")
    if metrics.get("tunnel_total"):
        lines.append(f"隧道/工具: {metrics['tunnel_correct']}/{metrics['tunnel_total']} 正确")
    if metrics.get("errors"):
        lines.append(f"分析异常: {metrics['errors']}")
    if details:
        lines.append("\n--- 需关注的样本 ---")
        for path, _cat, fam, verdict, got in details[:60]:
            lines.append(f"  [{verdict}] {os.path.basename(path)} 预期={fam} 实际={got}")
    return "\n".join(lines)
