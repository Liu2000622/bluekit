# -*- coding: utf-8 -*-
"""
自包含 HTML 可视化报告：概览统计、攻击链时间线、攻击者→被控点关系图、IOC 汇总
（高危高亮 + 一键复制封禁清单）、记录明细表。内联 CSS/JS，无外部依赖，可直接分发。
"""

import datetime
import html

from wsat.report.attack_chain import build_attack_chains
from wsat.report.reporting import build_ioc_dict

_RISK_CN = {"high": "高危", "medium": "中危", "low": "低危"}


def _esc(v):
    return html.escape(str(v)) if v is not None else ""


def _fmt_time(t):
    if not t:
        return ""
    try:
        return datetime.datetime.fromtimestamp(float(t)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return str(t)


def _risk_class(level):
    return {"high": "r-high", "medium": "r-med", "low": "r-low"}.get(level, "r-none")


def _overview(records, stats):
    valid = [r for r in records if getattr(r, "is_valid_target_flow", False)]
    attackers = {r.client_ip for r in valid if r.client_ip}
    targets = {r.server_ip for r in valid if r.server_ip}
    high = sum(1 for r in valid if r.risk_level == "high")
    fams = sorted({r.primary_family for r in valid if r.primary_family})
    cards = [
        ("有效目标流量", len(valid), ""),
        ("攻击者", len(attackers), ""),
        ("被控主机", len(targets), ""),
        ("高危事件", high, "hot" if high else ""),
        ("涉及家族", len(fams), ""),
    ]
    cells = "".join(
        f'<div class="card {cls}"><div class="num">{_esc(n)}</div>'
        f'<div class="lbl">{_esc(t)}</div></div>'
        for t, n, cls in cards)
    fam_tags = "".join(f'<span class="tag">{_esc(f)}</span>' for f in fams)
    return f'<section><h2>概览</h2><div class="cards">{cells}</div>' \
           f'<div class="fams">{fam_tags}</div></section>'


def _relation_svg(chains):
    """攻击者→被控点二部关系图（SVG）。"""
    attackers = [c["attacker"] for c in chains]
    targets = sorted({t for c in chains for t in c["targets"]})
    if not attackers or not targets:
        return ""
    row_h, pad, w = 34, 20, 620
    h = max(len(attackers), len(targets)) * row_h + 2 * pad
    ax, tx = 150, w - 150
    ay = {a: pad + i * row_h + row_h // 2 for i, a in enumerate(attackers)}
    ty = {t: pad + i * row_h + row_h // 2 for i, t in enumerate(targets)}
    edges = []
    for c in chains:
        y1 = ay[c["attacker"]]
        for t in c["targets"]:
            y2 = ty[t]
            edges.append(f'<line x1="{ax}" y1="{y1}" x2="{tx}" y2="{y2}" '
                         f'class="edge"/>')
    nodes = []
    for a, y in ay.items():
        nodes.append(f'<circle cx="{ax}" cy="{y}" r="6" class="n-atk"/>'
                     f'<text x="{ax - 12}" y="{y + 4}" text-anchor="end" class="lab">{_esc(a)}</text>')
    for t, y in ty.items():
        nodes.append(f'<circle cx="{tx}" cy="{y}" r="6" class="n-tgt"/>'
                     f'<text x="{tx + 12}" y="{y + 4}" class="lab">{_esc(t)}</text>')
    return (f'<section><h2>攻击者 → 被控点关系</h2>'
            f'<div class="svgwrap"><svg viewBox="0 0 {w} {h}" width="100%">'
            f'{"".join(edges)}{"".join(nodes)}</svg></div>'
            f'<div class="legend"><span class="n-atk-l">● 攻击者</span>'
            f'<span class="n-tgt-l">● 被控主机</span></div></section>')


def _chains_section(chains):
    if not chains:
        return ""
    blocks = []
    for c in chains:
        cmds = "".join(
            f'<li><span class="dot"></span>{_esc(cmd)}</li>' for cmd in c.get("commands", [])[:40])
        fam = "".join(f'<span class="tag">{_esc(f)}</span>' for f in c["families"])
        span = f'{_fmt_time(c["first_time"])} ~ {_fmt_time(c["last_time"])}'
        blocks.append(
            f'<div class="chain"><div class="chain-h">'
            f'<b>{_esc(c["attacker"])}</b> → {_esc("、".join(c["targets"]))}'
            f'<span class="meta">{fam} · {c["record_count"]} 条 · 高危 {c["high_risk"]}</span></div>'
            f'<div class="chain-t">{_esc(span)}</div>'
            f'<ul class="timeline">{cmds}</ul></div>')
    return f'<section><h2>攻击链 / 行为时间线</h2>{"".join(blocks)}</section>'


def _ioc_section(ioc):
    block_ips = sorted(set(ioc.get("server_ips", []) + ioc.get("client_ips", [])))
    groups = [
        ("被控主机 (server)", ioc.get("server_endpoints", [])),
        ("攻击者 IP", ioc.get("client_ips", [])),
        ("URL 路径", ioc.get("uris", [])),
        ("载荷 SHA-256", ioc.get("hashes", [])),
        ("命令 / 行为", ioc.get("cmds", [])),
    ]
    parts = []
    for title, items in groups:
        if not items:
            continue
        lis = "".join(f"<li>{_esc(x)}</li>" for x in items)
        parts.append(f'<div class="ioc-g"><h3>{_esc(title)} ({len(items)})</h3><ul>{lis}</ul></div>')
    block_txt = "\n".join(block_ips)
    copy_btn = (f'<button class="copy" data-text="{_esc(block_txt)}">复制封禁清单 '
                f'({len(block_ips)} 个 IP)</button>') if block_ips else ""
    return f'<section><h2>IOC 汇总 {copy_btn}</h2><div class="ioc">{"".join(parts)}</div></section>'


def _records_table(records):
    valid = [r for r in records if getattr(r, "is_valid_target_flow", False)]
    valid.sort(key=lambda r: (r.risk_level != "high", r.risk_level != "medium"))
    rows = []
    for r in valid[:500]:
        cmd = (r.decoded_command or r.decoded_response or "")[:120]
        rows.append(
            f'<tr class="{_risk_class(r.risk_level)}">'
            f'<td>{_esc(_RISK_CN.get(r.risk_level, r.risk_level))}</td>'
            f'<td>{_esc(r.primary_family or r.analyzer)}</td>'
            f'<td>{_esc(r.client_ip)}</td>'
            f'<td>{_esc(r.server_ip)}:{_esc(r.server_port)}</td>'
            f'<td>{_esc(r.method)} {_esc(r.uri)}</td>'
            f'<td>{_esc(cmd)}</td></tr>')
    return (f'<section><h2>记录明细 ({len(valid)})</h2><div class="tblwrap"><table>'
            f'<thead><tr><th>风险</th><th>家族</th><th>攻击者</th><th>目标</th>'
            f'<th>请求</th><th>命令/回显</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></section>')


def build_html_report(result):
    """从分析结果生成自包含 HTML 报告字符串。"""
    records = getattr(result, "records", []) or []
    stats = getattr(result, "stats", {}) or {}
    chains = build_attack_chains(records)
    ioc = build_ioc_dict(result)
    body = (_overview(records, stats) + _relation_svg(chains)
            + _chains_section(chains) + _ioc_section(ioc) + _records_table(records))
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return _PAGE.replace("{{BODY}}", body).replace("{{GEN}}", gen)


def write_html_report(result, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html_report(result))
    return path


_PAGE = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Webshell 流量分析报告</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.5}
header{background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:24px 32px;border-bottom:1px solid #334155}
header h1{margin:0;font-size:20px}header .sub{color:#94a3b8;font-size:13px;margin-top:4px}
main{max-width:1100px;margin:0 auto;padding:0 20px 60px}
section{margin-top:32px}h2{font-size:16px;border-left:3px solid #38bdf8;padding-left:10px;color:#f1f5f9}
h3{font-size:13px;color:#94a3b8;margin:12px 0 6px}
.cards{display:flex;flex-wrap:wrap;gap:12px}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px 20px;min-width:120px;flex:1}
.card .num{font-size:26px;font-weight:700;color:#38bdf8}.card .lbl{font-size:12px;color:#94a3b8;margin-top:4px}
.card.hot .num{color:#f87171}
.fams{margin-top:12px}.tag{display:inline-block;background:#334155;color:#cbd5e1;border-radius:5px;padding:2px 8px;font-size:12px;margin:2px}
.svgwrap{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;overflow-x:auto}
.edge{stroke:#475569;stroke-width:1.2}.n-atk{fill:#f87171}.n-tgt{fill:#38bdf8}.lab{fill:#cbd5e1;font-size:12px}
.legend{font-size:12px;margin-top:8px}.legend span{margin-right:16px}.n-atk-l{color:#f87171}.n-tgt-l{color:#38bdf8}
.chain{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;margin-top:12px}
.chain-h{font-size:14px}.chain-h .meta{color:#94a3b8;font-size:12px;margin-left:8px}
.chain-t{color:#64748b;font-size:12px;margin:4px 0 8px}
.timeline{list-style:none;margin:0;padding:0 0 0 14px;border-left:2px solid #334155}
.timeline li{position:relative;padding:3px 0 3px 14px;font-size:13px;color:#cbd5e1;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.timeline .dot{position:absolute;left:-7px;top:9px;width:8px;height:8px;border-radius:50%;background:#38bdf8}
.ioc{display:flex;flex-wrap:wrap;gap:20px}.ioc-g{flex:1;min-width:240px}
.ioc-g ul{list-style:none;margin:0;padding:0}.ioc-g li{font-size:12px;font-family:ui-monospace,Menlo,monospace;color:#cbd5e1;padding:2px 0;word-break:break-all;border-bottom:1px solid #1e293b}
.copy{background:#38bdf8;color:#0f172a;border:0;border-radius:6px;padding:5px 12px;font-size:12px;font-weight:600;cursor:pointer;margin-left:10px}
.copy:hover{background:#7dd3fc}.copy.ok{background:#4ade80}
.tblwrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e293b;white-space:nowrap;max-width:340px;overflow:hidden;text-overflow:ellipsis}
th{color:#94a3b8;font-weight:600;position:sticky;top:0;background:#0f172a}
td:last-child{white-space:normal;font-family:ui-monospace,Menlo,monospace}
tr.r-high td:first-child{color:#f87171;font-weight:700}tr.r-med td:first-child{color:#fbbf24}tr.r-low td:first-child{color:#94a3b8}
</style></head><body>
<header><h1>Webshell 加密流量分析报告</h1><div class="sub">生成时间 {{GEN}}</div></header>
<main>{{BODY}}</main>
<script>
document.querySelectorAll('.copy').forEach(function(b){
  b.addEventListener('click',function(){
    var t=b.getAttribute('data-text')||'';
    navigator.clipboard.writeText(t).then(function(){
      var o=b.textContent;b.textContent='已复制 ✓';b.classList.add('ok');
      setTimeout(function(){b.textContent=o;b.classList.remove('ok')},1500);
    });
  });
});
</script></body></html>"""
