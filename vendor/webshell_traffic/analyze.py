#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webshell 流量分析 —— 统一命令行入口。

把分散在各模块的分析能力聚合为一个 CLI，便于脚本化 / 批量使用：

  自动识别 PCAP 中的疑似 webshell 类型：
    python analyze.py auto -i attack.pcap

  按指定类型解密并导出 Excel 报告：
    python analyze.py suo5     -i attack.pcap -o report.xlsx
    python analyze.py godzilla -i attack.pcap -o report.xlsx -k <密码> -u /shell.jsp -c AES_BASE64
    python analyze.py behinder -i attack.pcap -o report.xlsx -p <密码>

图形界面仍可通过 `python main.py` 启动，二者共用同一套底层逻辑。
"""

import argparse
import sys

from auto_analyzer import analyze_pcap_auto
from suo5_full_analyzer import process_pcap_to_excel
from godzilla_pcap_analyzer import process_godzilla_pcap
from behinder_pcap_analyzer import process_behinder_pcap

# 与 GUI 中保持一致的加密器选项
GODZILLA_CRYPTERS = ["AES_BASE64", "XOR_BASE64", "PHP_EVAL_XOR_BASE64"]


def cmd_auto(args):
    weak_dict = False if args.no_weak_dict else args.weak_dict
    result = analyze_pcap_auto(
        args.input,
        args.output,
        keys=args.keys,
        weak_dict=weak_dict,
        crypters=args.crypters,
    )
    print("\n=== 自动分析汇总 ===")
    for item in result.type_distribution.values():
        print(f"{item['流量类型']}: 命中 {item['命中流数']} 流，"
              f"成功记录 {item['成功解密记录数']}，"
              f"过滤/待补充 {item['过滤/待补充数']}，"
              f"告警 {item['仅检测告警数']}")
    print(f"\n[*] 报告: {args.output}")
    return 0 if result.stats.get("识别命中流数", 0) else 1


def cmd_suo5(args):
    process_pcap_to_excel(args.input, args.output)
    return 0


def cmd_godzilla(args):
    process_godzilla_pcap(args.input, args.output, args.key, args.uri, args.crypter)
    return 0


def cmd_behinder(args):
    process_behinder_pcap(args.input, args.output, args.password)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="Webshell 加密流量分析工具（统一 CLI 入口）。",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # auto
    p_auto = sub.add_parser("auto", help="自动识别、解密/检测并导出合并 Excel 报告")
    p_auto.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    p_auto.add_argument("-o", "--output", default="auto_analysis_report.xlsx",
                        help="输出 Excel 报告路径 (默认 auto_analysis_report.xlsx)")
    p_auto.add_argument("--keys", nargs="*", default=[],
                        help="候选密钥/密码，可提供多个，例如 --keys pass rebeyond")
    p_auto.add_argument("--dict", dest="weak_dict", default="weak",
                        help="弱口令字典: weak 使用内置字典，或填写字典文件路径")
    p_auto.add_argument("--no-weak-dict", action="store_true",
                        help="禁用内置弱口令试解")
    p_auto.add_argument("--crypters", nargs="*", default=None,
                        help="哥斯拉候选加密器，默认尝试 AES/XOR/PHP_EVAL")
    p_auto.set_defaults(func=cmd_auto)

    # suo5
    p_suo5 = sub.add_parser("suo5", help="解密 suo5 流量并导出 Excel")
    p_suo5.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    p_suo5.add_argument("-o", "--output", required=True, help="输出 Excel 报告路径")
    p_suo5.set_defaults(func=cmd_suo5)

    # godzilla
    p_god = sub.add_parser("godzilla", help="解密哥斯拉流量并导出 Excel")
    p_god.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    p_god.add_argument("-o", "--output", required=True, help="输出 Excel 报告路径")
    p_god.add_argument("-k", "--key", required=True, help="连接密码 (key)")
    p_god.add_argument("-u", "--uri", required=True, help="Webshell URI，例如 /shell.jsp")
    p_god.add_argument("-c", "--crypter", default="AES_BASE64", choices=GODZILLA_CRYPTERS,
                       help="加密器类型 (默认 AES_BASE64)")
    p_god.set_defaults(func=cmd_godzilla)

    # behinder
    p_beh = sub.add_parser("behinder", help="解密冰蝎流量并导出 Excel")
    p_beh.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    p_beh.add_argument("-o", "--output", required=True, help="输出 Excel 报告路径")
    p_beh.add_argument("-p", "--password", required=True, help="Webshell 连接密码")
    p_beh.set_defaults(func=cmd_behinder)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        sys.exit(args.func(args))
    except FileNotFoundError:
        print(f"[!] 找不到输入文件: {getattr(args, 'input', '?')}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] 已中断。", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
