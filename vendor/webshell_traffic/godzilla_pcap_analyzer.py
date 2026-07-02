#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哥斯拉（Godzilla）PCAP 分析入口。

识别/解密/报告/artifacts 统一走 auto_analyzer 引擎（仅启用 GodzillaPlugin），
与「自动分析」共用同一套核心逻辑；加密器（AES/XOR、raw/base64、C#/ASP 变体）
由引擎自动判定，crypter 参数仅作向后兼容。
"""

import argparse
import sys


def process_godzilla_pcap(input_path, output_path, key, uri="", crypter="",
                          status_callback=print, cancel_check=None, enable_rules=True,
                          include_filtered=True, high_med_only=False, mask_sensitive=False):
    """哥斯拉 PCAP 分析：走统一引擎，用给定连接密码试解。返回 AutoAnalysisResult。"""
    from auto_analyzer import analyze_pcap_auto
    from analyzers.legacy_plugins import GodzillaPlugin
    return analyze_pcap_auto(
        input_path, output_path, plugins=[GodzillaPlugin()],
        keys=[key] if key else [], weak_dict=False,
        status_callback=status_callback, cancel_check=cancel_check,
        enable_rules=enable_rules, include_filtered=include_filtered,
        high_med_only=high_med_only, mask_sensitive=mask_sensitive)


def main():
    parser = argparse.ArgumentParser(description="Analyze Godzilla webshell traffic in a PCAP.")
    parser.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    parser.add_argument("-o", "--output", required=True, help="输出 Excel 报告路径")
    parser.add_argument("-k", "--key", default="key", help="连接密码（默认 key）")
    parser.add_argument("-u", "--uri", default="", help="Webshell URI（可选，仅信息）")
    parser.add_argument("-c", "--crypter", default="", help="（兼容参数，加密器自动判定）")
    args = parser.parse_args()
    try:
        process_godzilla_pcap(args.input, args.output, args.key, args.uri, args.crypter)
    except FileNotFoundError:
        print(f"[!] 找不到输入文件: {args.input}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
