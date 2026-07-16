# -*- coding: utf-8 -*-
"""
威胁情报加载：从 JSON 文件批量导入已知 C2 的 TLS 指纹（JA3/JA3S/JA4/JA4S），
填充 crypto.ja3 的内置已知表——无需改代码即可对接公开指纹库（FoxIO JA4+ DB、
abuse.ch SSLBL 等）。

安全性：表内条目即便过期/错误，也只会「漏配」（永不匹配良性流量），不会误报，
因此可安全地按情报增量补充。随仓库分发 rules/threat_intel.json 作为默认起点，
存在即自动加载（GUI/CLI 均生效）；也可用 CLI --intel 追加自定义情报文件。

JSON 结构（各段可选，未知段忽略）：
{
  "ja3":  {"<md5 32hex>": "名称", ...},
  "ja3s": {"<md5 32hex>": "名称", ...},
  "ja4":  {"<ja4 指纹串>": "名称", ...},
  "ja4s": {"<ja4s 指纹串>": "名称", ...},
  "_comment": "以 _ 开头的键为说明字段，加载时忽略"
}
"""

import json
import os
import sys

import wsat.crypto.ja3 as ja3


def _resource_base():
    """情报文件所在根目录。PyInstaller 打包后数据解压到 sys._MEIPASS，须优先从那里找。"""
    return getattr(sys, "_MEIPASS", None) or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))


# 随仓库分发的默认情报文件；存在即自动加载
DEFAULT_INTEL_PATH = os.path.join(_resource_base(), "rules", "threat_intel.json")


# SNI 域名 / 服务端 IP 观察名单：来自外部情报（威胁 feed）的 IOC，命中即告警。
# 与指纹不同，这些是「值型」IOC，正常由操作者按自有情报维护。
_SNI_WATCH = {}
_IP_WATCH = {}


def _tables():
    """返回 段名 -> ja3 模块内置已知表（同一 dict 引用，原地合并即时生效）。"""
    return {"ja3": ja3._KNOWN_JA3, "ja3s": ja3._KNOWN_JA3S,
            "ja4": ja3._KNOWN_JA4, "ja4s": ja3._KNOWN_JA4S}


def register_fingerprints(intel):
    """把 dict（ja3/ja3s/ja4/ja4s 指纹 + sni/ip 观察名单）合并进内置表，返回加载条目数。"""
    if not isinstance(intel, dict):
        return 0
    count = 0
    for section, table in _tables().items():
        entries = intel.get(section)
        if not isinstance(entries, dict):
            continue
        for fp, name in entries.items():
            if fp and name:
                table[str(fp).strip()] = str(name)
                count += 1
    for section, table in (("sni", _SNI_WATCH), ("ip", _IP_WATCH)):
        entries = intel.get(section)
        if not isinstance(entries, dict):
            continue
        for value, name in entries.items():
            if value and name:
                key = str(value).strip()
                table[key.lower() if section == "sni" else key] = str(name)
                count += 1
    return count


def match_sni(host):
    """SNI 主机名是否命中观察名单（精确或子域后缀匹配）；命中返回名称，否则 None。"""
    if not host or not _SNI_WATCH:
        return None
    h = host.lower().rstrip(".")
    for domain, name in _SNI_WATCH.items():
        if h == domain or h.endswith("." + domain):
            return name
    return None


def match_ip(ip):
    """服务端/对端 IP 是否命中观察名单（精确匹配）；命中返回名称，否则 None。"""
    return _IP_WATCH.get(ip) if ip else None


def load_intel_file(path):
    """从 JSON 文件加载威胁情报（指纹 + SNI/IP 名单）；文件不存在/解析失败返回 0（不抛）。"""
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            intel = json.load(f)
    except (OSError, ValueError):
        return 0
    return register_fingerprints(intel)


def load_default_intel():
    """加载随仓库分发的默认情报文件（若存在）。"""
    return load_intel_file(DEFAULT_INTEL_PATH)
