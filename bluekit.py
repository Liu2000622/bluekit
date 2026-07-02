#!/usr/bin/env python3
"""BlueKit —— 蓝队离线研判工具（本机运行 / 纯离线 / 无外网）

功能 Tab：
  · 访问日志分析（集成 accesslog-analyzer）
  · 流量分析（内嵌 Wireshark 引擎 tshark）
  · 编解码套件
  · Java 反序列化查看
  · 工具箱（文件头识别 / .class 反编译）

用法：
  python3 bluekit.py
打包 Windows exe 见 build/BUILD-WINDOWS.md
"""
from __future__ import annotations

import sys
from pathlib import Path

# 保证源码运行与 PyInstaller 打包后都能 import 到 core/tabs
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import tkinter as tk
from tkinter import ttk

from core.theme import apply_theme
from tabs import (accesslog_tab, codec_tab, deser_tab, traffic_tab,
                  utils_tab, webshell_tab, wstraffic_tab)

VERSION = "0.4.0"


def main():
    root = tk.Tk()
    root.title(f"BlueKit 蓝队离线研判工具 v{VERSION}")
    root.geometry("1080x720")
    root.minsize(920, 600)
    apply_theme(root)

    # ---- 顶部标题栏 ----
    header = ttk.Frame(root, style="Header.TFrame", padding=(18, 12))
    header.pack(fill="x")
    ttk.Label(header, text="🛡  BlueKit", style="HeaderTitle.TLabel").pack(side="left")
    ttk.Label(header, text="蓝队离线研判工具  ·  纯离线 · 本机运行 · 无外网",
              style="HeaderSub.TLabel").pack(side="left", padx=14, pady=(8, 0))
    ttk.Label(header, text=f"v{VERSION}", style="HeaderSub.TLabel").pack(side="right", pady=(8, 0))

    # ---- 主体标签页 ----
    body = ttk.Frame(root, padding=(10, 8))
    body.pack(fill="both", expand=True)
    nb = ttk.Notebook(body)
    nb.pack(fill="both", expand=True)

    for builder in (accesslog_tab, traffic_tab, wstraffic_tab, webshell_tab,
                    codec_tab, deser_tab, utils_tab):
        frame, title = builder.build(nb)
        nb.add(frame, text=title)

    # ---- 底部状态栏 ----
    status = ttk.Label(
        root, anchor="w", style="Status.TLabel",
        text="纯标准库 · 无外网请求   |   流量分析: 内嵌 tshark   |   反编译: java + cfr.jar")
    status.pack(fill="x", side="bottom")

    root.mainloop()


if __name__ == "__main__":
    main()
