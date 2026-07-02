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
    header = ttk.Frame(root, style="Header.TFrame", padding=(20, 14))
    header.pack(fill="x")
    ttk.Label(header, text="🛡  BlueKit", style="HeaderTitle.TLabel").pack(side="left")
    ttk.Label(header, text="蓝队离线研判工具  ·  纯离线 · 本机运行 · 无外网",
              style="HeaderSub.TLabel").pack(side="left", padx=14, pady=(10, 0))
    ttk.Label(header, text=f"v{VERSION}", style="HeaderSub.TLabel").pack(side="right", pady=(10, 0))
    # 顶栏下的一条 accent 分隔线
    ttk.Frame(root, style="Accent.TFrame", height=2).pack(fill="x")

    # ---- 底部状态栏 ----
    status = ttk.Label(
        root, anchor="w", style="Status.TLabel",
        text="纯标准库 · 无外网请求   |   流量分析: 内嵌 tshark   |   反编译: java + cfr.jar")
    status.pack(fill="x", side="bottom")

    # ---- 主体：左侧导航 + 右侧内容 ----
    body = ttk.Frame(root)
    body.pack(fill="both", expand=True)

    sidebar = ttk.Frame(body, style="Sidebar.TFrame", width=196)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    ttk.Label(sidebar, text="  功能模块", style="SidebarTitle.TLabel").pack(
        anchor="w", pady=(14, 6))

    content = ttk.Frame(body, padding=(12, 10))
    content.pack(side="left", fill="both", expand=True)

    tabs = [
        ("📊  访问日志分析", accesslog_tab),
        ("🌐  流量分析", traffic_tab),
        ("🐚  WebShell 流量分析", wstraffic_tab),
        ("🔓  WebShell 解密", webshell_tab),
        ("🔣  编解码", codec_tab),
        ("☕  反序列化查看", deser_tab),
        ("🧰  工具箱", utils_tab),
    ]

    frames, buttons = [], []
    for _title, builder in tabs:
        frame, _ = builder.build(content)
        frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        frames.append(frame)

    def show(idx):
        frames[idx].tkraise()
        for j, b in enumerate(buttons):
            b.configure(style="NavActive.TButton" if j == idx else "Nav.TButton")

    for i, (title, _builder) in enumerate(tabs):
        b = ttk.Button(sidebar, text=title, style="Nav.TButton",
                       command=lambda i=i: show(i))
        b.pack(fill="x")
        buttons.append(b)

    show(0)
    root.mainloop()


if __name__ == "__main__":
    main()
