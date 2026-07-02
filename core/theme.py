"""统一 UI 主题 —— 现代扁平风，跨平台字体自适应。纯 ttk，无第三方依赖。"""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# ---------------- 调色板 ----------------
BG = "#eef1f5"          # 窗口底
CARD = "#ffffff"        # 卡片/输入
FG = "#111827"          # 主文字
MUTED = "#6b7280"       # 次要文字
BORDER = "#d1d5db"      # 描边
ACCENT = "#2563eb"      # 主色（蓝）
ACCENT_HOVER = "#1d4ed8"
ACCENT_SOFT = "#e8efff"
HEADER_BG = "#1e293b"   # 顶栏深色
HEADER_SUB = "#93c5fd"
SIDEBAR_BG = "#182233"  # 侧边导航（比顶栏略深，形成层次）
CONSOLE_BG = "#1e1e1e"  # 输出台
CONSOLE_FG = "#d4d4d4"

# ---------------- 字体（按平台挑）----------------
if sys.platform == "darwin":
    UI_FAMILY, MONO_FAMILY, SIZE = "PingFang SC", "Menlo", 13
elif sys.platform.startswith("win"):
    UI_FAMILY, MONO_FAMILY, SIZE = "Microsoft YaHei UI", "Consolas", 10
else:
    UI_FAMILY, MONO_FAMILY, SIZE = "Noto Sans CJK SC", "DejaVu Sans Mono", 10

MONO = (MONO_FAMILY, SIZE)


def apply_theme(root: tk.Tk) -> ttk.Style:
    root.configure(background=BG)
    # 全局默认字体
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont"):
        try:
            tkfont.nametofont(name).configure(family=UI_FAMILY, size=SIZE)
        except tk.TclError:
            pass

    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except tk.TclError:
        pass

    st.configure(".", background=BG, foreground=FG,
                 font=(UI_FAMILY, SIZE), focuscolor=BG)
    st.configure("TFrame", background=BG)
    st.configure("Card.TFrame", background=CARD)
    st.configure("TLabel", background=BG, foreground=FG)
    st.configure("Muted.TLabel", background=BG, foreground=MUTED)

    # LabelFrame（卡片）
    st.configure("TLabelframe", background=BG, bordercolor=BORDER,
                 relief="solid", borderwidth=1)
    st.configure("TLabelframe.Label", background=BG, foreground=ACCENT,
                 font=(UI_FAMILY, SIZE, "bold"))

    # 普通按钮
    st.configure("TButton", background=CARD, foreground=FG, bordercolor=BORDER,
                 relief="flat", padding=(12, 6), borderwidth=1)
    st.map("TButton",
           background=[("active", "#e9edf3"), ("pressed", "#dde3ea")],
           bordercolor=[("active", ACCENT)])

    # 主操作按钮（▶）
    st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                 bordercolor=ACCENT, padding=(14, 6), borderwidth=0)
    st.map("Accent.TButton",
           background=[("active", ACCENT_HOVER), ("pressed", ACCENT_HOVER)],
           foreground=[("disabled", "#e5e7eb")])

    # 输入
    st.configure("TEntry", fieldbackground=CARD, bordercolor=BORDER,
                 borderwidth=1, padding=4, relief="flat")
    st.map("TEntry", bordercolor=[("focus", ACCENT)])
    st.configure("TCombobox", fieldbackground=CARD, bordercolor=BORDER,
                 borderwidth=1, padding=3, arrowsize=14)
    st.map("TCombobox", bordercolor=[("focus", ACCENT)])

    # Notebook（顶部标签页）
    st.configure("TNotebook", background=BG, borderwidth=0,
                 tabmargins=(8, 6, 8, 0))
    st.configure("TNotebook.Tab", background="#dfe4ea", foreground=MUTED,
                 padding=(18, 9), font=(UI_FAMILY, SIZE), borderwidth=0)
    st.map("TNotebook.Tab",
           background=[("selected", CARD)],
           foreground=[("selected", ACCENT)],
           expand=[("selected", (1, 1, 1, 0))])

    # 表格
    st.configure("Treeview", background=CARD, fieldbackground=CARD,
                 foreground=FG, rowheight=26, borderwidth=1, bordercolor=BORDER)
    st.configure("Treeview.Heading", background="#eef1f5", foreground=FG,
                 font=(UI_FAMILY, SIZE, "bold"), padding=5, relief="flat")
    st.map("Treeview.Heading", background=[("active", ACCENT_SOFT)])
    st.map("Treeview", background=[("selected", ACCENT)],
           foreground=[("selected", "#ffffff")])

    # 滚动条
    st.configure("TScrollbar", background="#cbd2da", troughcolor=BG,
                 bordercolor=BG, arrowcolor=MUTED, relief="flat")

    # 顶栏
    st.configure("Header.TFrame", background=HEADER_BG)
    st.configure("HeaderTitle.TLabel", background=HEADER_BG, foreground="#ffffff",
                 font=(UI_FAMILY, SIZE + 7, "bold"))
    st.configure("HeaderSub.TLabel", background=HEADER_BG, foreground=HEADER_SUB,
                 font=(UI_FAMILY, SIZE - 1))

    # 状态栏
    st.configure("Status.TLabel", background="#e3e7ed", foreground=MUTED,
                 padding=(10, 5), font=(UI_FAMILY, SIZE - 1))

    # 侧边导航
    st.configure("Sidebar.TFrame", background=SIDEBAR_BG)
    st.configure("Nav.TButton", background=SIDEBAR_BG, foreground="#c3cede",
                 relief="flat", borderwidth=0, padding=(20, 12), anchor="w",
                 font=(UI_FAMILY, SIZE))
    st.map("Nav.TButton",
           background=[("active", "#26344a"), ("pressed", "#26344a")],
           foreground=[("active", "#ffffff")])
    st.configure("NavActive.TButton", background=ACCENT, foreground="#ffffff",
                 relief="flat", borderwidth=0, padding=(20, 12), anchor="w",
                 font=(UI_FAMILY, SIZE, "bold"))
    st.map("NavActive.TButton",
           background=[("active", ACCENT_HOVER), ("pressed", ACCENT_HOVER)],
           foreground=[("active", "#ffffff")])
    st.configure("Accent.TFrame", background=ACCENT)
    st.configure("SidebarTitle.TLabel", background=SIDEBAR_BG, foreground="#5f6b7f",
                 font=(UI_FAMILY, SIZE - 2, "bold"))
    return st
