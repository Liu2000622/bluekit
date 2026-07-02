"""GUI 公共控件与后台执行助手。"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

from core import theme


def make_output(parent) -> scrolledtext.ScrolledText:
    txt = scrolledtext.ScrolledText(parent, wrap="none", font=theme.MONO,
                                    undo=False, height=20, borderwidth=0,
                                    relief="flat", padx=10, pady=8)
    txt.configure(background=theme.CONSOLE_BG, foreground=theme.CONSOLE_FG,
                  insertbackground=theme.CONSOLE_FG,
                  selectbackground="#264f78")
    return txt


def primary_button(parent, text, command):
    """主操作按钮（蓝色 Accent 风格）。"""
    return ttk.Button(parent, text=text, command=command, style="Accent.TButton")


def make_input(parent, height=8) -> tk.Text:
    """统一风格的多行输入框。"""
    t = tk.Text(parent, height=height, wrap="word", font=theme.MONO,
                relief="flat", borderwidth=1, padx=8, pady=6,
                background=theme.CARD, foreground=theme.FG,
                insertbackground=theme.FG, highlightthickness=1,
                highlightbackground=theme.BORDER, highlightcolor=theme.ACCENT)
    return t


def set_text(widget: scrolledtext.ScrolledText, content: str):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.configure(state="normal")


def run_bg(widget, func, *args, busy_msg="处理中…"):
    """后台线程执行 func(*args)->str，结果写回 widget，避免界面卡死。"""
    set_text(widget, busy_msg)

    def worker():
        try:
            result = func(*args)
        except Exception as e:  # noqa: BLE001
            result = f"[错误] {type(e).__name__}: {e}"
        widget.after(0, lambda: set_text(widget, result))

    threading.Thread(target=worker, daemon=True).start()


def labeled_entry(parent, label: str, default: str = "", width: int = 50):
    row = ttk.Frame(parent)
    ttk.Label(row, text=label).pack(side="left")
    var = tk.StringVar(value=default)
    ent = ttk.Entry(row, textvariable=var, width=width)
    ent.pack(side="left", fill="x", expand=True, padx=4)
    return row, var
