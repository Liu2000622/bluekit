"""编解码 Tab。"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core import codec
from tabs.common import make_input, make_output, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)

    ttk.Label(frame, text="输入").pack(anchor="w", pady=(0, 4))
    inp = make_input(frame, height=8)
    inp.pack(fill="both", expand=False)

    btns = ttk.Frame(frame)
    btns.pack(fill="x", pady=6)

    out = make_output(frame)

    def do(op_name, encode: bool):
        src = inp.get("1.0", "end-1c")
        for name, enc, dec in codec.OPERATIONS:
            if name == op_name:
                fn = enc if encode else dec
                if fn is None:
                    set_text(out, f"{name} 不支持该方向")
                    return
                try:
                    set_text(out, fn(src))
                except Exception as e:  # noqa: BLE001
                    set_text(out, f"[错误] {e}")
                return

    # 每个操作一行：编码 / 解码 两个按钮
    for name, enc, dec in codec.OPERATIONS:
        row = ttk.Frame(btns)
        row.pack(side="left", padx=3)
        ttk.Label(row, text=name, width=11, anchor="center").pack()
        sub = ttk.Frame(row)
        sub.pack()
        if enc is not None:
            ttk.Button(sub, text="编码", width=5,
                       command=lambda n=name: do(n, True)).pack(side="left")
        ttk.Button(sub, text="解码", width=5,
                   command=lambda n=name: do(n, False)).pack(side="left")

    ttk.Label(frame, text="输出").pack(anchor="w", pady=(6, 4))
    out.pack(fill="both", expand=True)
    return frame, "编解码"
