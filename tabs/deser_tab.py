"""Java 反序列化查看 Tab。"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core import deser
from tabs.common import make_input, make_output, primary_button, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)

    ttk.Label(frame, text="粘贴反序列化数据（Base64 / Hex / 原文均可，自动识别）").pack(anchor="w", pady=(0, 4))
    inp = make_input(frame, height=8)
    inp.pack(fill="both", expand=False)

    out = make_output(frame)

    def analyze():
        src = inp.get("1.0", "end-1c")
        if not src.strip():
            set_text(out, "请先粘贴数据。")
            return
        try:
            set_text(out, deser.analyze(src))
        except Exception as e:  # noqa: BLE001
            set_text(out, f"[错误] {e}")

    bar = ttk.Frame(frame)
    bar.pack(fill="x", pady=8)
    primary_button(bar, "▶ 识别 & 扫 gadget", analyze).pack(side="left")

    ttk.Label(frame, text="结果").pack(anchor="w", pady=(6, 4))
    out.pack(fill="both", expand=True)
    return frame, "反序列化查看"
