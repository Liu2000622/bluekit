"""访问日志分析 Tab —— 集成你的 accesslog-analyzer 引擎。"""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from core import accesslog
from tabs.common import labeled_entry, make_output, primary_button, run_bg, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)

    top = ttk.Frame(frame)
    top.pack(fill="x")
    row, path_var = labeled_entry(top, "日志文件/目录：", "", width=48)
    row.pack(side="left", fill="x", expand=True)

    def pick_file():
        p = filedialog.askopenfilename(title="选择访问日志")
        if p:
            path_var.set(p)

    def pick_dir():
        p = filedialog.askdirectory(title="选择日志目录")
        if p:
            path_var.set(p)

    ttk.Button(top, text="选文件", command=pick_file).pack(side="left", padx=2)
    ttk.Button(top, text="选目录", command=pick_dir).pack(side="left", padx=2)

    opt = ttk.Frame(frame)
    opt.pack(fill="x", pady=4)
    ttk.Label(opt, text="最低严重度：").pack(side="left")
    sev = tk.StringVar(value="LOW")
    ttk.Combobox(opt, textvariable=sev, values=["LOW", "MEDIUM", "HIGH"],
                 width=8, state="readonly").pack(side="left", padx=4)
    row2, base_var = labeled_entry(opt, "基线(可选)：", "", width=28)
    row2.pack(side="left", padx=8)

    out = make_output(frame)

    def analyze():
        p = path_var.get().strip()
        if not p:
            set_text(out, "请先选择日志文件或目录。\n\n" + accesslog.log_format_help())
            return
        baseline = [base_var.get().strip()] if base_var.get().strip() else None
        run_bg(out, accesslog.analyze_paths, [p], sev.get(), 5, baseline,
               busy_msg="分析中…（大日志需要几秒）")

    primary_button(opt, "▶ 分析", analyze).pack(side="left", padx=8)

    out.pack(fill="both", expand=True, pady=(6, 0))
    set_text(out, accesslog.log_format_help())
    return frame, "访问日志分析"
