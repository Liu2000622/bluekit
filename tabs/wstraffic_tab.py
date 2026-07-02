"""WebShell 流量分析 Tab —— 集成 pcap 全自动分析引擎（冰蝎/哥斯拉/Suo5/隧道/C2）。"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import wstraffic
from tabs.common import labeled_entry, make_output, primary_button, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)
    state: dict = {"report": None}

    ok, msg = wstraffic.available()
    ttk.Label(frame,
              text=("引擎就绪：pcap 全自动分析（冰蝎/哥斯拉/Suo5/菜刀/蚁剑/隧道/C2）"
                    if ok else f"⚠️ {msg}（打包版已内置依赖；本 Tab 依赖 scapy/pycryptodome/openpyxl）"),
              foreground=("#2a7" if ok else "#c22")).pack(anchor="w")

    # 文件选择
    top = ttk.Frame(frame)
    top.pack(fill="x", pady=(6, 2))
    row, pcap_var = labeled_entry(top, "PCAP：", "", width=50)
    row.pack(side="left", fill="x", expand=True)

    def pick():
        p = filedialog.askopenfilename(
            title="选择 pcap/pcapng",
            filetypes=[("抓包文件", "*.pcap *.pcapng *.cap"), ("所有文件", "*.*")])
        if p:
            pcap_var.set(p)

    ttk.Button(top, text="选文件", command=pick).pack(side="left", padx=2)

    # 选项
    opt = ttk.Frame(frame)
    opt.pack(fill="x", pady=2)
    row2, keys_var = labeled_entry(opt, "已知密钥(可选,逗号分隔):", "", width=30)
    row2.pack(side="left")
    weak_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt, text="弱口令字典爆破", variable=weak_var).pack(side="left", padx=10)

    out = make_output(frame)

    def analyze():
        p = pcap_var.get().strip()
        if not p:
            set_text(out, "请先选择 pcap 文件。")
            return
        ok2, msg2 = wstraffic.available()
        if not ok2:
            set_text(out, f"依赖未就绪：{msg2}")
            return
        keys = [k.strip() for k in keys_var.get().split(",") if k.strip()] or None
        report = os.path.join(tempfile.mkdtemp(prefix="bluekit_ws_"),
                              "webshell_report.xlsx")
        set_text(out, "分析中…（读包 + TCP 重组 + 插件识别 + 解密，可能几秒到几十秒）")

        def worker():
            try:
                result, log = wstraffic.analyze(p, report, keys=keys,
                                                weak_dict=weak_var.get())
                state["report"] = getattr(result, "output_path", None) or report
                text = wstraffic.render(result, log)
            except Exception as e:  # noqa: BLE001
                text = f"[分析失败] {type(e).__name__}: {e}"
            frame.after(0, lambda: set_text(out, text))
        threading.Thread(target=worker, daemon=True).start()

    def open_report():
        rp = state.get("report")
        if not rp or not os.path.exists(rp):
            messagebox.showinfo("报告", "还没有生成报告，先分析一次。")
            return
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", rp])
            elif os.name == "nt":
                os.startfile(rp)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", rp])
        except Exception as e:  # noqa: BLE001
            messagebox.showwarning("报告", f"无法打开：{e}\n路径：{rp}")

    bar = ttk.Frame(frame)
    bar.pack(fill="x", pady=6)
    primary_button(bar, "▶ 全自动分析", analyze).pack(side="left", padx=3)
    ttk.Button(bar, text="打开 Excel 报告", command=open_report).pack(side="left", padx=3)

    ttk.Label(frame, text="分析结果（完整明细见 Excel 报告）").pack(anchor="w", pady=(4, 2))
    out.pack(fill="both", expand=True)
    set_text(out, "全自动：选 pcap → 开始分析 → 自动识别并解密 webshell/隧道流量，出报告。\n"
                  "· 无需密钥即可自动识别类型并尝试解密（可选填已知密钥、开弱口令爆破）\n"
                  "· 覆盖：suo5 / 哥斯拉 / 冰蝎 / 菜刀 / 蚁剑 / Weevely / reGeorg /\n"
                  "        Log4Shell/ThinkPHP 写马 / FRP/NPS/Chisel/CS/Meterpreter 等隧道与 C2\n"
                  "· 结果明细直接入 Excel，本框展示摘要")
    return frame, "WebShell 流量分析"
