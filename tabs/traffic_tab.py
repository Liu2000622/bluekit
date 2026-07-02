"""流量分析 Tab —— Wireshark 式界面：过滤器构造表单 + 数据包表格 + 统计。"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import tshark
from tabs.common import labeled_entry, make_output, primary_button, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=6)

    # ---------- 引擎状态 ----------
    bin_ = tshark.find_tshark()
    ver = ""
    try:
        ver = tshark.version() if bin_ else ""
    except Exception:
        ver = ""
    txt = (f"引擎: {ver}" if bin_
           else "⚠️ 未找到 tshark —— 打包时会自动内嵌；本机调试可装 Wireshark 或设 BLUEKIT_TSHARK")
    ttk.Label(frame, text=txt, foreground=("#2a7" if bin_ else "#c22")).pack(anchor="w")

    # ---------- 文件选择 ----------
    top = ttk.Frame(frame)
    top.pack(fill="x", pady=(4, 2))
    row, pcap_var = labeled_entry(top, "PCAP：", "", width=52)
    row.pack(side="left", fill="x", expand=True)

    def pick():
        p = filedialog.askopenfilename(
            title="选择 pcap/pcapng",
            filetypes=[("抓包文件", "*.pcap *.pcapng *.cap"), ("所有文件", "*.*")])
        if p:
            pcap_var.set(p)

    ttk.Button(top, text="选文件", command=pick).pack(side="left", padx=2)

    # ---------- 过滤器构造表单 ----------
    form = ttk.LabelFrame(frame, text="过滤器构造（填字段自动生成 Wireshark 过滤器，无需记命令）", padding=6)
    form.pack(fill="x", pady=4)

    r1 = ttk.Frame(form)
    r1.pack(fill="x")
    _r, src_var = labeled_entry(r1, "源IP:", "", width=15)
    _r.pack(side="left")
    _r, dst_var = labeled_entry(r1, "目的IP:", "", width=15)
    _r.pack(side="left", padx=6)
    ttk.Label(r1, text="协议:").pack(side="left")
    proto_var = tk.StringVar(value="")
    ttk.Combobox(r1, textvariable=proto_var, width=8, state="normal",
                 values=["", "http", "dns", "tcp", "udp", "tls", "mysql",
                         "redis", "icmp", "ftp", "smtp"]).pack(side="left", padx=2)
    _r, port_var = labeled_entry(r1, "端口:", "", width=7)
    _r.pack(side="left", padx=6)

    r2 = ttk.Frame(form)
    r2.pack(fill="x", pady=(4, 0))
    _r, url_var = labeled_entry(r2, "URL(域名/路径):", "", width=24)
    _r.pack(side="left")
    _r, contains_var = labeled_entry(r2, "包含关键字:", "", width=18)
    _r.pack(side="left", padx=(8, 0))
    ttk.Label(r2, text="预设:").pack(side="left", padx=(8, 0))
    preset_var = tk.StringVar(value="全部")
    preset_cb = ttk.Combobox(r2, textvariable=preset_var, width=22, state="readonly",
                             values=[p[0] for p in tshark.FILTER_PRESETS])
    preset_cb.pack(side="left", padx=2)

    # 生效的 display filter（可手改）
    r3 = ttk.Frame(form)
    r3.pack(fill="x", pady=(4, 0))
    _r, filt_var = labeled_entry(r3, "display filter:", "", width=60)
    _r.pack(side="left", fill="x", expand=True)

    def apply_form(*_):
        f = tshark.build_filter(src_var.get(), dst_var.get(), proto_var.get(),
                                port_var.get(), contains_var.get(), url_var.get())
        filt_var.set(f)

    def apply_preset(*_):
        for name, expr in tshark.FILTER_PRESETS:
            if name == preset_var.get():
                filt_var.set(expr)
                return

    ttk.Button(r2, text="↧ 用表单生成", command=apply_form).pack(side="left", padx=6)
    preset_cb.bind("<<ComboboxSelected>>", apply_preset)

    # ---------- 数据包表格（Treeview）----------
    mid = ttk.Frame(frame)
    mid.pack(fill="both", expand=True, pady=4)

    cols = tshark.PACKET_COLUMNS
    tree = ttk.Treeview(mid, columns=cols, show="headings", height=14)
    widths = {"No.": 60, "Time": 90, "Source": 130, "Dest": 130,
              "Proto": 70, "Len": 60, "Info": 480}
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=widths.get(c, 100),
                    anchor="w", stretch=(c == "Info"))
    tree.tag_configure("odd", background="#f6f8fb")
    tree.tag_configure("even", background="#ffffff")
    tree.tag_configure("alert", background="#fde8e8", foreground="#b91c1c")
    vsb = ttk.Scrollbar(mid, orient="vertical", command=tree.yview)
    hsb = ttk.Scrollbar(mid, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    mid.rowconfigure(0, weight=1)
    mid.columnconfigure(0, weight=1)

    row_streams: dict[str, str] = {}   # item_id -> tcp.stream

    # ---------- 底部：详情/统计输出 ----------
    out = make_output(frame)
    out.configure(height=8)

    def _need():
        p = pcap_var.get().strip()
        if not p:
            set_text(out, "请先选择 pcap 文件。")
            return None
        return p

    def load_packets():
        p = _need()
        if not p:
            return
        tree.delete(*tree.get_children())
        row_streams.clear()
        set_text(out, "加载数据包中…")

        def worker():
            try:
                rows, streams, truncated = tshark.packet_rows(p, filt_var.get(), limit=2000)
            except Exception as e:  # noqa: BLE001
                frame.after(0, lambda: set_text(out, f"[错误] {e}"))
                return

            def fill():
                import re
                alert_re = re.compile(
                    r"union\s+select|/bin/|cmd\.exe|/etc/passwd|\.\./|<script|"
                    r"\$\{jndi:|base64_decode|whoami|eval\(", re.I)
                for i, (r, st) in enumerate(zip(rows, streams)):
                    info = r[6] if len(r) > 6 else ""
                    tag = "alert" if alert_re.search(info) else ("odd" if i % 2 else "even")
                    iid = tree.insert("", "end", values=r, tags=(tag,))
                    row_streams[iid] = st
                msg = f"共 {len(rows)} 个包" + ("（已截断到 2000，用过滤器缩小范围）" if truncated else "")
                msg += "  ·  双击某行可追踪其 TCP 流"
                set_text(out, msg)
            frame.after(0, fill)

        threading.Thread(target=worker, daemon=True).start()

    def on_double(_evt):
        sel = tree.focus()
        if not sel:
            return
        st = row_streams.get(sel, "")
        p = pcap_var.get().strip()
        if not p:
            return
        if st == "":
            set_text(out, "该包不属于 TCP 流。")
            return
        set_text(out, f"追踪 TCP 流 {st} 中…")

        def worker():
            try:
                res = tshark.follow_tcp_stream(p, int(st))
            except Exception as e:  # noqa: BLE001
                res = f"[错误] {e}"
            frame.after(0, lambda: set_text(out, res))
        threading.Thread(target=worker, daemon=True).start()

    tree.bind("<Double-1>", on_double)

    # ---------- 操作按钮条 ----------
    bar = ttk.Frame(frame)
    bar.pack(fill="x")

    def stat(fn, msg):
        p = _need()
        if not p:
            return
        set_text(out, msg)

        def worker():
            try:
                res = fn(p)
            except Exception as e:  # noqa: BLE001
                res = f"[错误] {e}"
            frame.after(0, lambda: set_text(out, res))
        threading.Thread(target=worker, daemon=True).start()

    primary_button(bar, "▶ 加载数据包", load_packets).pack(side="left", padx=3)
    ttk.Button(bar, text="协议分层", command=lambda: stat(tshark.protocol_hierarchy, "统计协议分层…")).pack(side="left", padx=3)
    ttk.Button(bar, text="会话统计", command=lambda: stat(tshark.conversations, "统计会话…")).pack(side="left", padx=3)
    ttk.Button(bar, text="HTTP 请求", command=lambda: stat(tshark.http_requests, "提取 HTTP 请求…")).pack(side="left", padx=3)

    def open_ws():
        p = _need()
        if not p:
            return
        if not tshark.open_in_wireshark(p):
            messagebox.showwarning("Wireshark", "未找到 Wireshark GUI。")

    ttk.Button(bar, text="在 Wireshark 打开", command=open_ws).pack(side="left", padx=3)

    ttk.Label(frame, text="详情 / 统计 / 追踪流：").pack(anchor="w", pady=(4, 0))
    out.pack(fill="both", expand=False)
    set_text(out, "用法：选 pcap → （可选）填过滤器表单或选预设 → 加载数据包 → 双击行追踪 TCP 流。")
    return frame, "流量分析(Wireshark)"
