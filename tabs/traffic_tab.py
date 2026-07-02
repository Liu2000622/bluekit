"""流量分析 Tab —— 导入即自动解析、默认展示全部、按条件过滤、可取消过滤。"""
from __future__ import annotations

import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import tshark
from tabs.common import labeled_entry, make_output, primary_button, set_text

_ALERT_RE = re.compile(
    r"union\s+select|/bin/|cmd\.exe|/etc/passwd|\.\./|<script|"
    r"\$\{jndi:|base64_decode|whoami|eval\(", re.I)


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=8)
    state = {"pcap": None}
    row_streams: dict = {}

    # ---- 引擎状态 ----
    bin_ = tshark.find_tshark()
    ver = ""
    try:
        ver = tshark.version() if bin_ else ""
    except Exception:
        ver = ""
    ttk.Label(frame,
              text=(f"引擎: {ver}" if bin_ else
                    "⚠️ 未找到 tshark（打包版已内置；源码调试请装 Wireshark 或设 BLUEKIT_TSHARK）"),
              foreground=("#2a7" if bin_ else "#c22")).pack(anchor="w")

    # ---- 文件选择（选中即自动解析）----
    top = ttk.Frame(frame)
    top.pack(fill="x", pady=(6, 2))
    row, pcap_var = labeled_entry(top, "PCAP：", "", width=50)
    row.pack(side="left", fill="x", expand=True)
    open_btn = ttk.Button(top, text="导入 pcap")
    open_btn.pack(side="left", padx=2)

    # ---- 过滤器构造表单 ----
    form = ttk.LabelFrame(frame, text="过滤条件（填好点「应用过滤」；点「显示全部」取消过滤）", padding=6)
    form.pack(fill="x", pady=4)
    r1 = ttk.Frame(form)
    r1.pack(fill="x")
    _r, src_var = labeled_entry(r1, "源IP:", "", width=14)
    _r.pack(side="left")
    _r, dst_var = labeled_entry(r1, "目的IP:", "", width=14)
    _r.pack(side="left", padx=6)
    ttk.Label(r1, text="协议:").pack(side="left")
    proto_var = tk.StringVar(value="")
    ttk.Combobox(r1, textvariable=proto_var, width=7,
                 values=["", "http", "dns", "tcp", "udp", "tls", "mysql",
                         "redis", "icmp", "ftp", "smtp"]).pack(side="left", padx=2)
    _r, port_var = labeled_entry(r1, "端口:", "", width=6)
    _r.pack(side="left", padx=6)

    r2 = ttk.Frame(form)
    r2.pack(fill="x", pady=(4, 0))
    _r, url_var = labeled_entry(r2, "URL(域名/路径):", "", width=22)
    _r.pack(side="left")
    _r, contains_var = labeled_entry(r2, "关键字:", "", width=16)
    _r.pack(side="left", padx=6)
    ttk.Label(r2, text="预设:").pack(side="left")
    preset_var = tk.StringVar(value="全部")
    preset_cb = ttk.Combobox(r2, textvariable=preset_var, width=18, state="readonly",
                             values=[p[0] for p in tshark.FILTER_PRESETS])
    preset_cb.pack(side="left", padx=2)

    r3 = ttk.Frame(form)
    r3.pack(fill="x", pady=(4, 0))
    _r, filt_var = labeled_entry(r3, "display filter:", "", width=58)
    _r.pack(side="left", fill="x", expand=True)

    # ---- 数据包表格 ----
    mid = ttk.Frame(frame)
    mid.pack(fill="both", expand=True, pady=4)
    cols = tshark.PACKET_COLUMNS
    tree = ttk.Treeview(mid, columns=cols, show="headings", height=13)
    widths = {"No.": 60, "Time": 90, "Source": 130, "Dest": 130,
              "Proto": 70, "Len": 60, "Info": 480}
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=widths.get(c, 100), anchor="w", stretch=(c == "Info"))
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

    # ---- 按钮条 ----
    bar = ttk.Frame(frame)
    bar.pack(fill="x")

    # ---- 详情/统计输出 ----
    out = make_output(frame)
    out.configure(height=7)

    # ================= 逻辑 =================
    def load_packets(display_filter=""):
        p = state.get("pcap")
        if not p:
            set_text(out, "请先导入 pcap 文件。")
            return
        tree.delete(*tree.get_children())
        row_streams.clear()
        set_text(out, "解析中…" if not display_filter else f"按过滤器加载：{display_filter}")

        def worker():
            try:
                rows, streams, truncated = tshark.packet_rows(p, display_filter, limit=3000)
            except Exception as e:  # noqa: BLE001
                frame.after(0, lambda: set_text(out, f"[错误] {e}"))
                return

            def fill():
                for i, (r, st) in enumerate(zip(rows, streams)):
                    info = r[6] if len(r) > 6 else ""
                    tag = "alert" if _ALERT_RE.search(info) else ("odd" if i % 2 else "even")
                    iid = tree.insert("", "end", values=r, tags=(tag,))
                    row_streams[iid] = st
                scope = "全部" if not display_filter else f"过滤: {display_filter}"
                msg = f"共 {len(rows)} 个包（{scope}）"
                if truncated:
                    msg += "  ·  已截断到 3000，用过滤条件缩小范围"
                msg += "  ·  双击某行可追踪其 TCP 流  ·  可疑包已标红"
                set_text(out, msg)
            frame.after(0, fill)
        threading.Thread(target=worker, daemon=True).start()

    def do_import():
        p = filedialog.askopenfilename(
            title="导入 pcap/pcapng",
            filetypes=[("抓包文件", "*.pcap *.pcapng *.cap"), ("所有文件", "*.*")])
        if not p:
            return
        pcap_var.set(p)
        state["pcap"] = p
        # 清空过滤条件，导入即自动解析并展示全部
        for v in (src_var, dst_var, proto_var, port_var, url_var, contains_var, filt_var):
            v.set("")
        preset_var.set("全部")
        load_packets("")

    def current_filter():
        # 优先用 display filter 框；为空则按表单字段拼
        f = filt_var.get().strip()
        if f:
            return f
        return tshark.build_filter(src_var.get(), dst_var.get(), proto_var.get(),
                                   port_var.get(), contains_var.get(), url_var.get())

    def apply_filter():
        if not state.get("pcap"):
            set_text(out, "请先导入 pcap 文件。")
            return
        f = current_filter()
        filt_var.set(f)   # 回填，便于查看/微调
        load_packets(f)

    def show_all():
        for v in (src_var, dst_var, proto_var, port_var, url_var, contains_var, filt_var):
            v.set("")
        preset_var.set("全部")
        load_packets("")

    def apply_preset(_evt=None):
        for name, expr in tshark.FILTER_PRESETS:
            if name == preset_var.get():
                filt_var.set(expr)
                if state.get("pcap"):
                    load_packets(expr)
                return

    def on_double(_evt):
        sel = tree.focus()
        if not sel:
            return
        st = row_streams.get(sel, "")
        p = state.get("pcap")
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

    def stat(fn, msg):
        if not state.get("pcap"):
            set_text(out, "请先导入 pcap 文件。")
            return
        set_text(out, msg)

        def worker():
            try:
                res = fn(state["pcap"])
            except Exception as e:  # noqa: BLE001
                res = f"[错误] {e}"
            frame.after(0, lambda: set_text(out, res))
        threading.Thread(target=worker, daemon=True).start()

    def open_ws():
        if not state.get("pcap"):
            set_text(out, "请先导入 pcap 文件。")
            return
        if not tshark.open_in_wireshark(state["pcap"]):
            messagebox.showwarning("Wireshark", "未找到 Wireshark GUI。")

    # ---- 连线 ----
    open_btn.configure(command=do_import)
    preset_cb.bind("<<ComboboxSelected>>", apply_preset)
    tree.bind("<Double-1>", on_double)
    primary_button(bar, "🔍 应用过滤", apply_filter).pack(side="left", padx=3)
    ttk.Button(bar, text="✖ 显示全部", command=show_all).pack(side="left", padx=3)
    ttk.Button(bar, text="协议分层", command=lambda: stat(tshark.protocol_hierarchy, "统计协议分层…")).pack(side="left", padx=3)
    ttk.Button(bar, text="HTTP 请求", command=lambda: stat(tshark.http_requests, "提取 HTTP 请求…")).pack(side="left", padx=3)
    ttk.Button(bar, text="会话统计", command=lambda: stat(tshark.conversations, "统计会话…")).pack(side="left", padx=3)
    ttk.Button(bar, text="在 Wireshark 打开", command=open_ws).pack(side="left", padx=3)

    set_text(out, "点「导入 pcap」选择抓包文件 → 自动解析并展示全部数据包。\n"
                  "填过滤条件（源/目的IP、协议、端口、URL、关键字）或选预设 → 「🔍 应用过滤」。\n"
                  "「✖ 显示全部」取消过滤。双击数据包行追踪其 TCP 流。")
    return frame, "流量分析(Wireshark)"
