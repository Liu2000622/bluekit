"""WebShell 流量分析 Tab —— 集成原版全部功能（自动分析 + suo5/哥斯拉/冰蝎 PCAP 专项 +
手动载荷解密），BlueKit 统一主题的原生子标签。"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import wstraffic
from tabs.common import labeled_entry, make_input, make_output, primary_button, set_text


def _open_file(path):
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:  # noqa: BLE001
        messagebox.showwarning("打开", f"无法打开：{e}\n{path}")


def _tmp_report(tag):
    return os.path.join(tempfile.mkdtemp(prefix=f"bluekit_{tag}_"), f"{tag}_report.xlsx")


# ---------- 通用 PCAP 分析面板 ----------
def _pcap_panel(parent, *, tag, run_fn, extra_fields):
    """extra_fields: [(label, key, 'entry'|'combo', values)]"""
    f = ttk.Frame(parent, padding=10)
    state = {"report": None}
    top = ttk.Frame(f)
    top.pack(fill="x")
    row, pcap_var = labeled_entry(top, "PCAP：", "", width=46)
    row.pack(side="left", fill="x", expand=True)
    ttk.Button(top, text="选文件",
               command=lambda: pcap_var.set(filedialog.askopenfilename(
                   filetypes=[("抓包", "*.pcap *.pcapng *.cap"), ("所有", "*.*")]) or pcap_var.get())
               ).pack(side="left", padx=2)

    vars_: dict = {}
    if extra_fields:
        opt = ttk.Frame(f)
        opt.pack(fill="x", pady=4)
        for label, key, typ, values in extra_fields:
            if typ == "combo":
                ttk.Label(opt, text=label).pack(side="left")
                v = tk.StringVar(value=values[0] if values else "")
                ttk.Combobox(opt, textvariable=v, values=values, width=22,
                             state="readonly").pack(side="left", padx=4)
            else:
                r, v = labeled_entry(opt, label, "", width=16)
                r.pack(side="left", padx=4)
            vars_[key] = v

    out = make_output(f)

    def run():
        p = pcap_var.get().strip()
        if not p:
            set_text(out, "请先选择 pcap。")
            return
        kw = {k: v.get() for k, v in vars_.items()}
        report = _tmp_report(tag)
        set_text(out, "分析中…")

        def worker():
            try:
                res, log = run_fn(p, report, kw)
                state["report"] = getattr(res, "output_path", None) or report
                text = wstraffic.render(res, log) if hasattr(res, "records") \
                    else ("分析完成。\n" + "\n".join(log[-25:]) +
                          f"\n\n[报告] {state['report']}")
            except Exception as e:  # noqa: BLE001
                text = f"[分析失败] {type(e).__name__}: {e}"
            f.after(0, lambda: set_text(out, text))
        threading.Thread(target=worker, daemon=True).start()

    bar = ttk.Frame(f)
    bar.pack(fill="x", pady=6)
    primary_button(bar, "▶ 分析", run).pack(side="left", padx=3)
    ttk.Button(bar, text="打开 Excel 报告",
               command=lambda: _open_file(state["report"]) if state.get("report")
               else messagebox.showinfo("报告", "先分析一次")).pack(side="left", padx=3)
    out.pack(fill="both", expand=True)
    return f


# ---------- 通用手动解密面板 ----------
def _decrypt_panel(parent, *, tool, need_key=False, need_crypter=False,
                   key_label="连接密码/密钥：", payload_label="加密载荷："):
    f = ttk.Frame(parent, padding=10)
    top = ttk.Frame(f)
    top.pack(fill="x")
    key_var = crypter_var = None
    if need_key:
        r, key_var = labeled_entry(top, key_label, "", width=24)
        r.pack(side="left")
    if need_crypter:
        ttk.Label(top, text="加密器：").pack(side="left", padx=(8, 0))
        crypter_var = tk.StringVar(value=wstraffic.GODZILLA_CRYPTERS[0])
        ttk.Combobox(top, textvariable=crypter_var, values=wstraffic.GODZILLA_CRYPTERS,
                     width=22, state="readonly").pack(side="left", padx=4)

    ttk.Label(f, text=payload_label).pack(anchor="w", pady=(6, 2))
    inp = make_input(f, height=6)
    inp.pack(fill="both", expand=False)
    out = make_output(f)

    def run():
        payload = inp.get("1.0", "end-1c").strip()
        if not payload:
            set_text(out, "请输入载荷。")
            return
        try:
            res = wstraffic.manual_decrypt(
                tool, payload,
                key=key_var.get() if key_var else "",
                crypter=crypter_var.get() if crypter_var else "")
            set_text(out, res or "(空)")
        except Exception as e:  # noqa: BLE001
            set_text(out, f"[解密失败] {e}")

    bar = ttk.Frame(f)
    bar.pack(fill="x", pady=6)
    primary_button(bar, "▶ 解密", run).pack(side="left")
    ttk.Label(f, text="解密结果").pack(anchor="w", pady=(6, 2))
    out.pack(fill="both", expand=True)
    return f


# ---------- 自动分析面板 ----------
def _auto_panel(parent):
    f = ttk.Frame(parent, padding=10)
    state = {"report": None}
    top = ttk.Frame(f)
    top.pack(fill="x")
    row, pcap_var = labeled_entry(top, "PCAP：", "", width=46)
    row.pack(side="left", fill="x", expand=True)
    ttk.Button(top, text="选文件",
               command=lambda: pcap_var.set(filedialog.askopenfilename(
                   filetypes=[("抓包", "*.pcap *.pcapng *.cap"), ("所有", "*.*")]) or pcap_var.get())
               ).pack(side="left", padx=2)
    opt = ttk.Frame(f)
    opt.pack(fill="x", pady=4)
    r2, keys_var = labeled_entry(opt, "已知密钥(逗号分隔,可选):", "", width=28)
    r2.pack(side="left")
    weak_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(opt, text="弱口令爆破", variable=weak_var).pack(side="left", padx=8)
    out = make_output(f)

    def run():
        p = pcap_var.get().strip()
        if not p:
            set_text(out, "请先选择 pcap。")
            return
        keys = [k.strip() for k in keys_var.get().split(",") if k.strip()] or None
        report = _tmp_report("auto")
        set_text(out, "全自动分析中…")

        def worker():
            try:
                res, log = wstraffic.analyze(p, report, keys=keys, weak_dict=weak_var.get())
                state["report"] = getattr(res, "output_path", None) or report
                text = wstraffic.render(res, log)
            except Exception as e:  # noqa: BLE001
                text = f"[失败] {type(e).__name__}: {e}"
            f.after(0, lambda: set_text(out, text))
        threading.Thread(target=worker, daemon=True).start()

    bar = ttk.Frame(f)
    bar.pack(fill="x", pady=6)
    primary_button(bar, "▶ 全自动分析", run).pack(side="left", padx=3)
    ttk.Button(bar, text="打开 Excel 报告",
               command=lambda: _open_file(state["report"]) if state.get("report")
               else messagebox.showinfo("报告", "先分析一次")).pack(side="left", padx=3)
    out.pack(fill="both", expand=True)
    set_text(out, "全自动：选 pcap → 自动识别并解密 webshell/隧道/C2，出 Excel。无需密钥。")
    return f


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=6)
    ok, msg = wstraffic.available()
    if not ok:
        ttk.Label(frame, text=f"⚠️ {msg}", foreground="#c22").pack(anchor="w", pady=4)
        set_text_widget = make_output(frame)
        set_text_widget.pack(fill="both", expand=True)
        set_text(set_text_widget,
                 "WebShell 流量分析需要 scapy / pycryptodome / openpyxl。\n"
                 "打包版已内置；源码运行请： pip install scapy pycryptodome openpyxl")
        return frame, "WebShell 流量分析"

    sub = ttk.Notebook(frame)
    sub.pack(fill="both", expand=True)

    sub.add(_auto_panel(sub), text="自动分析")
    sub.add(_pcap_panel(sub, tag="suo5", extra_fields=[],
                        run_fn=lambda p, o, kw: wstraffic.pcap_analyze("suo5", p, o)),
            text="suo5 PCAP")
    sub.add(_pcap_panel(sub, tag="godzilla",
                        extra_fields=[("密钥:", "key", "entry", None),
                                      ("加密器:", "crypter", "combo", wstraffic.GODZILLA_CRYPTERS)],
                        run_fn=lambda p, o, kw: wstraffic.pcap_analyze(
                            "godzilla", p, o, key=kw.get("key", ""), crypter=kw.get("crypter", ""))),
            text="哥斯拉 PCAP")
    sub.add(_pcap_panel(sub, tag="behinder",
                        extra_fields=[("连接密码:", "password", "entry", None)],
                        run_fn=lambda p, o, kw: wstraffic.pcap_analyze(
                            "behinder", p, o, password=kw.get("password", ""))),
            text="冰蝎 PCAP")
    sub.add(_decrypt_panel(sub, tool="suo5", payload_label="suo5 十六进制载荷："),
            text="suo5 解密")
    sub.add(_decrypt_panel(sub, tool="godzilla", need_key=True, need_crypter=True,
                           payload_label="哥斯拉加密载荷："),
            text="哥斯拉解密")
    sub.add(_decrypt_panel(sub, tool="behinder", need_key=True,
                           key_label="连接密码(默认rebeyond)：",
                           payload_label="冰蝎加密载荷 (raw/base64)："),
            text="冰蝎解密")
    return frame, "WebShell 流量分析"
