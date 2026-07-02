"""工具箱 Tab —— 文件头识别 + .class/jar 反编译（jar 整包 + 恶意特征定位）。"""
from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from core import decompile, filetype, theme
from tabs.common import labeled_entry, make_output, primary_button, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)

    # 反编译状态：{"outdir":..., "files":[...]}
    state: dict = {"outdir": None, "files": []}

    # ---- 文件选择 ----
    top = ttk.Frame(frame)
    top.pack(fill="x")
    row, path_var = labeled_entry(top, "文件（.class / .jar / .war）：", "", width=46)
    row.pack(side="left", fill="x", expand=True)

    def pick():
        p = filedialog.askopenfilename(
            title="选择 .class / .jar / .war",
            filetypes=[("Java", "*.class *.jar *.war"), ("所有文件", "*.*")])
        if p:
            path_var.set(p)

    ttk.Button(top, text="选文件", command=pick).pack(side="left", padx=2)

    # ---- 中部：左类清单 + 右源码 ----
    mid = ttk.Frame(frame)
    mid.pack(fill="both", expand=True, pady=8)

    left = ttk.Frame(mid)
    left.pack(side="left", fill="y")
    ttk.Label(left, text="类清单（jar 反编译后）").pack(anchor="w")
    _r, filter_var = labeled_entry(left, "筛选:", "", width=24)
    _r.pack(fill="x", pady=2)
    lb = tk.Listbox(left, width=40, height=22, font=theme.MONO,
                    background=theme.CARD, foreground=theme.FG,
                    selectbackground=theme.ACCENT, selectforeground="#fff",
                    highlightthickness=1, highlightbackground=theme.BORDER,
                    relief="flat", activestyle="none")
    lbsb = ttk.Scrollbar(left, orient="vertical", command=lb.yview)
    lb.configure(yscrollcommand=lbsb.set)
    lb.pack(side="left", fill="y", expand=True)
    lbsb.pack(side="left", fill="y")

    right = ttk.Frame(mid)
    right.pack(side="left", fill="both", expand=True, padx=(8, 0))
    ttk.Label(right, text="源码 / 结果").pack(anchor="w")
    out = make_output(right)
    out.pack(fill="both", expand=True)

    # ---- 列表渲染 / 筛选 ----
    def refresh_list(*_):
        kw = filter_var.get().strip().lower()
        lb.delete(0, "end")
        root = state["outdir"]
        for f in state["files"]:
            rel = decompile.rel_name(f, root) if root else f
            if kw in rel.lower():
                lb.insert("end", rel)

    filter_var.trace_add("write", refresh_list)

    def on_select(_evt):
        sel = lb.curselection()
        if not sel:
            return
        rel = lb.get(sel[0])
        if rel.startswith("⚠ "):
            rel = rel[2:]
        root = state["outdir"]
        full = os.path.join(root, rel) if root else rel
        try:
            set_text(out, Path(full).read_text("utf-8", errors="replace"))
        except OSError as e:
            set_text(out, f"[读取失败] {e}")

    lb.bind("<<ListboxSelect>>", on_select)

    # ---- 操作 ----
    def identify():
        p = path_var.get().strip()
        if not p:
            set_text(out, "请先选择文件。")
            return
        try:
            with open(p, "rb") as f:
                data = f.read(1 << 20)
            set_text(out, filetype.identify(data))
        except OSError as e:
            set_text(out, f"[读取失败] {e}")

    def do_decompile():
        p = path_var.get().strip()
        if not p:
            set_text(out, "请先选择 .class / .jar / .war 文件。")
            return
        low = p.lower()
        if low.endswith((".jar", ".war")):
            set_text(out, "整包反编译中…（大 jar 需要一会儿）")
            lb.delete(0, "end")

            def worker():
                outdir, files, log = decompile.decompile_jar(p)
                state["outdir"], state["files"] = outdir, files

                def done():
                    refresh_list()
                    msg = f"反编译完成：{len(files)} 个类 → {outdir}\n"
                    msg += "点左侧类名看源码；点「扫恶意特征」定位可疑类。\n"
                    if log:
                        msg += "\n[CFR 日志]\n" + "\n".join(log.splitlines()[:15])
                    set_text(out, msg)
                frame.after(0, done)
            threading.Thread(target=worker, daemon=True).start()
        else:
            set_text(out, "反编译中…")

            def worker():
                res = decompile.decompile(p)
                frame.after(0, lambda: set_text(out, res))
            threading.Thread(target=worker, daemon=True).start()

    def do_scan():
        if not state["files"]:
            set_text(out, "请先反编译一个 jar/war（本功能对整包源码扫恶意特征）。")
            return
        hits = decompile.scan_malicious(state["files"], state["outdir"])
        if not hits:
            set_text(out, "未在反编译源码里命中明显恶意特征。")
            return
        lines = [f"恶意特征命中排行（共 {len(hits)} 个类命中，点左侧类名看源码）:\n"]
        for rel, n, sample in hits[:50]:
            lines.append(f"  [{n:>3} 命中] {rel}")
            lines.append(f"            {sample}")
        set_text(out, "\n".join(lines))
        # 把命中类顶到列表前面
        filter_var.set("")
        lb.delete(0, "end")
        hit_names = {h[0] for h in hits}
        for rel, n, _ in hits:
            lb.insert("end", f"⚠ {rel}")
        for f in state["files"]:
            rel = decompile.rel_name(f, state["outdir"])
            if rel not in hit_names:
                lb.insert("end", rel)

    bar = ttk.Frame(frame)
    bar.pack(fill="x")
    ttk.Button(bar, text="识别文件类型", command=identify).pack(side="left", padx=3)
    primary_button(bar, "▶ 反编译 (class/jar)", do_decompile).pack(side="left", padx=3)
    ttk.Button(bar, text="扫恶意特征 (jar)", command=do_scan).pack(side="left", padx=3)

    set_text(out, "· 识别文件类型：看 magic bytes，查改后缀免杀 / webshell 伪装\n"
                  "· 反编译：\n"
                  "    - 单个 .class → 直接出 Java 源码（适合内存马 dump 出来的 class）\n"
                  "    - 整个 .jar/.war → 解出所有类，左侧点开看，配合「扫恶意特征」定位坏类\n"
                  "· 引擎 CFR，需本机有 java")
    return frame, "工具箱"
