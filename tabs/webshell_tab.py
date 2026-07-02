"""WebShell 流量解密 Tab —— 冰蝎 / 哥斯拉 / 蚁剑 / 通用。"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core import webshell
from tabs.common import make_input, make_output, primary_button, set_text


def build(nb) -> tuple[ttk.Frame, str]:
    frame = ttk.Frame(nb, padding=12)

    ttk.Label(frame, text="粘贴 WebShell 请求/响应体（可含 param=value 表单，自动取值）").pack(anchor="w", pady=(0, 4))
    inp = make_input(frame, height=8)
    inp.pack(fill="both", expand=False)

    ctl = ttk.Frame(frame)
    ctl.pack(fill="x", pady=6)

    tool = tk.StringVar(value=webshell.TOOLS[0])
    ttk.Label(ctl, text="工具：").pack(side="left")
    ttk.Combobox(ctl, textvariable=tool, values=webshell.TOOLS, width=16,
                 state="readonly").pack(side="left", padx=4)

    ttk.Label(ctl, text="密码：").pack(side="left")
    pwd = tk.StringVar(value="rebeyond")
    ttk.Entry(ctl, textvariable=pwd, width=12).pack(side="left", padx=2)

    ttk.Label(ctl, text="密钥(哥斯拉/通用)：").pack(side="left")
    key = tk.StringVar(value="key")
    ttk.Entry(ctl, textvariable=key, width=10).pack(side="left", padx=2)

    ttk.Label(ctl, text="模式：").pack(side="left")
    mode = tk.StringVar(value="aes")
    ttk.Combobox(ctl, textvariable=mode,
                 values=["aes", "xor", "aes-ecb", "aes-cbc", "base64", "rot13", "plain"],
                 width=8, state="readonly").pack(side="left", padx=2)

    out = make_output(frame)

    def decrypt():
        data = inp.get("1.0", "end-1c")
        if not data.strip():
            set_text(out, "请先粘贴流量数据。")
            return
        t = tool.get()
        try:
            if t.startswith("冰蝎"):
                r = webshell.behinder(data, pwd.get(), "xor" if mode.get() == "xor" else "aes")
            elif t.startswith("哥斯拉"):
                r = webshell.godzilla(data, pwd.get(), key.get(),
                                      "xor" if mode.get() == "xor" else "aes")
            elif t.startswith("蚁剑"):
                enc = mode.get() if mode.get() in ("base64", "rot13", "plain") else "base64"
                r = webshell.antsword(data, enc)
            else:  # 通用
                algo = mode.get() if mode.get() in ("aes-ecb", "aes-cbc", "xor") else "aes-ecb"
                r = webshell.generic(data, pwd.get() or key.get(), algo, "base64")
            set_text(out, r if r.strip() else "(解出为空 —— 核对密码/密钥/模式)")
        except Exception as e:  # noqa: BLE001
            set_text(out, f"[解密失败] {e}\n\n提示：核对连接密码/密钥与加密模式；\n"
                          "不同版本密钥派生不同，可切到「通用模式」用自定义密钥手工试。")

    def on_tool(*_):
        t = tool.get()
        defaults = {"冰蝎 Behinder": ("rebeyond", "key", "aes"),
                    "哥斯拉 Godzilla": ("pass", "key", "aes"),
                    "蚁剑 AntSword": ("", "", "base64"),
                    "通用模式": ("", "", "aes-ecb")}
        p, k, m = defaults.get(t, ("", "", "aes"))
        pwd.set(p)
        key.set(k)
        mode.set(m)

    tool.trace_add("write", on_tool)

    primary_button(ctl, "▶ 解密", decrypt).pack(side="left", padx=8)

    ttk.Label(frame, text="解密结果").pack(anchor="w", pady=(6, 4))
    out.pack(fill="both", expand=True)
    set_text(out, "支持：\n"
                  "  冰蝎 Behinder  —— AES-ECB / XOR，key=md5(密码)[:16]，默认密码 rebeyond\n"
                  "  哥斯拉 Godzilla —— AES-ECB / XOR，key=md5(密码+密钥)，默认 pass/key\n"
                  "  蚁剑 AntSword  —— base64 / rot13 / 明文 编码器\n"
                  "  通用模式        —— 自定义密钥 + AES-ECB/CBC/XOR（版本不匹配时兜底）\n\n"
                  "解密后若为 gzip 会自动解压。")
    return frame, "WebShell 解密"
