"""统一资源路径解析 —— 源码运行 / PyInstaller onefile / onedir 都能找到随包资源。

PyInstaller 6.x onedir 把 datas 放进 exe 同级的 _internal/；onefile 放进 sys._MEIPASS；
用户手放的 portable tshark 一般在 exe 同级 third_party/。这里把这些根都查一遍。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def resource_roots() -> list[Path]:
    roots: list[Path] = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(Path(meipass))
        exe_dir = Path(sys.executable).resolve().parent
        roots += [exe_dir, exe_dir / "_internal"]
    # 源码根目录（core/ 的上级）
    roots.append(Path(__file__).resolve().parent.parent)
    # 去重保序
    seen, uniq = set(), []
    for r in roots:
        if str(r) not in seen:
            seen.add(str(r))
            uniq.append(r)
    return uniq


def find_resource(rel: str) -> str | None:
    """在所有资源根下查 rel（相对路径），返回第一个存在的绝对路径。"""
    for root in resource_roots():
        p = root / rel
        if p.exists():
            return str(p)
    return None


def find_executable_resource(rel: str) -> str | None:
    """同 find_resource，但要求可执行。"""
    for root in resource_roots():
        p = root / rel
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None
