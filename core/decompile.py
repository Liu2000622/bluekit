"""Java .class 反编译封装 —— 调用本地 CFR（离线）。

CFR 是单 jar 的 Java 反编译器，对动态生成/内存马 dump 出来的 class 支持好。
查找顺序：随包 third_party/cfr.jar → 环境变量 BLUEKIT_CFR → PATH 里的 cfr.jar。
需要本机有 java。
"""
from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.paths import find_resource

# 反编译源码里的恶意/危险特征，用于整包反编译后快速定位坏类
MALICIOUS_PATTERNS = re.compile(
    r"Runtime\.getRuntime|ProcessBuilder|\.exec\(|defineClass|"
    r"base64|Base64|javax\.crypto|Cipher|"
    r"getParameter|getHeader|getInputStream|"
    r"javax\.servlet|jakarta\.servlet|ClassLoader|"
    r"URLClassLoader|reflect\.|invoke\(", re.I)


def find_cfr() -> str | None:
    cands = [
        find_resource(os.path.join("third_party", "cfr.jar")) or "",
        os.environ.get("BLUEKIT_CFR", ""),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def find_java() -> str | None:
    return shutil.which("java")


def decompile(class_file: str, timeout: int = 60) -> str:
    java = find_java()
    if not java:
        return "未找到 java。反编译需要本机安装 JRE/JDK。"
    cfr = find_cfr()
    if not cfr:
        return ("未找到 cfr.jar。请把 CFR 反编译器放到 third_party/cfr.jar，"
                "或设置环境变量 BLUEKIT_CFR。")
    try:
        p = subprocess.run([java, "-jar", cfr, class_file],
                          capture_output=True, text=True,
                          timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return f"反编译超时（>{timeout}s）"
    return p.stdout or p.stderr or "（无输出）"


def decompile_jar(jar_file: str, outdir: str | None = None, timeout: int = 600):
    """反编译整个 jar/war，把所有类解成 .java 到 outdir。

    返回 (outdir, java_files, log)：
      outdir     —— 输出目录（None 则自动建临时目录）
      java_files —— list[str] 反编译出的 .java 绝对路径（失败为 []）
      log        —— CFR 日志 / 错误信息
    """
    java = find_java()
    if not java:
        return None, [], "未找到 java。反编译需要本机安装 JRE/JDK。"
    cfr = find_cfr()
    if not cfr:
        return None, [], "未找到 cfr.jar。请把 CFR 放到 third_party/cfr.jar。"
    if outdir is None:
        outdir = tempfile.mkdtemp(prefix="bluekit_decompile_")
    os.makedirs(outdir, exist_ok=True)
    try:
        p = subprocess.run([java, "-jar", cfr, jar_file, "--outputdir", outdir],
                          capture_output=True, text=True,
                          timeout=timeout, errors="replace")
        log = (p.stderr or p.stdout or "").strip()
    except subprocess.TimeoutExpired:
        log = f"反编译超时（>{timeout}s），jar 可能过大"
    files = sorted(glob.glob(os.path.join(outdir, "**", "*.java"), recursive=True))
    if not files and not log:
        log = "未解出任何 .java（jar 为空或非法？）"
    return outdir, files, log


def scan_malicious(java_files: list[str], root: str) -> list[tuple[str, int, str]]:
    """在反编译出的源码里扫恶意特征，返回 (相对类名, 命中数, 首个命中行摘要)。"""
    hits = []
    for f in java_files:
        try:
            text = Path(f).read_text("utf-8", errors="replace")
        except OSError:
            continue
        matches = MALICIOUS_PATTERNS.findall(text)
        if matches:
            # 首个命中行
            sample = ""
            for line in text.splitlines():
                if MALICIOUS_PATTERNS.search(line):
                    sample = line.strip()[:80]
                    break
            rel = os.path.relpath(f, root)
            hits.append((rel, len(matches), sample))
    hits.sort(key=lambda x: -x[1])
    return hits


def rel_name(f: str, root: str) -> str:
    return os.path.relpath(f, root)
