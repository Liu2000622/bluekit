# -*- coding: utf-8 -*-
"""
Java class 载荷分析：把解密/上传出的 Java class 字节码转成可读信息。

三档能力（按可用性自动选择）：
  1. 纯 Python 解析（无依赖，总可用）：类名/父类/接口/方法签名/字符串常量池——
     对 webshell 内存马研判已够用（能看到类结构、方法名、命令/类名字符串）。
  2. JDK 自带 javap 反汇编（有 java 环境时）：方法 + 字节码指令。
  3. CFR 反编译出 Java 源码（随附 tools/cfr.jar，系统有 Java 即用；CFR_JAR 环境变量可覆盖）。
"""

import os
import shutil
import struct
import subprocess
import sys

# 常量池 tag（JVM 规范 §4.4）
_CP_UTF8, _CP_INT, _CP_FLOAT, _CP_LONG, _CP_DOUBLE = 1, 3, 4, 5, 6
_CP_CLASS, _CP_STRING, _CP_FIELDREF, _CP_METHODREF, _CP_IFACEMETHODREF = 7, 8, 9, 10, 11
_CP_NAMEANDTYPE, _CP_METHODHANDLE, _CP_METHODTYPE = 12, 15, 16
_CP_DYNAMIC, _CP_INVOKEDYNAMIC, _CP_MODULE, _CP_PACKAGE = 17, 18, 19, 20


def _skip_attributes(data, off):
    (count,) = struct.unpack_from(">H", data, off)
    off += 2
    for _ in range(count):
        _name_idx, length = struct.unpack_from(">HI", data, off)
        off += 6 + length
    return off


def parse_class(data):
    """解析 Java class 字节码，返回结构 dict；非法/非 class 返回 None。"""
    if not data or len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    try:
        minor, major, cp_count = struct.unpack_from(">HHH", data, 4)
        utf8, class_ref = {}, {}
        off, i = 10, 1
        while i < cp_count:
            tag = data[off]
            off += 1
            if tag == _CP_UTF8:
                (ln,) = struct.unpack_from(">H", data, off)
                off += 2
                utf8[i] = data[off:off + ln].decode("utf-8", "replace")
                off += ln
            elif tag in (_CP_INT, _CP_FLOAT):
                off += 4
            elif tag in (_CP_LONG, _CP_DOUBLE):
                off += 8
                i += 1  # long/double 占两个常量池槽
            elif tag == _CP_CLASS:
                (class_ref[i],) = struct.unpack_from(">H", data, off)
                off += 2
            elif tag in (_CP_STRING, _CP_METHODTYPE, _CP_MODULE, _CP_PACKAGE):
                off += 2
            elif tag in (_CP_FIELDREF, _CP_METHODREF, _CP_IFACEMETHODREF,
                         _CP_NAMEANDTYPE, _CP_DYNAMIC, _CP_INVOKEDYNAMIC):
                off += 4
            elif tag == _CP_METHODHANDLE:
                off += 3
            else:
                return None  # 未知 tag：结构异常
            i += 1

        access_flags, this_class, super_class = struct.unpack_from(">HHH", data, off)
        off += 6

        def cls_name(idx):
            ni = class_ref.get(idx)
            return utf8.get(ni, "").replace("/", ".") if ni else ""

        (ic,) = struct.unpack_from(">H", data, off)
        off += 2
        interfaces = []
        for _ in range(ic):
            (ii,) = struct.unpack_from(">H", data, off)
            off += 2
            interfaces.append(cls_name(ii))

        (fc,) = struct.unpack_from(">H", data, off)
        off += 2
        for _ in range(fc):
            off += 6
            off = _skip_attributes(data, off)

        (mc,) = struct.unpack_from(">H", data, off)
        off += 2
        methods = []
        for _ in range(mc):
            _ma, ni, di = struct.unpack_from(">HHH", data, off)
            off += 6
            methods.append((utf8.get(ni, ""), utf8.get(di, "")))
            off = _skip_attributes(data, off)

        strings = [s for s in utf8.values() if s and 2 <= len(s) <= 300]
        return {
            "version": f"{major}.{minor}",
            "class": cls_name(this_class),
            "super": cls_name(super_class),
            "access_flags": access_flags,
            "interfaces": interfaces,
            "methods": methods,
            "strings": strings,
        }
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def summarize(data, max_methods=50, max_strings=60):
    """纯 Python 结构摘要（无外部依赖）；非 class 返回 None。"""
    info = parse_class(data)
    if not info:
        return None
    lines = [f"类名: {info['class']}    继承: {info['super']}    (Java major {info['version']})"]
    if info["interfaces"]:
        lines.append(f"实现接口: {', '.join(info['interfaces'])}")
    if info["methods"]:
        lines.append(f"方法 ({len(info['methods'])}):")
        for name, desc in info["methods"][:max_methods]:
            lines.append(f"  {name} {desc}")
    # 过滤掉类型描述符噪声，突出命令/类引用等有语义的字符串
    interesting = [s for s in info["strings"]
                   if not s.startswith(("(", "L")) and not s.startswith("java/")]
    if interesting:
        lines.append(f"字符串常量 (共 {len(info['strings'])}，摘取有语义的):")
        for s in interesting[:max_strings]:
            lines.append(f"  {s!r}")
    return "\n".join(lines)


def _cfr_jar():
    """定位 CFR jar：环境变量 CFR_JAR 优先，其次随附的 tools/cfr.jar（源码或打包解压目录）。"""
    p = os.environ.get("CFR_JAR")
    if p and os.path.exists(p):
        return p
    bases = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bases.append(meipass)
    # 本模块在 report/ 子包下，项目根是其父目录（tools/ 在项目根）
    bases.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for base in bases:
        for cand in (os.path.join(base, "tools", "cfr.jar"), os.path.join(base, "cfr.jar")):
            if os.path.exists(cand):
                return cand
    return None


def decompile_file(class_path, timeout=20):
    """
    对落盘的 .class 尝试更完整的反编译/反汇编，返回文本或 None：
      1. 配置了 CFR_JAR → CFR 出 Java 源码；
      2. 否则有 JDK javap → 反汇编（方法 + 字节码）；
      3. 都不可用 → None（调用方回退到 summarize）。
    """
    java = shutil.which("java")
    cfr = _cfr_jar()
    if java and cfr:
        try:
            out = subprocess.run([java, "-jar", cfr, class_path],
                                 capture_output=True, timeout=timeout, text=True)
            if out.returncode == 0 and out.stdout.strip():
                return "// —— CFR 反编译（Java 源码）——\n" + out.stdout
        except (subprocess.SubprocessError, OSError):
            pass
    javap = shutil.which("javap")
    if javap:
        try:
            out = subprocess.run([javap, "-p", "-c", "-constants", class_path],
                                 capture_output=True, timeout=timeout, text=True)
            if out.returncode == 0 and out.stdout.strip():
                return "// —— javap 反汇编（JDK，方法 + 字节码）——\n" + out.stdout
        except (subprocess.SubprocessError, OSError):
            pass
    return None


def decompile_bytes(data, timeout=20):
    """
    对 class 字节内容做反编译/反汇编（供 GUI/CLI 交互输入）：纯 Python 结构摘要 +
    javap/CFR（写临时文件调用）。返回组合文本；非 class 返回 None。
    """
    if not data or len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    import tempfile
    parts = []
    summ = summarize(data)
    if summ:
        parts.append("===== 结构摘要（纯 Python 解析）=====\n" + summ)
    # 内存马研判（延迟导入避免与 memshell 循环依赖）
    from wsat.report.memshell import analyze_memshell, format_verdict
    verdict = format_verdict(analyze_memshell(data))
    if verdict:
        parts.append("===== 内存马研判 =====\n" + verdict)
    fd, tmp = tempfile.mkstemp(suffix=".class")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        deco = decompile_file(tmp, timeout=timeout)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    if deco:
        parts.append("\n===== 反编译 / 反汇编 =====\n" + deco)
    else:
        parts.append("\n（未检测到 Java 运行时，仅纯 Python 摘要；已随附 CFR 反编译器，"
                     "安装 Java 后即可反编译出可读的 Java 源码）")
    return "\n".join(parts)
