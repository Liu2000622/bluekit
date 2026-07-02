"""文件头（magic bytes）识别 —— 离线，用于快速判断上传文件/附件真实类型，
识别改后缀免杀、webshell 伪装、序列化/字节码等。
"""
from __future__ import annotations

# (magic 前缀 bytes, 类型, 说明)
SIGNATURES = [
    (b"\xCA\xFE\xBA\xBE", "Java class", "JVM 字节码（内存马 dump 常见）"),
    (b"\xAC\xED\x00\x05", "Java 序列化", "反序列化数据流"),
    (b"PK\x03\x04", "ZIP/JAR/WAR/docx", "压缩包或 Java 归档"),
    (b"PK\x05\x06", "ZIP(空)", "空压缩包"),
    (b"\x1F\x8B", "GZIP", "gzip 压缩"),
    (b"\x7FELF", "ELF", "Linux 可执行/so"),
    (b"MZ", "PE/EXE/DLL", "Windows 可执行"),
    (b"%PDF", "PDF", ""),
    (b"\x89PNG\r\n\x1a\n", "PNG", "注意图片马"),
    (b"\xFF\xD8\xFF", "JPEG", "注意图片马"),
    (b"GIF87a", "GIF", ""),
    (b"GIF89a", "GIF", ""),
    (b"BM", "BMP", ""),
    (b"Rar!\x1a\x07", "RAR", ""),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip", ""),
    (b"<?php", "PHP 源码", "可能是 webshell"),
    (b"<%@", "JSP/ASP", "可能是 webshell"),
    (b"<%", "JSP/ASP", "可能是 webshell"),
    (b"#!/", "脚本(shebang)", ""),
    (b"\xEF\xBB\xBF", "UTF-8 BOM 文本", ""),
    (b"SQLite format 3\x00", "SQLite 数据库", ""),
]

# webshell 关键字（文本类文件二次判断）
WEBSHELL_HINTS = [
    b"eval(", b"assert(", b"system(", b"exec(", b"passthru(", b"shell_exec(",
    b"base64_decode(", b"Runtime.getRuntime", b"ProcessBuilder",
    b"cmd.exe", b"/bin/sh", b"request.getParameter", b"defineClass",
]


def identify(data: bytes) -> str:
    lines = []
    lines.append(f"文件大小: {len(data)} 字节")
    head = data[:32]
    lines.append(f"头部 Hex: {head.hex(' ')}")

    matched = None
    for magic, name, note in SIGNATURES:
        if data.startswith(magic):
            matched = (name, note)
            break
    if matched:
        note = f"  —  {matched[1]}" if matched[1] else ""
        lines.append(f"✅ 识别类型: {matched[0]}{note}")
    else:
        # 文本？
        try:
            data[:512].decode("utf-8")
            lines.append("识别类型: 疑似文本文件（无已知二进制头）")
        except UnicodeDecodeError:
            lines.append("识别类型: 未知二进制（无匹配特征）")

    hits = [h.decode("latin-1") for h in WEBSHELL_HINTS if h in data[:8192]]
    if hits:
        lines.append("")
        lines.append("🚨 命中 webshell / 命令执行关键字:")
        lines.append("    " + ", ".join(hits))
    return "\n".join(lines)
