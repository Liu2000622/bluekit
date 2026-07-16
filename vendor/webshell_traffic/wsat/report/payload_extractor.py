# -*- coding: utf-8 -*-
"""
从解密结果中识别二进制文件类型（Java class / gzip / 序列化 / PE / ZIP 等），
并把原始字节按对应扩展名落盘，便于直接用 jd-gui/CFR 反编译、gzip 解压等后续分析。

命名采用「内容哈希」寻址：同内容复用同一文件（自然去重），不同内容用不同哈希，
极小概率同名不同内容时再追加序号，绝不覆盖已有的不同数据。
"""

import hashlib
import os

# (魔数, 起始偏移, 扩展名, 说明)。按从具体到宽泛排列，第一条命中即返回。
# 注：Mach-O 胖二进制也用 CAFEBABE，与 Java class 冲突；webshell 场景基本是 class，
# 故 class 优先，Mach-O 走其余 FEEDFA** 魔数。
_SIGNATURES = [
    # --- 代码 / 可执行（webshell 内存马载荷最常见）---
    (b"\xca\xfe\xba\xbe", 0, "class", "Java .class 字节码（可用 jd-gui/CFR 反编译）"),
    (b"\xac\xed\x00", 0, "ser", "Java 序列化对象（可用 SerializationDumper 解析）"),
    (b"dex\n", 0, "dex", "Android DEX 字节码（可用 jadx 反编译）"),
    (b"\x00asm", 0, "wasm", "WebAssembly 模块"),
    (b"MZ", 0, "exe", "PE/.NET 可执行（可用 dnSpy/ILSpy 分析）"),
    (b"\x7fELF", 0, "elf", "ELF 可执行"),
    (b"\xfe\xed\xfa\xce", 0, "macho", "Mach-O 可执行（32 位）"),
    (b"\xfe\xed\xfa\xcf", 0, "macho", "Mach-O 可执行（64 位）"),
    (b"\xcf\xfa\xed\xfe", 0, "macho", "Mach-O 可执行（64 位小端）"),
    (b"\xce\xfa\xed\xfe", 0, "macho", "Mach-O 可执行（32 位小端）"),
    # --- 压缩 / 归档 ---
    (b"\x1f\x8b", 0, "gz", "gzip 压缩数据（可 gunzip 解压）"),
    (b"PK\x03\x04", 0, "zip", "ZIP/JAR/Office 归档（可解压逐项分析）"),
    (b"PK\x05\x06", 0, "zip", "空 ZIP 归档"),
    (b"PK\x07\x08", 0, "zip", "ZIP 数据段"),
    (b"BZh", 0, "bz2", "bzip2 压缩数据"),
    (b"\xfd7zXZ\x00", 0, "xz", "xz 压缩数据"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip 归档"),
    (b"Rar!\x1a\x07", 0, "rar", "RAR 归档"),
    (b"\x28\xb5\x2f\xfd", 0, "zst", "zstandard 压缩数据"),
    (b"\x04\x22\x4d\x18", 0, "lz4", "LZ4 压缩数据"),
    (b"ustar", 257, "tar", "tar 归档"),
    # --- 文档 ---
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "OLE2 复合文档（老版 Office/msi，常含宏）"),
    (b"%PDF-", 0, "pdf", "PDF 文档"),
    (b"{\\rtf", 0, "rtf", "RTF 文档"),
    # --- 图片（图片马外壳常见）---
    (b"\x89PNG\r\n\x1a\n", 0, "png", "PNG 图片（可能为图片马外壳）"),
    (b"\xff\xd8\xff", 0, "jpg", "JPEG 图片（可能为图片马外壳）"),
    (b"GIF87a", 0, "gif", "GIF 图片"),
    (b"GIF89a", 0, "gif", "GIF 图片"),
    (b"BM", 0, "bmp", "BMP 图片"),
    (b"II*\x00", 0, "tiff", "TIFF 图片"),
    (b"MM\x00*", 0, "tiff", "TIFF 图片"),
    (b"\x00\x00\x01\x00", 0, "ico", "ICO 图标"),
    # --- 数据库 / 抓包 / 其它 ---
    (b"SQLite format 3\x00", 0, "sqlite", "SQLite 数据库"),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap", "PCAP 抓包（小端）"),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap", "PCAP 抓包（大端）"),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng", "PCAPNG 抓包"),
    # --- 音视频 ---
    (b"ID3", 0, "mp3", "MP3 音频（含 ID3 标签）"),
    (b"OggS", 0, "ogg", "Ogg 媒体"),
    (b"fLaC", 0, "flac", "FLAC 音频"),
    (b"\x1aE\xdf\xa3", 0, "mkv", "Matroska/WebM 媒体"),
    (b"ftyp", 4, "mp4", "MP4/MOV 媒体"),
]


def detect_payload_type(data):
    """按魔数识别二进制文件类型；返回 (ext, label) 或 None（非已知二进制文件）。"""
    if not data or not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    for magic, off, ext, label in _SIGNATURES:
        if data[off:off + len(magic)] == magic:
            return ext, label
    return None


def is_binary_file_payload(data):
    """data 是否为已知的二进制文件类型（据此决定要不要落盘为文件）。"""
    return detect_payload_type(data) is not None


def save_payload(data, out_dir, base="payload"):
    """
    把二进制载荷原始字节落盘为对应扩展名文件，返回 (path, ext, label)。
    内容哈希命名去重：同内容复用同一文件，不同内容不撞名。
    未识别类型的用 .bin。
    """
    data = bytes(data)
    detected = detect_payload_type(data)
    ext, label = detected if detected else ("bin", "未识别二进制数据")
    os.makedirs(out_dir, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:12]
    name = f"{base}_{ext}_{digest}.{ext}"
    path = os.path.join(out_dir, name)
    n = 1
    while os.path.exists(path):
        # 已存在：同内容则复用（去重）；极小概率哈希同、内容不同则追加序号
        with open(path, "rb") as f:
            if f.read() == data:
                return path, ext, label
        name = f"{base}_{ext}_{digest}_{n}.{ext}"
        path = os.path.join(out_dir, name)
        n += 1
    with open(path, "wb") as f:
        f.write(data)
    return path, ext, label
