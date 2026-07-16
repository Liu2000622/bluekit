# -*- coding: utf-8 -*-
"""
通用编码/解码工具（与 GUI 解耦，纯函数，便于测试）。

覆盖 webshell 与隧道流量常见的「传输层编码/混淆」——非家族密钥加密，而是各
工具在承载指令/载荷时叠加的可逆编码，应急分析时经常需要手工正反转换：

  - Base64 / Base64-URL : 冰蝎/哥斯拉/菜刀/蚁剑/suo5(v2 marshalBase64) 普遍使用
  - Hex                 : suo5 hex 载荷、二进制转写
  - URL                 : 哥斯拉 PHP_EVAL 参数、Web 漏洞利用 payload
  - Gzip / Zlib(Deflate): 哥斯拉(gzip)、weevely(gzinflate/gzcompress)
  - ROT13               : weevely str_rot13 混淆
  - XOR(重复密钥)       : suo5/冰蝎/哥斯拉等固定异或（通用重复密钥形态）

家族专属的「口令派生密钥 + 组合算法」解密仍走各自的载荷解密页，本模块只做
与密钥无关（XOR 除外，需用户给密钥）的可逆编码转换。

对外接口：
  list_codecs()        -> [名称, ...]
  codec_uses_key(name) -> bool
  apply(name, direction, text, key="") -> str   # direction: "编码" | "解码"
"""

import base64
import binascii
import codecs as _codecs
import gzip
import zlib
from urllib.parse import quote, unquote_to_bytes

ENCODE = "编码"
DECODE = "解码"

# 需要用户提供密钥的编码器
_KEYED = {"XOR"}


def list_codecs():
    return ["Base64", "Base64-URL", "Hex", "URL", "Gzip", "Zlib/Deflate", "ROT13", "XOR"]


def codec_uses_key(name):
    return name in _KEYED


# ----------------------------- 内部工具 -----------------------------

def _fix_b64_padding(s):
    s = "".join(s.split())
    return s + "=" * (-len(s) % 4)


def _parse_key(key):
    """XOR 密钥：优先按 hex 解析（0x42 / 42 / 4869），否则按 utf-8 文本。"""
    k = (key or "").strip()
    if not k:
        raise ValueError("XOR 需要提供密钥（hex 如 0x42，或直接文本）")
    hk = k[2:] if k.lower().startswith("0x") else k
    if len(hk) % 2 == 0 and hk and all(c in "0123456789abcdefABCDEF" for c in hk):
        try:
            return binascii.unhexlify(hk)
        except binascii.Error:
            pass
    return k.encode("utf-8")


def _binary_candidates(text):
    """
    把文本形式的二进制输入解析为候选字节序列（按可能性排序）。

    hex 与 base64 字符集重叠（纯 hex 串也是合法 base64），故：纯 hex 优先按 hex 解，
    再尝试 base64，最后回退原始 utf-8。会验证的编码器（gzip/zlib）逐个候选试到成功为止。
    """
    s = text.strip()
    compact = "".join(s.split())
    cands = []
    if compact and len(compact) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in compact):
        try:
            cands.append(bytes.fromhex(compact))
        except ValueError:
            pass
    try:
        b = base64.b64decode(_fix_b64_padding(compact), validate=True)
        if b not in cands:
            cands.append(b)
    except (binascii.Error, ValueError):
        pass
    raw = s.encode("utf-8")
    if raw not in cands:
        cands.append(raw)
    return cands


def _binary_input(text):
    """二进制输入的最佳单一解释（纯 hex 优先，其次 base64，再回退原始）。"""
    return _binary_candidates(text)[0]


def _display(b):
    """字节结果的展示：可读则给文本，否则同时给 hex 与 base64 两种表示。"""
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return f"[hex]\n{b.hex()}\n\n[base64]\n{base64.b64encode(b).decode()}"
    ctrl = sum(1 for c in t if ord(c) < 32 and c not in "\r\n\t")
    if t and ctrl / len(t) > 0.1:
        return f"[hex]\n{b.hex()}\n\n[base64]\n{base64.b64encode(b).decode()}"
    return t


def _xor(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


# ----------------------------- 编码 -----------------------------

def _encode(name, text, key):
    if name == "Base64":
        return base64.b64encode(text.encode("utf-8")).decode()
    if name == "Base64-URL":
        return base64.urlsafe_b64encode(text.encode("utf-8")).decode()
    if name == "Hex":
        return text.encode("utf-8").hex()
    if name == "URL":
        return quote(text, safe="")
    if name == "Gzip":
        return base64.b64encode(gzip.compress(text.encode("utf-8"))).decode()
    if name == "Zlib/Deflate":
        return base64.b64encode(zlib.compress(text.encode("utf-8"))).decode()
    if name == "ROT13":
        return _codecs.encode(text, "rot_13")
    if name == "XOR":
        return base64.b64encode(_xor(text.encode("utf-8"), _parse_key(key))).decode()
    raise ValueError(f"未知编码类型: {name}")


# ----------------------------- 解码 -----------------------------

def _decode(name, text, key):
    if name == "Base64":
        return _display(base64.b64decode(_fix_b64_padding(text)))
    if name == "Base64-URL":
        return _display(base64.urlsafe_b64decode(_fix_b64_padding(text)))
    if name == "Hex":
        return _display(bytes.fromhex("".join(text.split())))
    if name == "URL":
        return _display(unquote_to_bytes(text))
    if name == "Gzip":
        last = None
        for cand in _binary_candidates(text):
            try:
                return _display(gzip.decompress(cand))
            except (OSError, EOFError, zlib.error) as e:
                last = e
        raise ValueError(f"gzip 解压失败（输入既非 base64/hex 的 gzip 流）: {last}")
    if name == "Zlib/Deflate":
        for cand in _binary_candidates(text):
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 16 + zlib.MAX_WBITS):
                try:
                    return _display(zlib.decompress(cand, wbits))
                except zlib.error:
                    continue
        raise ValueError("zlib/deflate 解压失败（输入既非 base64/hex 的 deflate 流）")
    if name == "ROT13":
        return _codecs.encode(text, "rot_13")  # ROT13 自反
    if name == "XOR":
        return _display(_xor(_binary_input(text), _parse_key(key)))
    raise ValueError(f"未知编码类型: {name}")


# ----------------------------- 对外统一入口 -----------------------------

def apply(name, direction, text, key=""):
    """按 name + direction 执行编解码；出错时返回以 [!] 开头的可读提示。"""
    if not text:
        return "[!] 输入为空。"
    try:
        if direction == ENCODE:
            return _encode(name, text, key)
        if direction == DECODE:
            return _decode(name, text, key)
        return f"[!] 未知方向: {direction}"
    except (binascii.Error, ValueError, zlib.error, OSError) as e:
        return f"[!] {direction}失败（{name}）: {e}"
