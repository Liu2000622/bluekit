"""编解码套件 —— 纯标准库，全部离线。

每个函数接受 str，返回 str；失败抛 ValueError（GUI 层捕获显示）。
"""
from __future__ import annotations

import base64
import binascii
import gzip
import html
import json
import urllib.parse
import zlib


# ---------------- Base64 ----------------
def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8", "surrogatepass")).decode("ascii")


def b64_decode(s: str) -> str:
    data = _b64_bytes(s)
    return data.decode("utf-8", "replace")


def _b64_bytes(s: str) -> bytes:
    s2 = s.strip().replace("\n", "").replace("\r", "")
    # 兼容 urlsafe 与缺失 padding
    s2 = s2.replace("-", "+").replace("_", "/")
    pad = (-len(s2)) % 4
    s2 += "=" * pad
    try:
        return base64.b64decode(s2)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"非法 Base64: {e}")


# ---------------- Hex ----------------
def hex_encode(s: str) -> str:
    return s.encode("utf-8", "surrogatepass").hex()


def hex_decode(s: str) -> str:
    s2 = s.strip().replace(" ", "").replace("\n", "").replace("0x", "")
    try:
        return bytes.fromhex(s2).decode("utf-8", "replace")
    except ValueError as e:
        raise ValueError(f"非法 Hex: {e}")


# ---------------- URL ----------------
def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    # 连续解码，直到不再变化（对抗多重编码），最多 5 层
    prev = s
    for _ in range(5):
        cur = urllib.parse.unquote_plus(prev)
        if cur == prev:
            break
        prev = cur
    return prev


# ---------------- Unicode (\uXXXX) ----------------
def unicode_encode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def unicode_decode(s: str) -> str:
    try:
        # 处理 \uXXXX 与 \xXX
        return s.encode("utf-8").decode("unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        raise ValueError(f"Unicode 解码失败: {e}")


# ---------------- HTML 实体 ----------------
def html_encode(s: str) -> str:
    return html.escape(s)


def html_decode(s: str) -> str:
    return html.unescape(s)


# ---------------- Gzip / zlib（Base64 包裹，方便文本传递）----------------
def gzip_compress_b64(s: str) -> str:
    return base64.b64encode(gzip.compress(s.encode("utf-8"))).decode("ascii")


def gzip_decompress_b64(s: str) -> str:
    raw = _b64_bytes(s)
    try:
        return gzip.decompress(raw).decode("utf-8", "replace")
    except (OSError, EOFError):
        # 退化尝试 raw deflate / zlib
        try:
            return zlib.decompress(raw).decode("utf-8", "replace")
        except zlib.error:
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", "replace")
            except zlib.error as e:
                raise ValueError(f"Gzip/zlib 解压失败: {e}")


# ---------------- JWT（仅解码展示，不校验签名，离线安全）----------------
def jwt_decode(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        raise ValueError("不是有效 JWT（应为 header.payload[.signature]）")
    out = []
    labels = ["Header", "Payload", "Signature"]
    for i, p in enumerate(parts):
        if i == 2:
            out.append(f"--- {labels[i]}（原文，不校验）---\n{p}")
            continue
        try:
            decoded = _b64_bytes(p).decode("utf-8", "replace")
            try:
                decoded = json.dumps(json.loads(decoded), indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        except ValueError:
            decoded = "<解码失败>"
        out.append(f"--- {labels[i]} ---\n{decoded}")
    return "\n\n".join(out)


# 注册表：GUI 按这个动态生成按钮，(名称, 编码函数, 解码函数)
OPERATIONS = [
    ("Base64", b64_encode, b64_decode),
    ("Hex", hex_encode, hex_decode),
    ("URL", url_encode, url_decode),
    ("Unicode", unicode_encode, unicode_decode),
    ("HTML 实体", html_encode, html_decode),
    ("Gzip(+B64)", gzip_compress_b64, gzip_decompress_b64),
    ("JWT 解码", None, jwt_decode),  # 仅解码
]
