"""WebShell 流量解密 —— 冰蝎 / 哥斯拉 / 蚁剑 常见默认算法。离线、纯标准库 + 自研 AES。

说明与免责：
  这几款工具版本/加密器很多，密钥派生随连接密码与配置变化。这里实现的是
  **最常见的默认算法**，并提供「通用模式」（自定义密钥 + AES-ECB/CBC/XOR + base64/hex）
  兜底。解不出时先核对密码/密钥/模式，或用通用模式手工试。
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re

from core import crypto_aes as aes


# ---------------- 基础工具 ----------------
def _b64d(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("latin-1")
    s = re.sub(r"\s", "", s)
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Base64 解码失败: {e}")


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _maybe_gunzip(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except OSError:
            pass
    return data


def _extract_value(body: str) -> str:
    """若是 param=value（URL 表单），取最长的那个 value；否则原样返回。

    注意：base64 尾部的 '=' 是填充，不是表单分隔符。先 rstrip('=') 再判断，
    避免把纯 base64 密文误当成 name=value 切坏。
    """
    import urllib.parse
    body = body.strip()
    if "=" not in body.rstrip("="):
        return body                      # 纯 base64/hex，无表单分隔符
    vals = []
    for p in re.split(r"[&\n]", body):
        if "=" in p.rstrip("="):
            vals.append(urllib.parse.unquote_plus(p.split("=", 1)[1]))
    return max(vals, key=len) if vals else body


def _render(raw: bytes) -> str:
    raw = _maybe_gunzip(raw)
    return raw.decode("utf-8", "replace")


# ---------------- 冰蝎 Behinder ----------------
def behinder_key(password: str = "rebeyond") -> bytes:
    """key = md5(password) 的十六进制前 16 位（ASCII）。默认连接密码 rebeyond。"""
    return hashlib.md5(password.encode()).hexdigest()[:16].encode()


def behinder(data: str, password: str = "rebeyond", mode: str = "aes") -> str:
    key = behinder_key(password)
    raw = _b64d(_extract_value(data))
    if mode == "xor":
        return _render(_xor(raw, key))
    return _render(aes.decrypt_ecb(raw, key, unpad=True))


# ---------------- 哥斯拉 Godzilla ----------------
def godzilla_key(password: str = "pass", key: str = "key") -> tuple[bytes, bytes]:
    """AES key = md5(pass+key) 十六进制前 16 位；XOR key = md5(pass+key) 全 32 位。"""
    h = hashlib.md5((password + key).encode()).hexdigest()
    return h[:16].encode(), h.encode()


def godzilla(data: str, password: str = "pass", key: str = "key",
             mode: str = "aes") -> str:
    aes_key, xor_key = godzilla_key(password, key)
    payload = _extract_value(data)
    # Godzilla 有时在 base64 前后夹 2 位 key，做一次容错剥离
    raw = None
    for cand in (payload, payload[2:-2] if len(payload) > 4 else payload):
        try:
            raw = _b64d(cand)
            break
        except ValueError:
            continue
    if raw is None:
        raise ValueError("无法 Base64 解码（核对密码/密钥或用通用模式）")
    if mode == "xor":
        return _render(_xor(raw, xor_key))
    return _render(aes.decrypt_ecb(raw, aes_key, unpad=True))


# ---------------- 蚁剑 AntSword ----------------
def antsword(data: str, encoder: str = "base64") -> str:
    """蚁剑默认走明文/编码器（可插拔）。这里覆盖最常见的 base64 / rot13 / 明文。"""
    import codecs
    import urllib.parse
    val = urllib.parse.unquote_plus(data.strip())
    if encoder == "base64":
        # 蚁剑常把命令再 base64 一层
        try:
            return _render(_b64d(_extract_value(val)))
        except ValueError:
            return val
    if encoder == "rot13":
        return codecs.decode(val, "rot_13")
    return val  # plain


# ---------------- 通用模式（自定义）----------------
def generic(data: str, key: str, algo: str = "aes-ecb",
            encoding: str = "base64", iv: str = "") -> str:
    raw = _b64d(_extract_value(data)) if encoding == "base64" \
        else bytes.fromhex(re.sub(r"\s", "", _extract_value(data)))
    kb = key.encode()
    if len(kb) not in (16, 24, 32) and algo.startswith("aes"):
        # 用 md5 归一到 16 字节
        kb = hashlib.md5(key.encode()).hexdigest()[:16].encode()
    if algo == "aes-ecb":
        return _render(aes.decrypt_ecb(raw, kb, unpad=True))
    if algo == "aes-cbc":
        ivb = (iv.encode() + b"\x00" * 16)[:16]
        return _render(aes.decrypt_cbc(raw, kb, ivb, unpad=True))
    if algo == "xor":
        return _render(_xor(raw, kb))
    raise ValueError(f"未知算法: {algo}")


# ---------------- 加密（供自测 / 造样例）----------------
def _behinder_encrypt(plain: bytes, password="rebeyond", mode="aes") -> str:
    key = behinder_key(password)
    enc = _xor(plain, key) if mode == "xor" else aes.encrypt_ecb(plain, key)
    return base64.b64encode(enc).decode()


def _godzilla_encrypt(plain: bytes, password="pass", key="key", mode="aes") -> str:
    aes_key, xor_key = godzilla_key(password, key)
    enc = _xor(plain, xor_key) if mode == "xor" else aes.encrypt_ecb(plain, aes_key)
    return base64.b64encode(enc).decode()


TOOLS = ["冰蝎 Behinder", "哥斯拉 Godzilla", "蚁剑 AntSword", "通用模式"]
