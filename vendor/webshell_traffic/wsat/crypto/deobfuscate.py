# -*- coding: utf-8 -*-
"""
多层混淆解码链：真实 webshell 大量用嵌套编码把载荷藏起来，如
    eval(base64_decode(strrev(urldecode('...'))))
或 gzinflate(base64_decode(...))、str_rot13(...) 等任意组合。此模块用有界深度优先
搜索，反复尝试 base64 / urldecode / strrev / gzinflate / gzuncompress / gzip /
str_rot13 / hex，直到还原出「最像可读脚本」的一层，返回还原文本与所用解码链。

全程按 **字节** 处理（gzinflate 等的中间产物是二进制，字符串管道会损坏），仅在打分
与最终输出时按 utf-8 宽松解码。启发式打分：可打印占比 + 命中脚本 token 加权。搜索
受节点预算与长度膨胀上限约束，避免对随机数据爆炸。
"""

import base64
import binascii
import gzip
import re
import urllib.parse
import zlib

_B64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
_HEX_RE = re.compile(rb"^[0-9a-fA-F\s]+$")
_TOKENS = (b"<?php", b"<?=", b"eval", b"assert", b"system(", b"shell_exec", b"passthru",
           b"proc_open", b"popen", b"base64_decode", b"gzinflate", b"str_rot13", b"strrev",
           b"$_post", b"$_get", b"$_request", b"$_server", b"$_cookie", b"function ",
           b"cmd.exe", b"/bin/sh", b"whoami", b"preg_replace")

_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")

_NODE_BUDGET = 800
_MAX_LEN = 200_000
# 可逆解码器：连续两次等于没做，禁止相邻重复以防搜索树爆炸
_INVOLUTIVE = {"strrev", "str_rot13"}


def _score(b: bytes) -> float:
    """越像可读脚本分越高：可打印占比 + 脚本 token 命中加权。"""
    if not b:
        return -1.0
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)
    score = printable
    low = b.lower()
    for tok in _TOKENS:
        if tok in low:
            score += 0.5
    return score


def _dec_base64(b: bytes):
    t = re.sub(rb"\s", b"", b)
    if len(t) < 8 or not _B64_RE.match(b):
        return None
    return base64.b64decode(t + b"=" * (-len(t) % 4), validate=False)


def _dec_hex(b: bytes):
    t = re.sub(rb"\s", b"", b)
    if len(t) < 8 or len(t) % 2 or not _HEX_RE.match(b):
        return None
    return bytes.fromhex(t.decode("ascii"))


def _dec_url(b: bytes):
    if b"%" not in b:
        return None
    out = urllib.parse.unquote_to_bytes(bytes(b).replace(b"+", b" "))
    return out if out != b else None


def _dec_strrev(b: bytes):
    return b[::-1]


def _dec_gzinflate(b: bytes):
    return zlib.decompress(b, -zlib.MAX_WBITS)


def _dec_gzuncompress(b: bytes):
    return zlib.decompress(b)


def _dec_gzip(b: bytes):
    return gzip.decompress(b)


def _dec_rot13(b: bytes):
    return b.translate(_ROT13)


_DECODERS = [
    ("base64", _dec_base64),
    ("urldecode", _dec_url),
    ("hex", _dec_hex),
    ("gzinflate", _dec_gzinflate),
    ("gzuncompress", _dec_gzuncompress),
    ("gzip", _dec_gzip),
    ("str_rot13", _dec_rot13),
    ("strrev", _dec_strrev),
]


def deobfuscate(text, max_depth=6):
    """
    对疑似多层编码的载荷做有界 DFS 解码，返回 (还原文本 str, [解码步骤名])。
    未能改善（无更可读的解码）时返回 (原文 str, [])。
    """
    data = text.encode("latin1", "ignore") if isinstance(text, str) else bytes(text)
    best = {"data": data, "steps": [], "score": _score(data)}
    budget = [_NODE_BUDGET]

    def dfs(cur, steps, depth):
        if budget[0] <= 0 or depth >= max_depth or len(cur) > _MAX_LEN:
            return
        last = steps[-1] if steps else None
        for name, fn in _DECODERS:
            if budget[0] <= 0:
                return
            # 相邻重复可逆解码（strrev/strrev、rot13/rot13）等于没做，跳过
            if name in _INVOLUTIVE and name == last:
                continue
            budget[0] -= 1
            try:
                out = fn(cur)
            except (binascii.Error, ValueError, zlib.error, OSError, UnicodeError):
                continue
            if not out or out == cur or len(out) > len(cur) * 4 + 256:
                continue
            sc = _score(out)
            if sc > best["score"]:
                best.update(data=out, steps=steps + [name], score=sc)
            # 二进制中间产物（如 deflate 字节）分数会暂时变低，仍须深入才能到 gz 层——
            # 不按分数剪枝，靠节点预算 + 深度 + 结构校验（合法解码/不膨胀）约束搜索
            dfs(out, steps + [name], depth + 1)

    dfs(data, [], 0)
    return best["data"].decode("utf-8", "replace"), best["steps"]


def is_multilayer_encoded(text) -> bool:
    """是否为「多层编码」载荷：能解出至少 2 步且最终比原文更可读。"""
    _out, steps = deobfuscate(text)
    return len(steps) >= 2
