# -*- coding: utf-8 -*-
"""
对称加解密工具（与 GUI 解耦，纯函数，便于测试）。

覆盖 webshell/隧道分析中会遇到的分组密码及其工作模式：
  算法：AES（128/192/256）、DES、3DES(TripleDES)、SM4（国密，自实现）
  模式：ECB / CBC / CFB / OFB / CTR，AES 额外支持 GCM（认证加密）
  填充：PKCS7 / Zero / None（仅 ECB/CBC 需要；流式模式 CFB/OFB/CTR/GCM 不填充）

AES/DES/3DES 走 pycryptodome 原生模式；SM4 用本模块自带的块加密 + 通用模式包装
（GB/T 32907，已用官方测试向量校验），无需额外依赖。

对外接口：
  list_algos() / list_modes(algo) / mode_needs_iv(mode)
  apply(algo, mode, direction, text, key, key_fmt, iv, iv_fmt, padding, ct_fmt) -> str
    direction: "加密" | "解密"
    *_fmt: "文本" | "Hex" | "Base64"（key/iv 的解释方式）
    ct_fmt: "Base64" | "Hex"（密文的编码：加密输出 / 解密输入）
"""

import base64
import binascii

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util import Counter

ENCRYPT = "加密"
DECRYPT = "解密"

_ALGOS = ["AES", "DES", "3DES", "SM4"]
_MODES = {
    "AES": ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"],
    "DES": ["ECB", "CBC", "CFB", "OFB", "CTR"],
    "3DES": ["ECB", "CBC", "CFB", "OFB", "CTR"],
    "SM4": ["ECB", "CBC", "CFB", "OFB", "CTR"],
}
_BLOCK = {"AES": 16, "DES": 8, "3DES": 8, "SM4": 16}
_KEYSIZES = {"AES": (16, 24, 32), "DES": (8,), "3DES": (16, 24), "SM4": (16,)}


def list_algos():
    return list(_ALGOS)


def list_modes(algo):
    return list(_MODES.get(algo, []))


def mode_needs_iv(mode):
    return mode != "ECB"


# ============================ SM4（GB/T 32907）============================

_SM4_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]
_SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]


def _sm4_ck_table():
    """固定参数 CK：CK[i] 的 4 个字节为 (28i+7j) mod 256（j=0..3）。"""
    table = []
    for i in range(32):
        v = 0
        for j in range(4):
            v = (v << 8) | ((7 * (4 * i + j)) % 256)
        table.append(v)
    return table


_SM4_CK = _sm4_ck_table()
_M32 = 0xffffffff


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _sm4_tau(a):
    return ((_SM4_SBOX[(a >> 24) & 0xff] << 24) | (_SM4_SBOX[(a >> 16) & 0xff] << 16)
            | (_SM4_SBOX[(a >> 8) & 0xff] << 8) | _SM4_SBOX[a & 0xff])


def _sm4_t(x):  # 轮函数线性变换 L∘τ
    b = _sm4_tau(x)
    return b ^ _rol(b, 2) ^ _rol(b, 10) ^ _rol(b, 18) ^ _rol(b, 24)


def _sm4_tp(x):  # 密钥扩展线性变换 L'∘τ
    b = _sm4_tau(x)
    return b ^ _rol(b, 13) ^ _rol(b, 23)


def _sm4_round_keys(key):
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") ^ _SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        nk = k[0] ^ _sm4_tp(k[1] ^ k[2] ^ k[3] ^ _SM4_CK[i])
        rk.append(nk)
        k = [k[1], k[2], k[3], nk]
    return rk


def _sm4_crypt_block(block, rk):
    x = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(4)]
    for i in range(32):
        x = [x[1], x[2], x[3], x[0] ^ _sm4_t(x[1] ^ x[2] ^ x[3] ^ rk[i])]
    return b"".join(v.to_bytes(4, "big") for v in (x[3], x[2], x[1], x[0]))


class _SM4:
    block_size = 16

    def __init__(self, key):
        self._ek = _sm4_round_keys(key)
        self._dk = self._ek[::-1]

    def encrypt_block(self, b):
        return _sm4_crypt_block(b, self._ek)

    def decrypt_block(self, b):
        return _sm4_crypt_block(b, self._dk)


# --- 通用工作模式（用于 SM4；AES/DES/3DES 走 pycryptodome 原生模式）---

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _blocks(data, bs):
    return [data[i:i + bs] for i in range(0, len(data), bs)]


def _sm4_mode_encrypt(cipher, mode, data, iv):
    bs = cipher.block_size
    if mode == "ECB":
        return b"".join(cipher.encrypt_block(b) for b in _blocks(data, bs))
    if mode == "CBC":
        out, prev = b"", iv
        for b in _blocks(data, bs):
            prev = cipher.encrypt_block(_xor(b, prev))
            out += prev
        return out
    if mode == "CFB":
        out, fb = b"", iv
        for b in _blocks(data, bs):
            c = _xor(b, cipher.encrypt_block(fb)[:len(b)])
            out += c
            fb = c
        return out
    if mode == "OFB":
        out, fb = b"", iv
        for b in _blocks(data, bs):
            fb = cipher.encrypt_block(fb)
            out += _xor(b, fb[:len(b)])
        return out
    if mode == "CTR":
        out, ctr = b"", int.from_bytes(iv, "big")
        for b in _blocks(data, bs):
            ks = cipher.encrypt_block(ctr.to_bytes(bs, "big"))
            out += _xor(b, ks[:len(b)])
            ctr = (ctr + 1) % (1 << (8 * bs))
        return out
    raise ValueError(f"SM4 不支持模式: {mode}")


def _sm4_mode_decrypt(cipher, mode, data, iv):
    bs = cipher.block_size
    if mode == "ECB":
        return b"".join(cipher.decrypt_block(b) for b in _blocks(data, bs))
    if mode == "CBC":
        out, prev = b"", iv
        for c in _blocks(data, bs):
            out += _xor(cipher.decrypt_block(c), prev)
            prev = c
        return out
    if mode == "CFB":
        out, fb = b"", iv
        for c in _blocks(data, bs):
            out += _xor(c, cipher.encrypt_block(fb)[:len(c)])
            fb = c
        return out
    if mode in ("OFB", "CTR"):  # 流式模式：解密与加密对称
        return _sm4_mode_encrypt(cipher, mode, data, iv)
    raise ValueError(f"SM4 不支持模式: {mode}")


# ============================ pycryptodome 分派（AES/DES/3DES）===============

_PYCA = {"AES": AES, "DES": DES, "3DES": DES3}


def _pyca_new(algo, mode, key, iv):
    mod = _PYCA[algo]
    bs = mod.block_size
    if mode == "ECB":
        return mod.new(key, mod.MODE_ECB)
    if mode == "CBC":
        return mod.new(key, mod.MODE_CBC, iv=iv)
    if mode == "CFB":
        return mod.new(key, mod.MODE_CFB, iv=iv, segment_size=bs * 8)  # 整块 CFB（同 OpenSSL）
    if mode == "OFB":
        return mod.new(key, mod.MODE_OFB, iv=iv)
    if mode == "CTR":
        ctr = Counter.new(bs * 8, initial_value=int.from_bytes(iv, "big"))
        return mod.new(key, mod.MODE_CTR, counter=ctr)
    if mode == "GCM":
        return mod.new(key, mod.MODE_GCM, nonce=iv)
    raise ValueError(f"{algo} 不支持模式: {mode}")


# ============================ 编码/填充工具 ============================

def _fix_b64_padding(s):
    s = "".join(s.split())
    return s + "=" * (-len(s) % 4)


def _parse_bytes(s, fmt, field):
    s = (s or "").strip()
    if fmt == "Hex":
        try:
            return bytes.fromhex("".join(s.split()))
        except ValueError:
            raise ValueError(f"{field} 不是合法 Hex")
    if fmt == "Base64":
        try:
            return base64.b64decode(_fix_b64_padding(s), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f"{field} 不是合法 Base64")
    return s.encode("utf-8")  # 文本(UTF-8)


def _parse_ct(text, ct_fmt):
    s = text.strip()
    if ct_fmt == "Hex":
        try:
            return bytes.fromhex("".join(s.split()))
        except ValueError:
            raise ValueError("密文不是合法 Hex")
    try:
        return base64.b64decode(_fix_b64_padding(s), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("密文不是合法 Base64")


def _fmt_ct(b, ct_fmt):
    return b.hex() if ct_fmt == "Hex" else base64.b64encode(b).decode()


def _pad(data, bs, scheme):
    if scheme == "None":
        if len(data) % bs != 0:
            raise ValueError(f"无填充时明文长度须为 {bs} 的整数倍（当前 {len(data)}）")
        return data
    if scheme == "Zero":
        return data + b"\x00" * ((-len(data)) % bs or 0)
    pad = bs - (len(data) % bs)  # PKCS7
    return data + bytes([pad]) * pad


def _unpad(data, bs, scheme):
    if not data:
        return data
    if scheme == "None":
        return data
    if scheme == "Zero":
        return data.rstrip(b"\x00")
    pad = data[-1]  # PKCS7
    if pad < 1 or pad > bs or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 填充非法（密钥/模式/IV 可能不对）")
    return data[:-pad]


def _display(b):
    """明文结果展示：可读则文本，否则同时给 hex 与 base64。"""
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return f"[hex]\n{b.hex()}\n\n[base64]\n{base64.b64encode(b).decode()}"
    ctrl = sum(1 for c in t if ord(c) < 32 and c not in "\r\n\t")
    if t and ctrl / len(t) > 0.1:
        return f"[hex]\n{b.hex()}\n\n[base64]\n{base64.b64encode(b).decode()}"
    return t


# ============================ 对外统一入口 ============================

def apply(algo, mode, direction, text, key, key_fmt="文本", iv="", iv_fmt="Hex",
          padding="PKCS7", ct_fmt="Base64"):
    """按算法/模式执行对称加解密；出错时返回以 [!] 开头的可读提示。"""
    if not text:
        return "[!] 输入为空。"
    try:
        return _apply(algo, mode, direction, text, key, key_fmt, iv, iv_fmt, padding, ct_fmt)
    except (ValueError, binascii.Error, KeyError) as e:
        return f"[!] {direction}失败（{algo}/{mode}）: {e}"


def _apply(algo, mode, direction, text, key, key_fmt, iv, iv_fmt, padding, ct_fmt):
    if algo not in _ALGOS:
        raise ValueError(f"未知算法: {algo}")
    if mode not in _MODES[algo]:
        raise ValueError(f"{algo} 不支持模式 {mode}")

    bs = _BLOCK[algo]
    kb = _parse_bytes(key, key_fmt, "密钥")
    if len(kb) not in _KEYSIZES[algo]:
        want = "/".join(str(n) for n in _KEYSIZES[algo])
        raise ValueError(f"{algo} 密钥须为 {want} 字节，当前 {len(kb)} 字节")

    ivb = b""
    if mode_needs_iv(mode):
        want = 12 if mode == "GCM" else bs
        ivb = _parse_bytes(iv, iv_fmt, "IV/Nonce")
        if mode != "GCM" and len(ivb) != bs:
            raise ValueError(f"{mode} 的 IV 须为 {bs} 字节，当前 {len(ivb)} 字节")
        if mode == "GCM" and not ivb:
            raise ValueError("GCM 需要 Nonce（推荐 12 字节）")

    block_pad = mode in ("ECB", "CBC")

    if direction == ENCRYPT:
        data = text.encode("utf-8")
        if block_pad:
            data = _pad(data, bs, padding)
        if algo == "SM4":
            ct = _sm4_mode_encrypt(_SM4(kb), mode, data, ivb)
        elif mode == "GCM":
            c, tag = _pyca_new(algo, mode, kb, ivb).encrypt_and_digest(data)
            ct = c + tag  # 约定：密文尾部拼 16 字节认证标签
        else:
            ct = _pyca_new(algo, mode, kb, ivb).encrypt(data)
        return _fmt_ct(ct, ct_fmt)

    if direction == DECRYPT:
        data = _parse_ct(text, ct_fmt)
        if algo == "SM4":
            if block_pad and len(data) % bs != 0:
                raise ValueError(f"密文长度须为 {bs} 的整数倍")
            pt = _sm4_mode_decrypt(_SM4(kb), mode, data, ivb)
        elif mode == "GCM":
            if len(data) < 16:
                raise ValueError("GCM 密文过短（缺少 16 字节认证标签）")
            c, tag = data[:-16], data[-16:]
            pt = _pyca_new(algo, mode, kb, ivb).decrypt_and_verify(c, tag)
        else:
            if block_pad and len(data) % bs != 0:
                raise ValueError(f"密文长度须为 {bs} 的整数倍")
            pt = _pyca_new(algo, mode, kb, ivb).decrypt(data)
        if block_pad:
            pt = _unpad(pt, bs, padding)
        return _display(pt)

    return f"[!] 未知方向: {direction}"
