"""纯 Python AES-128/192/256（ECB / CBC + PKCS7）—— 零第三方依赖。

只为 WebShell 流量解密提供 AES 原语。用 FIPS-197 测试向量自校验（见文件末 selftest）。
不追求性能，只求正确、可离线、可打包。
"""
from __future__ import annotations

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xff


def _key_expansion(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _bytes_to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _encrypt_block(block: bytes, w, nr) -> bytes:
    s = _bytes_to_state(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, nr):
        s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        s = [s[r][r:] + s[r][:r] for r in range(4)]                 # ShiftRows
        for c in range(4):                                          # MixColumns
            col = [s[r][c] for r in range(4)]
            s[0][c] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
            s[1][c] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
            s[2][c] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
            s[3][c] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        _add_round_key(s, w, rnd)
    s = [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    s = [s[r][r:] + s[r][:r] for r in range(4)]
    _add_round_key(s, w, nr)
    return _state_to_bytes(s)


def _decrypt_block(block: bytes, w, nr) -> bytes:
    s = _bytes_to_state(block)
    _add_round_key(s, w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]  # InvShiftRows
        s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        _add_round_key(s, w, rnd)
        for c in range(4):                                            # InvMixColumns
            col = [s[r][c] for r in range(4)]
            s[0][c] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
            s[1][c] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
            s[2][c] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
            s[3][c] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
    s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]
    s = [[_INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    return _state_to_bytes(s)


_NR = {16: 10, 24: 12, 32: 14}


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    p = data[-1]
    if 1 <= p <= 16 and data[-p:] == bytes([p]) * p:
        return data[:-p]
    return data  # 非法 padding 就原样返回，交给上层判断


def _pkcs7_pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    w, nr = _key_expansion(key), _NR[len(key)]
    data = _pkcs7_pad(data)
    return b"".join(_encrypt_block(data[i:i + 16], w, nr) for i in range(0, len(data), 16))


def decrypt_ecb(data: bytes, key: bytes, unpad: bool = True) -> bytes:
    w, nr = _key_expansion(key), _NR[len(key)]
    if len(data) % 16:
        raise ValueError("密文长度不是 16 的倍数（可能不是 AES 密文或密钥错）")
    out = b"".join(_decrypt_block(data[i:i + 16], w, nr) for i in range(0, len(data), 16))
    return _pkcs7_unpad(out) if unpad else out


def decrypt_cbc(data: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    w, nr = _key_expansion(key), _NR[len(key)]
    if len(data) % 16:
        raise ValueError("密文长度不是 16 的倍数")
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, w, nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return _pkcs7_unpad(out) if unpad else out


def encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    w, nr = _key_expansion(key), _NR[len(key)]
    data = _pkcs7_pad(data)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _encrypt_block(blk, w, nr)
        out += enc
        prev = enc
    return out


def selftest() -> bool:
    # FIPS-197 附录 B/C.1 已知向量（AES-128）
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    w, nr = _key_expansion(key), 10
    assert _encrypt_block(pt, w, nr) == ct, "AES 加密向量不符"
    assert _decrypt_block(ct, w, nr) == pt, "AES 解密向量不符"
    return True


if __name__ == "__main__":
    print("AES selftest:", "PASS" if selftest() else "FAIL")
