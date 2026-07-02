#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
冰蝎单条载荷解密（薄封装，复用 webshell_crypto 的真实算法引擎）。

真实冰蝎 v3/v4：静态密钥 = md5(连接密码)[:16] 十六进制字符（默认密码 rebeyond）。
  - XOR：明文 ^ key[(i+1)&15]，报文体可为 raw 或 base64（PHP/无 openssl 默认）
  - AES：AES/ECB/PKCS5（Java/openssl 默认）
  - v4 支持 json 等自定义传输，引擎会自动解包内嵌 base64。

不再依赖旧版并不存在的「动态密钥握手」假设，直接以连接密码解密。
"""
from __future__ import annotations

import argparse
import base64
import binascii

from webshell_crypto import behinder_decrypt, behinder_beautify


def behinder_decode(payload, password: str = "rebeyond", beautify: bool = True) -> str:
    """用连接密码解密一条冰蝎载荷（自动判定 XOR/AES、raw/base64）。"""
    if isinstance(payload, str):
        payload = payload.encode("latin1", "ignore")
    if not payload:
        return "[!] 载荷为空。"
    plain, algo = behinder_decrypt(payload, password)
    if plain is None:
        return "[!] 解密失败：连接密码不匹配，或该载荷非默认冰蝎加密器。"
    return behinder_beautify(plain) if beautify else plain


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a single Behinder payload using the connection password.",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("payload", help="The raw/base64 encrypted payload (request or response body).")
    parser.add_argument("-p", "--password", default="rebeyond",
                        help="The connection password (default: rebeyond).")
    args = parser.parse_args()

    try:
        raw = args.payload.encode("latin1", "ignore")
        # 若整体是 base64 文本，也允许先解一层交给引擎（引擎两种形态都会尝试）
        print("--- Decrypted Data ---")
        print(behinder_decode(raw, args.password))
    except binascii.Error:
        print("[!] Error: payload is not valid.")


if __name__ == "__main__":
    main()
