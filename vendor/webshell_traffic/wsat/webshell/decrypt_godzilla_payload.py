#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哥斯拉单条载荷解密（薄封装，复用 webshell_crypto 的真实算法引擎）。

真实哥斯拉：对称密钥 = md5(密钥字符串)[:16] 十六进制字符（默认 "key"）。
  - Java   ：base64/raw -> AES/ECB -> gzip
  - C#     ：base64/raw/ASMX -> AES/CBC(key=iv) -> gzip/PE/明文
  - PHP/ASP：base64/raw -> XOR(key[(i+1)&15]) -> gzip/明文；ASP 另有 Base64/RAW 明文形态
crypter 参数保留以兼容旧调用，实际加密器由引擎自动判定。
"""

import argparse

from wsat.crypto.webshell_crypto import godzilla_decrypt


def normalize_crypter(crypter: str) -> str:
    """规整加密器标识；仅为兼容旧调用保留（引擎已自动判定加密器）。"""
    c = (crypter or "").strip().upper()
    if c.startswith('PHP_EVAL_XOR_BASE64') or 'EVAL' in c:
        return 'PHP_EVAL_XOR_BASE64'
    if c.startswith('AES_BASE64') or 'AES' in c:
        return 'AES_BASE64'
    if c.startswith('XOR_BASE64') or 'XOR' in c:
        return 'XOR_BASE64'
    return c


def _decode(payload, key: str, is_response: bool = False) -> str:
    if isinstance(payload, str):
        payload = payload.encode("latin1", "ignore")
    if not payload or not key:
        return "[!] 载荷或密钥为空。"
    plain, algo = godzilla_decrypt(payload, key, is_response=is_response)
    if plain is None:
        return "[!] 解密失败：密钥/密钥字符串不匹配，或该载荷非默认哥斯拉加密器。"
    if isinstance(plain, (bytes, bytearray)):
        # 二进制文件载荷（class 内存马 / gzip / 序列化 / PE）：给出类型与保存建议
        from wsat.report.payload_extractor import detect_payload_type
        detected = detect_payload_type(plain)
        label = detected[1] if detected else "未识别二进制数据"
        ext = detected[0] if detected else "bin"
        return (f"[二进制文件载荷 {len(plain)} 字节，{label}]\n"
                f"建议保存为 .{ext} 文件后用对应工具分析。\n"
                f"--- hex（前 512 字节）---\n{bytes(plain)[:512].hex()}")
    return plain


def decrypt_aes_base64(payload_b64: str, key_str: str) -> str:
    """哥斯拉 AES 加密器解密（自动尝试 Java AES/ECB 与 C# AES/CBC）。"""
    return _decode(payload_b64, key_str)


def decrypt_xor_base64(payload_b64: str, key_str: str) -> str:
    """哥斯拉 PHP XOR 加密器解密（XOR key[(i+1)&15] + gzip）。"""
    return _decode(payload_b64, key_str)


def godzilla_decode(payload_str: str, key: str, crypter: str = "") -> str:
    """
    解密单条哥斯拉载荷。key 为「密钥字符串」（默认 "key"）；加密器自动判定，
    crypter 仅作兼容。EVAL 形态支持 `参数名=值&参数名=值` 请求体，取其中的密文值。
    """
    crypter = normalize_crypter(crypter)
    payload = payload_str
    if crypter == 'PHP_EVAL_XOR_BASE64' and isinstance(payload_str, str) and '&' in payload_str:
        try:
            payload = payload_str.split('&', 1)[1].split('=', 1)[1]
        except IndexError:
            return "[!] Invalid PHP_EVAL_XOR_BASE64 format. Expected 'param1=...&param2=...'."
    return _decode(payload, key)


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt a single Godzilla webshell payload (crypter auto-detected).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python3 decrypt_godzilla_payload.py <base64_payload> -k key\n")
    parser.add_argument("payload", help="The payload string (base64 or raw).")
    parser.add_argument("-k", "--key", default="key", help="Secret key string (default: key).")
    parser.add_argument("-c", "--crypter", default="", help="(Compatibility only; auto-detected).")
    args = parser.parse_args()

    print("--- Decrypted Data ---")
    print(godzilla_decode(args.payload, args.key, args.crypter))


if __name__ == "__main__":
    main()
