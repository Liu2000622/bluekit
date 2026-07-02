# -*- coding: utf-8 -*-
"""
统一的真实流量解密引擎（冰蝎 Behinder / 哥斯拉 Godzilla）。

本模块基于对公开样本与多份开源解密脚本（rebeyond/Behinder、BeichenDream/Godzilla、
AlphabugX/godzilla_decode、ba0gu0/behinder-decryptor、s1rius/webshell_pcap_decode 等）
的核对，实现「口令驱动 + 多算法自动探测 + 明文有效性校验」的解密，覆盖真实抓包中最常见
的加密器组合，避免旧实现中对握手/加密模式的错误假设。

核对结论（与旧实现的差异，均已在仓库内真实 pcap 上验证）：

  冰蝎 v3/v4（静态密钥，密钥 = md5(连接密码)[:16] 的十六进制字符）：
    - XOR   : 明文 ^ key[(i+1)&15]，PHP/无 openssl 场景默认；报文体可为 raw 或 base64
    - AES   : AES/ECB/PKCS5，Java/openssl 场景默认；报文体可为 raw 或 base64
    - 传输层：v4 支持自定义传输（json/image/AES_WITH_MAGIC 等）
    （旧实现假设“动态密钥协商 + AES/CBC/IV=md5(key)”，真实 v3/v4 并不存在，故全部解不出）

  哥斯拉（密钥 = md5(密钥字符串)[:16] 的十六进制字符，默认密钥字符串 "key"）：
    - Java    : base64/raw -> AES/ECB 解密 -> gzip 解压
    - C#      : base64/raw/ASMX -> AES/CBC(key=iv) 解密 -> gzip/PE/明文
    - PHP/ASP : base64/raw -> XOR key[(i+1)&15] -> gzip/明文；ASP 另有 Base64/RAW 明文形态
    - 响应体前后各有 16 个字符的 md5 标记（md5(pass+key) 的两半），解密前需剥离
    （旧实现只用一种 AES/CBC 且把前 16 字节当 IV、XOR 用 key[i%16]、且不做 gzip，全部解不出真实流量）
"""

import base64
import binascii
import hashlib
import re
import zlib
from urllib.parse import unquote_to_bytes

from Crypto.Cipher import AES

from analysis_record import looks_like_valid_plaintext


# ============================ 通用工具 ============================

def md5_hex16(s) -> bytes:
    """md5(s) 的十六进制摘要前 16 个字符（冰蝎/哥斯拉密钥派生方式）。"""
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.md5(s).hexdigest()[:16].encode("ascii")


def _key_candidates(secret: str):
    """同时支持传入连接口令（自动 md5 前 16 位）和已派生出的 16 字节 hex key。"""
    derived = md5_hex16(secret)
    yield derived
    raw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    if raw != derived and len(raw) in (16, 24, 32):
        yield raw


def dechunk(head: bytes, body: bytes) -> bytes:
    """
    若响应头声明 Transfer-Encoding: chunked，则对报文体做去分块，返回真实字节；
    否则原样返回。容错解析，遇到异常即返回已解出的部分（或原始 body）。
    """
    if b"transfer-encoding: chunked" not in head.lower():
        return body
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        size_field = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            break
        if size == 0:
            break
        out.extend(body[j + 2:j + 2 + size])
        i = j + 2 + size + 2
    return bytes(out) if out else body


def _content_length(head: bytes):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return None
    return None


def iter_http_messages(direction_bytes: bytes):
    """
    从「单个方向已拼接的 TCP 字节流」中按序切分出多条 HTTP 消息。

    逐条产出 (head, body)：
      - 依 Content-Length 截取报文体；
      - 若为 chunked，则去分块得到真实报文体；
      - 支持一个流内多次请求/响应（keep-alive 复用连接）。
    解析尽力而为，无法继续时停止。
    """
    data = direction_bytes
    while True:
        sep = data.find(b"\r\n\r\n")
        if sep == -1:
            break
        head = data[:sep]
        rest = data[sep + 4:]
        low = head.lower()
        if b"transfer-encoding: chunked" in low:
            body, consumed = _read_chunked(rest)
            rest = rest[consumed:]
        else:
            cl = _content_length(head)
            if cl is None:
                body = rest
                rest = b""
            else:
                body = rest[:cl]
                rest = rest[cl:]
        yield head, body
        if not rest or not rest.strip():
            break
        data = rest


def _read_chunked(data: bytes):
    """解析 chunked 报文体，返回 (去分块后的字节, 消费掉的字节数)。"""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j == -1:
            break
        size_field = data[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            break
        if size == 0:
            i = j + 2
            break
        out.extend(data[j + 2:j + 2 + size])
        i = j + 2 + size + 2
    return bytes(out), i


def _try_b64(data: bytes):
    """尽量宽松地 base64 解码；失败返回 None。"""
    if not data:
        return None
    s = bytes(data).strip()
    # 仅由 base64 字符构成才尝试，避免把 raw 二进制误当 base64
    if not re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", s):
        return None
    pad = len(s.replace(b"\r", b"").replace(b"\n", b"")) % 4
    try:
        return base64.b64decode(s + b"=" * ((4 - pad) % 4))
    except Exception:
        return None


def _try_hex(data: bytes):
    """若 data 是十六进制文本，返回解码后的字节；否则返回 None。"""
    s = bytes(data).strip()
    if len(s) < 2 or len(s) % 2:
        return None
    if not re.fullmatch(rb"[0-9A-Fa-f]+", s):
        return None
    try:
        return binascii.unhexlify(s)
    except (binascii.Error, ValueError):
        return None


def _gunzip(data: bytes):
    """
    尝试 gzip / zlib 解压；都失败返回 None。

    只用带完整性校验的格式：gzip(CRC32) 与 zlib(Adler32)。哥斯拉 Java 用 GZIPOutputStream、
    PHP 用 gzencode/gzcompress，均属这两类。刻意不回退 raw-deflate（负 wbits，无校验），
    因为错误密钥解出的乱码有时也能被 raw-deflate「解压」出垃圾，会造成误报。
    """
    for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            continue
    return None


def _xor(data: bytes, key: bytes) -> bytes:
    """冰蝎/哥斯拉默认异或：data[i] ^ key[(i+1)&15]（只用密钥前 16 字节）。"""
    return bytes(data[i] ^ key[(i + 1) & 15] for i in range(len(data)))


def _aes_ecb_decrypt(data: bytes, key: bytes):
    """AES/ECB 解密并去 PKCS7 填充；长度非法或异常返回 None。"""
    if len(data) < 16 or len(data) % 16 != 0:
        return None
    try:
        out = AES.new(key, AES.MODE_ECB).decrypt(data)
    except Exception:
        return None
    pad = out[-1]
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return out


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes):
    """AES/CBC 解密并严格去 PKCS7；长度非法或填充非法返回 None。"""
    if len(data) < 16 or len(data) % 16 != 0:
        return None
    try:
        out = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        return None
    pad = out[-1]
    if not (1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad):
        return None
    return out[:-pad]


def _to_text(data: bytes) -> str:
    """把字节明文转为展示文本（优先 utf-8，回退 gbk）。"""
    for enc in ("utf-8", "gbk"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", "replace")


# ============================ 冰蝎 Behinder ============================

def behinder_key(password: str) -> bytes:
    """冰蝎密钥：md5(连接密码) 的十六进制前 16 字符（默认密码 rebeyond）。"""
    return md5_hex16(password)


def _is_mostly_b64(body: bytes) -> bool:
    """报文体是否为「纯 base64 文本」（仅 base64 字符 + 可选换行/填充）。"""
    s = body.strip()
    return len(s) >= 16 and re.fullmatch(rb"[A-Za-z0-9+/\r\n]+={0,2}", s) is not None


def _behinder_transport_candidates(body: bytes):
    """
    产出 (候选字节, 是否来自 json 内嵌抽取)：
      - 若报文体是纯 base64 文本：只产出「解码后的字节」（不要对可打印的 base64
        文本本身做 XOR——那样错误密钥也常解出可打印乱码，造成误报）；
      - 否则视为 raw 二进制密文，直接产出；
      - v4 json 传输：从 {"...":{"...":"<base64>"}} 中抽取内嵌 base64 并解码（标记为内嵌）。
    is_nested 用于区分「v4 json 传输解包出的明文」与「普通业务 JSON 报文体」，
    仅前者允许走 PLAIN（无对称加密）判定，避免把业务 JSON 误判为冰蝎。
    """
    if _is_mostly_b64(body):
        b = _try_b64(body)
        if b is not None:
            yield b, False
    else:
        yield body, False
        if body.startswith(b"\x89PNG\r\n\x1a\n") and len(body) > 966:
            yield body[966:], True

    hex_decoded = _try_hex(body)
    if hex_decoded is not None:
        yield hex_decoded, False
        # 冰蝎 v4 image 传输：固定 PNG 头 + 966 字节图片壳，966 字节后为真实明文。
        if hex_decoded.startswith(b"\x89PNG\r\n\x1a\n") and len(hex_decoded) > 966:
            yield hex_decoded[966:], True

    if body[:1] in (b"{", b"["):
        for m in re.finditer(rb'"([A-Za-z0-9+/]{24,}={0,2})"', body):
            dec = _try_b64(m.group(1))
            if dec is not None:
                yield dec, True
        # xsgwork/冰蝎 v4 JSON 传输样本：固定偏移取字符串并把 <> 还原为 +/。
        if len(body) > 29:
            dec = _try_b64(body[26:-3].replace(b"<", b"+").replace(b">", b"/"))
            if dec is not None:
                yield dec, True


_WORD_RE = re.compile(rb"[A-Za-z_]{3,}")


def _behinder_plausible(data: bytes) -> bool:
    """
    比 looks_like_valid_plaintext 更严格的冰蝎明文判据，用于压制「用错误密码对短
    JSON 响应做 XOR 得到的可打印乱码」这类误报（两把密钥都源自 md5 十六进制，字节域
    相近，异或后往往仍落在可打印区间）。

    合法冰蝎明文必为下列之一：
      - Java .class（\\xCA\\xFE\\xBA\\xBE 开头）或 Java 序列化流（\\xAC\\xED 开头）；
      - JSON（{ / [ 开头且含 "key": 结构，如响应 {"status":..,"msg":..}）；
      - 代码/命令（含足够多真实单词且字母占比高，覆盖 PHP/ASP 载荷与命令）。
    """
    if data[:4] == b"\xca\xfe\xba\xbe" or data[:2] == b"\xac\xed":
        return True
    if not looks_like_valid_plaintext(data):
        return False
    stripped = data.strip()
    if stripped[:1] in (b"{", b"[") and (b'":' in data or b'": ' in data):
        return True
    text = data.decode("utf-8", "replace")
    words = _WORD_RE.findall(data)
    letters = sum(1 for c in text if c.isascii() and c.isalpha())
    return len(words) >= 3 and letters / max(len(text), 1) >= 0.45


def behinder_decrypt(body: bytes, password: str = "rebeyond"):
    """
    自动解密一段冰蝎报文体（请求或响应）。

    依次尝试：XOR(key[(i+1)&15]) 与 AES/ECB，作用于 raw 报文体、base64 解码后的字节、
    老版本 AES/CBC 变体，以及 v4 json/image/magic 传输；用 _behinder_plausible 严格校验结果。

    返回 (明文文本, 算法标签)；无法解出返回 (None, None)。
    """
    if not body:
        return None, None
    for key in _key_candidates(password):
        for cand, is_nested in _behinder_transport_candidates(body):
            if not cand or len(cand) < 4:
                continue
            # 1) XOR
            x = _xor(cand, key)
            if _behinder_plausible(x):
                return _to_text(x), "XOR"
            # 2) AES/ECB
            a = _aes_ecb_decrypt(cand, key)
            if a is not None and _behinder_plausible(a):
                return _to_text(a), "AES/ECB"
            # 3) 冰蝎 1.x-3.x 老格式：PHP 常见 AES/CBC(IV=0)，ASPX 常见 AES/CBC(IV=key)
            for iv, label in ((b"\x00" * 16, "AES/CBC/zero-iv"), (key[:16], "AES/CBC/key-iv")):
                c = _aes_cbc_decrypt(cand, key[:16], iv)
                if c is not None and _behinder_plausible(c):
                    return _to_text(c), label
            # 4) AES_WITH_MAGIC：hex -> ascii base64 + 尾部 magic，magic 长度由 key 首字节决定
            try:
                magic_len = int(key[:2].decode("ascii"), 16) % 16
            except Exception:
                magic_len = 0
            if magic_len and len(cand) > magic_len:
                inner = _try_b64(cand[:-magic_len])
                if inner is not None:
                    a = _aes_ecb_decrypt(inner, key)
                    if a is not None and _behinder_plausible(a):
                        return _to_text(a), "AES/ECB+magic"
            # 5) 仅 v4 json/image 传输解包出的明文允许不叠加对称加密
            if is_nested and (b'"msg"' in cand or cand[:4] in (b"\xca\xfe\xba\xbe", b"MZ")) \
                    and _behinder_plausible(cand):
                return _to_text(cand), "PLAIN"
    return None, None


def behinder_beautify(plaintext: str) -> str:
    """
    冰蝎响应通常为 {"status":"...","msg":"..."}，其中 status/msg 为 base64。
    尽量把它们二次解码为可读文本，便于展示；非该结构则原样返回。
    """
    if not plaintext:
        return plaintext
    out = plaintext
    for field in ("msg", "status"):
        m = re.search(r'"%s"\s*:\s*"([A-Za-z0-9+/=]+)"' % field, out)
        if not m:
            continue
        dec = _try_b64(m.group(1).encode())
        if dec is None:
            continue
        # msg 有时是多层 base64，逐层剥到不可再解为止（最多 3 层）
        text = _to_text(dec)
        for _ in range(2):
            inner = _try_b64(text.encode()) if re.fullmatch(r"[A-Za-z0-9+/=]+", text or "") else None
            if inner is None:
                break
            text = _to_text(inner)
        out = out.replace(m.group(0), '"%s(decoded)":"%s"' % (field, text))
    return out


# ============================ 哥斯拉 Godzilla ============================

def godzilla_key(secret: str = "key") -> bytes:
    """哥斯拉对称密钥：md5(密钥字符串) 的十六进制前 16 字符（默认密钥字符串 "key"）。"""
    return md5_hex16(secret)


_GODZILLA_PLAIN_MARKERS = (
    b"methodName=", b"methodName", b"parameters", b"Set Parameters=",
    b"Server.CreateObject", b"Function ", b"Sub main", b"Response.Write",
    b"<?xml", b"<soap:",
)


def _godzilla_plain_plausible(data: bytes) -> bool:
    """ASP 明文/Base64 与 C#/Java 初始载荷的严格明文判据，避免普通业务 base64 误报。"""
    if not data:
        return False
    if data.startswith((b"MZ", b"\xca\xfe\xba\xbe", b"\xac\xed\x00\x05")):
        return True
    if any(m in data for m in _GODZILLA_PLAIN_MARKERS):
        return looks_like_valid_plaintext(data)
    return False


def _godzilla_result_text(data: bytes) -> str:
    """
    哥斯拉 V3/V4 请求参数常为 key + 0x02 + 4 字节长度 + value 的序列化结构。
    能解析则转成 key=value 行；否则按原字节展示。
    """
    out = []
    offset = 0
    try:
        while offset < len(data):
            start = offset
            while offset < len(data) and data[offset] != 2:
                offset += 1
            if offset >= len(data) or offset == start:
                break
            key = data[start:offset].decode("utf-8")
            offset += 1
            if offset + 4 > len(data):
                break
            n = int.from_bytes(data[offset:offset + 4], "little", signed=False)
            offset += 4
            if n < 0 or offset + n > len(data):
                break
            value = _to_text(data[offset:offset + n])
            out.append(f"{key}={value}")
            offset += n
        if out:
            return "\n".join(out)
    except Exception:
        pass
    return _to_text(data)


def _extract_between(data: bytes, left: bytes, right: bytes):
    i = data.find(left)
    if i == -1:
        return None
    i += len(left)
    j = data.find(right, i)
    if j == -1:
        return None
    return data[i:j]


def _godzilla_payload_candidates(body: bytes, is_response: bool):
    """
    产出候选密文字节：
      - 请求：raw 报文体、各 POST 参数值、url 解码后的字节、ASMX/EVAL 内嵌内容
      - 响应：额外尝试剥离前后 16 字符（Java/PHP/C#）或前后 6 字符（ASP）标记
    每个候选再分别按 raw 与 base64 两种编码尝试。
    """
    raw_candidates = [body]
    decoded_body = body
    if b"%" in body:
        try:
            decoded_body = unquote_to_bytes(body.decode("latin1"))
            raw_candidates.append(decoded_body)
        except Exception:
            pass

    # 形如 pass=<payload>&x=<payload> 的参数体：枚举所有参数值，覆盖 PHP_EVAL 等多参数形态。
    # 不能用 parse_qsl：它会把 Base64 中合法的 '+' 改为空格，破坏密文。
    for src in (body, decoded_body):
        if b"=" in src[:256]:
            for part in src.split(b"&"):
                if b"=" not in part:
                    continue
                value = part.split(b"=", 1)[1]
                if not value:
                    continue
                raw_candidates.append(value)
                if b"%" in value:
                    try:
                        raw_candidates.append(unquote_to_bytes(value.decode("latin1")))
                    except Exception:
                        pass

    # C# ASMX / Eval 与 ASP Eval 的内嵌载荷。
    for src in (body, decoded_body):
        for left, right in (
            (b"<pass>", b"</pass>"),
            (b"<passResult>", b"</passResult>"),
            (b"HttpUtility.UrlDecode('", b"')))"),
            (b'bd(""""', b'""""))'),
        ):
            extracted = _extract_between(src, left, right)
            if extracted:
                raw_candidates.append(extracted)
                h = _try_hex(extracted)
                if h is not None:
                    raw_candidates.append(h)

    strips = [(0, 0)]
    if is_response:
        strips.append((16, 16))  # 响应前后 md5 标记
        strips.append((6, 6))    # ASP 响应固定短标记

    for raw in raw_candidates:
        for a, b in strips:
            core = raw[a: len(raw) - b if b else len(raw)]
            if len(core) < 8:
                continue
            yield core  # raw 形态
            hx = _try_hex(core)
            if hx is not None:
                yield hx
            dec = _try_b64(core)
            if dec is not None and dec != core:
                yield dec  # base64 形态


def godzilla_decrypt(body: bytes, secret: str = "key", is_response: bool = False):
    """
    自动解密一段哥斯拉报文体。

    对每个候选密文尝试：AES/ECB 解密后 gzip、XOR(key[(i+1)&15]) 后 gzip（Java/C# 走 AES，
    PHP 走 XOR），并回退到不 gzip 的形态；用 looks_like_valid_plaintext 校验。

    返回 (明文文本, 算法标签)；无法解出返回 (None, None)。
    """
    if not body:
        return None, None
    for key in _key_candidates(secret):
        for core in _godzilla_payload_candidates(body, is_response):
            # 0) ASP BASE64/RAW：解码后就是 VBScript/明文；必须有 webshell 结构标记才接受。
            if _godzilla_plain_plausible(core):
                return _godzilla_result_text(core), "PLAIN"

            # 1) AES/ECB -> gzip（Java）
            a = _aes_ecb_decrypt(core, key)
            if a is not None:
                g = _gunzip(a)
                if g is not None and looks_like_valid_plaintext(g):
                    return _godzilla_result_text(g), "AES/ECB+gzip"
                if looks_like_valid_plaintext(a):
                    return _godzilla_result_text(a), "AES/ECB"

            # 2) AES/CBC(key, iv=key) -> gzip（C# / ASMX）
            c = _aes_cbc_decrypt(core, key, key[:16])
            if c is not None:
                g = _gunzip(c)
                if g is not None and looks_like_valid_plaintext(g):
                    return _godzilla_result_text(g), "AES/CBC+gzip"
                if looks_like_valid_plaintext(c):
                    return _godzilla_result_text(c), "AES/CBC"

            # 3) XOR -> gzip（PHP / ASP XOR）
            x = _xor(core, key)
            g = _gunzip(x)
            if g is not None and looks_like_valid_plaintext(g):
                return _godzilla_result_text(g), "XOR+gzip"
            if _godzilla_plain_plausible(x):
                return _godzilla_result_text(x), "XOR"
    return None, None


# ============================ 组合探测 ============================

def auto_decrypt(body: bytes, password: str, is_response: bool = False):
    """
    在不确定是冰蝎还是哥斯拉时，两种引擎都试，返回第一个校验通过的结果。
    返回 (kind, 明文, 算法)；均失败返回 (None, None, None)。
    """
    plain, algo = godzilla_decrypt(body, password, is_response=is_response)
    if plain is not None:
        return "godzilla", plain, algo
    plain, algo = behinder_decrypt(body, password)
    if plain is not None:
        return "behinder", plain, algo
    return None, None, None
