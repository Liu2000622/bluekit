# -*- coding: utf-8 -*-
"""新增 webshell / HTTP/TCP 隧道插件。"""

import base64
import binascii
import gzip
import re
import zlib
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from wsat.analyzers.base import AnalysisContext, AnalyzerPlugin, DetectionResult
from wsat.core.analysis_record import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DECODE_BINARY_PAYLOAD,
    DECODE_TEXT,
    DECRYPT_SUCCESS,
    RISK_HIGH,
    AnalysisRecord,
    content_sha256,
    make_preview,
)
from wsat.core.http_transactions import iter_http_transactions
from wsat.core.pcap_utils import split_http_message
from wsat.core.websocket import frame_sizes_after_handshake
from wsat.crypto.deobfuscate import deobfuscate
from wsat.crypto.hassh import hassh_from_ws_direction
from wsat.crypto.webshell_crypto import iter_http_messages

_HTTP_METHOD_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"OPTIONS ", b"HEAD ")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _flows(stream):
    return list(stream.directions.values())


def _request(stream):
    for data in _flows(stream):
        for head, body in iter_http_messages(bytes(data)):
            if head.startswith(_HTTP_METHOD_PREFIXES):
                return head + b"\r\n\r\n" + body
        if data.startswith(_HTTP_METHOD_PREFIXES):
            return data
    return None


def _headers_and_body(request):
    if not request:
        return b"", b""
    return split_http_message(request)


def _response(stream):
    for data in _flows(stream):
        for head, body in iter_http_messages(bytes(data)):
            if head.startswith(b"HTTP/"):
                return head + b"\r\n\r\n" + body
        if data.startswith(b"HTTP/"):
            return data
    return None


def _request_line(request):
    if not request:
        return ""
    return request.split(b"\r\n", 1)[0].decode("utf-8", "ignore")


def _uri(request):
    parts = _request_line(request).split()
    return parts[1] if len(parts) >= 2 else ""


def _path(request):
    value = _uri(request)
    return urlsplit(value).path or value


def _decoded_text(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8", "ignore")
    return unquote_plus(data)


def _form_pairs(body):
    text = _decoded_text(body)
    return parse_qsl(text, keep_blank_values=True)


def _multipart_pairs(headers: bytes, body: bytes):
    ctype = _decoded_text(headers).lower()
    m = re.search(r"boundary=([^;\r\n]+)", ctype)
    if "multipart/form-data" not in ctype or not m:
        return []
    boundary = m.group(1).strip().strip('"').encode()
    pairs = []
    for part in body.split(b"--" + boundary):
        if b"\r\n\r\n" not in part:
            continue
        phead, pbody = part.split(b"\r\n\r\n", 1)
        name = re.search(rb'name="([^"]+)"', phead)
        if not name:
            continue
        value = pbody.strip().rstrip(b"--").strip()
        pairs.append((name.group(1).decode("utf-8", "ignore"),
                      value.decode("utf-8", "ignore")))
    return pairs


def _all_pairs(headers: bytes, body: bytes):
    return _multipart_pairs(headers, body) or _form_pairs(body)


def _try_b64_text(value):
    sample = (value or "").strip()
    if len(sample) < 8 or not _B64_RE.match(sample):
        return None
    try:
        raw = base64.b64decode(sample + "=" * (-len(sample) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    text = raw.decode("utf-8", "ignore")
    return text if text.strip() else None


def _b64_to_bytes(value):
    """把参数值按 base64 解码为原始字节；非 base64 返回 None（供识别 Java class 等二进制载荷）。"""
    s = value.decode("latin1", "ignore") if isinstance(value, (bytes, bytearray)) else (value or "")
    s = s.strip()
    if len(s) < 8 or not _B64_RE.match(s):
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def _try_hex_text(value):
    sample = (value or "").strip()
    if len(sample) < 8 or len(sample) % 2:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", sample):
        return None
    try:
        raw = bytes.fromhex(sample)
    except ValueError:
        return None
    text = raw.decode("utf-8", "ignore")
    return text if text.strip() else None


def _try_ant_xor_numbers(value, number=2):
    """
    AntSword-Cryption-WebShell x1_xor: base64 文本每字符 ord^number 后用 '/' 拼接。
    默认 number=2，来自公开 x1_encoder/x1_decoder。
    """
    sample = (value or "").strip()
    if "/" not in sample:
        return None
    parts = sample.split("/")
    if len(parts) < 8:
        return None
    chars = []
    for part in parts:
        if not part:
            continue
        if not part.isdigit():
            return None
        v = int(part)
        if not 0 <= v <= 255:
            return None
        chars.append(chr(v ^ number))
    return _try_b64_text("".join(chars))


def _maybe_inflate_b64(value):
    sample = (value or "").strip()
    try:
        raw = base64.b64decode(sample + "=" * (-len(sample) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(raw, wbits).decode("utf-8", "ignore")
        except zlib.error:
            continue
    return raw.decode("utf-8", "ignore") if raw else None


def _decode_candidates(value):
    value = value or ""
    seen = set()
    for item in (
        value,
        _try_b64_text(value),
        _try_hex_text(value),
        _maybe_inflate_b64(value),
        _try_ant_xor_numbers(value),
    ):
        if item and item not in seen:
            seen.add(item)
            yield item
    # 多层混淆递归还原（base64/strrev/gz/rot13/urldecode 任意链）——让菜刀/蚁剑/
    # weevely 等即便命中也能 surface 完整还原后的载荷
    deob, steps = deobfuscate(value)
    if len(steps) >= 2 and deob and deob not in seen:
        yield f"[多层解码 {'->'.join(steps)}] {deob}"


_PHP_TOKENS = ("<?php", "<?=", "eval(", "assert(", "system(", "shell_exec", "passthru",
               "proc_open", "$_post", "$_get", "$_request", "$_server", "$_cookie",
               "function ", "preg_replace")


def _looks_php(s):
    low = (s or "").lower()
    return any(t in low for t in _PHP_TOKENS)


# PHP 混淆一句话的强特征。与「菜刀」区分：菜刀是 base64_decode($_POST[...]) 单层解码器
# 包 **动态输入**；混淆一句话是解码器 **嵌套** 或包 **内嵌字符串字面量**（自带编码载荷）。
_DECODER = (r"(?:gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|strrev|"
            r"urldecode|rawurldecode|convert_uudecode|hex2bin)")
_OBF_CHAIN = re.compile(
    # 1) 解码器嵌套：base64_decode(gzinflate(...))、strrev(urldecode(...)) 等
    rf"{_DECODER}\s*\(\s*@?\s*{_DECODER}\s*\("
    # 2) 解码器直接包住较长的内嵌编码字符串字面量
    rf"|{_DECODER}\s*\(\s*['\"][A-Za-z0-9+/=%]{{24,}}['\"]", re.I)


def _http_entity_text(head: bytes, body: bytes):
    low = head.lower()
    data = body
    if b"content-encoding: gzip" in low:
        try:
            data = gzip.decompress(body)
        except Exception:
            pass
    return data.decode("utf-8", "ignore")


def _b64_runs_text(text: str, min_len=24):
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % min_len, text):
        decoded = _try_b64_text(m.group(0))
        if decoded:
            out.append(decoded)
    return out


def _record(plugin, stream, request, content, confidence=CONFIDENCE_HIGH):
    return AnalysisRecord(
        analyzer=plugin.name,
        stream_id=stream.stream_id,
        timestamp=stream.timestamp,
        src_ip=stream.key[0][0],
        dst_ip=stream.key[1][0],
        uri=_path(request),
        content=content,
        decrypt_status=DECRYPT_SUCCESS,
        is_valid_target_flow=True,
        confidence=confidence,
    )


_ANT_SHELL_CMD_RE = re.compile(
    r"\b(whoami|uname|hostname|ifconfig|ipconfig|systeminfo|netstat|tasklist|"
    r"net\s+user|id|pwd|cat\s|type\s|ls\s|dir\s|ps\s)\b", re.I)


def _looks_like_shell_command(text):
    """解码后的参数是否像蚁剑真正执行的 shell 命令（而非 PHP 包装器/密文）。"""
    if not text:
        return False
    t = text.strip()
    if any(x in t for x in ("ini_set", "asenc", "asoutput", "base64_decode", "<?php")):
        return False
    if _ANT_SHELL_CMD_RE.search(t):
        return True
    return bool(re.match(r'cd\s+["\']?.+["\']?\s*;', t))


class ChopperPlugin(AnalyzerPlugin):
    name = "chopper"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        # multipart 文件上传交由 web_exploit 的「Webshell上传」识别；菜刀是 urlencoded
        # 参数的命令交互，不是文件上传——避免把上传的 webshell 文件内容误判为菜刀通信。
        if b"multipart/form-data" in headers.lower():
            return None
        text = _decoded_text(body).lower()
        pairs = _all_pairs(headers, body)
        names = {k.lower() for k, _ in pairs}
        if {"z0", "z1"} & names or "frombase64string(" in text:
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                ["命中中国菜刀 z0/z1/z2 参数或 FromBase64String 执行结构"],
                {"uri": _path(request)},
            )
        # 要求出现带括号的 PHP 调用语法 eval(/assert(/system(，而非裸 "eval" 子串——
        # 避免大段 base64（哥斯拉/冰蝎密文）中偶然出现 eval/cmd 子串被误判为菜刀。
        if ("eval(" in text or "assert(" in text or "system(" in text) and (
            "base64_decode" in text or "$_post" in text or "$_get" in text
            or "$_request" in text or "gzuncompress" in text
        ):
            return DetectionResult(
                self.name, 0.86, CONFIDENCE_HIGH,
                ["POST 参数出现菜刀常见 eval(/assert( + $_POST/base64_decode 结构"],
                {"uri": _path(request)},
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        request = _request(stream)
        headers, body = _headers_and_body(request)
        parts = []
        for key, value in _all_pairs(headers, body):
            decoded = next(_decode_candidates(value), value)
            parts.append(f"{key}={decoded}")
        response = _response(stream)
        if response:
            rhead, rbody = split_http_message(response)
            rtext = _http_entity_text(rhead, rbody)
            if "->|" in rtext or "|<-" in rtext:
                parts.append("response=" + rtext)
        content = "\n".join(parts) if parts else _decoded_text(body)
        return [_record(self, stream, request, content)]


class ObfuscatedPhpPlugin(AnalyzerPlugin):
    """PHP 混淆一句话：eval/assert 包裹 base64_decode/gzinflate/strrev 等多层解码链。

    比菜刀更精确地归类这类「混淆一句话」，并用递归解码器还原真身。判据取「sink 直接
    包裹解码器」或「参数值多层解码还原出 PHP」，正常流量几乎不出现，误报低。
    """

    name = "obfuscated_php"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        text = _decoded_text(headers) + "\n" + _decoded_text(body)
        if _OBF_CHAIN.search(text):
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                ["命中 PHP 混淆一句话：eval/assert 包裹 base64_decode/gzinflate/strrev 等解码链"],
                {"uri": _path(request)})
        for key, value in _all_pairs(headers, body):
            deob, steps = deobfuscate(value)
            if len(steps) >= 2 and _looks_php(deob):
                return DetectionResult(
                    self.name, 0.88, CONFIDENCE_HIGH,
                    [f"参数 {key} 经 {'->'.join(steps)} 多层解码还原出 PHP 载荷"],
                    {"uri": _path(request), "param": key})
        return None

    def analyze(self, stream, context: AnalysisContext):
        request = _request(stream)
        headers, body = _headers_and_body(request)
        text = _decoded_text(body)
        candidates = [text] + [v for _k, v in _all_pairs(headers, body)]
        # 还原内层字符串字面量：eval(base64_decode('....')) 里的 '....'
        for m in re.finditer(r"""['"]([A-Za-z0-9+/=%._-]{16,})['"]""", text):
            candidates.append(m.group(1))
        parts, seen = [], set()
        for c in candidates:
            deob, steps = deobfuscate(c)
            if steps and _looks_php(deob) and deob not in seen:
                seen.add(deob)
                parts.append(f"[{'->'.join(steps)}] {deob}")
        rec = _record(self, stream, request, "\n".join(parts) if parts else text, CONFIDENCE_HIGH)
        rec.primary_family = "PHP混淆一句话"
        rec.candidate_families = ["PHP混淆一句话"]
        rec.family_evidence = "eval/assert 包裹多层解码链"
        if parts:
            rec.decoded_command = parts[0][:4000]
        return [rec]


class AntSwordPlugin(AnalyzerPlugin):
    name = "antsword"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        # JSP/Java 蚁剑：参数值 base64 直接解出 Java class（CAFEBABE），与哥斯拉（需 AES 解密
        # 才出 class）区分——蚁剑 JSP 是 pass=base64(明文 class)，置信度高且特异。
        for key, value in _all_pairs(headers, body):
            cls = _b64_to_bytes(value)
            if cls and cls[:4] == b"\xca\xfe\xba\xbe":
                return DetectionResult(
                    self.name, 0.9, CONFIDENCE_HIGH,
                    [f"参数 {key} base64 直接解出 Java class 字节码（JSP/Java 蚁剑加载器）"],
                    {"uri": _path(request), "param": key, "jsp_class": True})
        # ASP/VBScript 蚁剑：default 编码器用 eval("Ex"&cHr(101)&"cute(...) 拼出 Execute，
        # 请求体是 VBScript 明文（URL 编码），与 PHP/JSP 蚁剑判据互补
        _asp = unquote_plus(body.decode("utf-8", "ignore")).lower()
        if ("eval(" in _asp and "cute(" in _asp) or ("execute(" in _asp and "server.scripttimeout" in _asp):
            return DetectionResult(
                self.name, 0.88, CONFIDENCE_HIGH,
                ["请求体命中蚁剑 ASP/VBScript 一句话（eval(...)Execute 混淆拼接）"],
                {"uri": _path(request)})
        raw = (_decoded_text(headers) + "\n" + _decoded_text(body)).lower()
        if "function asenc" in raw or "function asoutput" in raw:
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                ["命中蚁剑 asenc/asoutput 输出包装函数"],
                {"uri": _path(request)},
            )
        for key, value in _all_pairs(headers, body):
            decoded = "\n".join(_decode_candidates(value)).lower()
            if "function asenc" in decoded or "function asoutput" in decoded:
                return DetectionResult(
                    self.name, 0.92, CONFIDENCE_HIGH,
                    [f"参数 {key} 可解出蚁剑 asenc/asoutput 输出包装函数"],
                    {"uri": _path(request), "param": key},
                )
            # 要求「组合特征」而非单个宽松词：正常参数值（如 hex 的 CSRF token）
            # base64/hex 解码后可能偶然含 eval(/$_post 单词，会误报为蚁剑。真蚁剑
            # default 编码器解出的是完整 PHP 包装器（ini_set+set_time_limit 等）。
            if decoded and (
                ("ini_set" in decoded and any(fn in decoded for fn in (
                    "set_time_limit", "system(", "eval(", "assert(", "base64_decode")))
                or ("eval(" in decoded and "base64_decode" in decoded)
                or ("assert(" in decoded and ("$_post" in decoded or "$_request" in decoded))
                or "antsword" in decoded
            ):
                return DetectionResult(
                    self.name, 0.82, CONFIDENCE_MEDIUM,
                    [f"参数 {key} 可 Base64 半解出蚁剑常见 PHP 片段"],
                    {"uri": _path(request), "param": key},
                )
        return None

    def analyze(self, stream, context: AnalysisContext):
        request = _request(stream)
        headers, body = _headers_and_body(request)
        # JSP/Java 蚁剑：class 载荷保留原始字节落盘为 .class，供反编译
        det = context.detection
        if det and det.metadata.get("jsp_class"):
            for key, value in _all_pairs(headers, body):
                cls = _b64_to_bytes(value)
                if cls and cls[:4] == b"\xca\xfe\xba\xbe":
                    rec = _record(self, stream, request,
                                  f"[JSP/Java 蚁剑 class 载荷 {len(cls)} 字节，见落盘文件]",
                                  CONFIDENCE_HIGH)
                    rec.raw_payload = cls
                    rec.payload_type = "java_class"
                    rec.content_type = "java_class"
                    rec.decode_status = DECODE_BINARY_PAYLOAD
                    rec.next_decode_hint = "Java class 字节码，可反编译（见落盘文件）"
                    rec.is_valid_target_flow = False  # 二进制载荷走「载荷结构分析」，非可读明文
                    return [rec]
        decoded = []
        command = None
        for key, value in _all_pairs(headers, body):
            cands = list(_decode_candidates(value))
            decoded.append(f"{key}=" + " | ".join(cands))
            for c in cands:
                if command is None and _looks_like_shell_command(c):
                    command = " ".join(c.split())
        response = _response(stream)
        if response:
            rhead, rbody = split_http_message(response)
            rtext = _http_entity_text(rhead, rbody)
            runs = _b64_runs_text(rtext)
            if runs:
                decoded.append("response_b64=" + "\n".join(runs[:5]))
        rec = _record(self, stream, request, "\n".join(decoded),
                      CONFIDENCE_HIGH if command else CONFIDENCE_MEDIUM)
        if command:
            # 从"半解罗列"提升为"解出命令"：提炼出真正执行的 shell 命令
            rec.decoded_command = command
            rec.detect_confidence = CONFIDENCE_HIGH
        return [rec]


class WebSocketShellPlugin(AnalyzerPlugin):
    """WebShell / 命令交互 over WebSocket：握手升级后，帧载荷解出 shell 命令即判定。

    仅当「存在 WS 握手 且 帧内容含 shell 命令特征」时触发，避免把正常 WS（聊天 / 实时
    推送 / 加密隧道如 chisel）误报——加密隧道的帧解不出可读命令，自然不命中。
    """

    name = "websocket_shell"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def _messages(self, stream):
        from wsat.core.websocket import frames_after_handshake, is_ws_handshake
        has_hs = False
        msgs = []
        for data in _flows(stream):
            if is_ws_handshake(data):
                has_hs = True
            for _op, payload in frames_after_handshake(data):
                if payload:
                    msgs.append(payload)
        return has_hs, msgs

    def detect(self, stream):
        has_hs, msgs = self._messages(stream)
        if not has_hs or not msgs:
            return None
        for m in msgs:
            if _looks_like_shell_command(m.decode("utf-8", "ignore")):
                return DetectionResult(
                    self.name, 0.85, CONFIDENCE_HIGH,
                    ["WebSocket 帧载荷解出 shell 命令（webshell / 命令交互 over WS）"])
        return None

    def analyze(self, stream, context: AnalysisContext):
        _has_hs, msgs = self._messages(stream)
        decoded = []
        for m in msgs[:50]:
            text = m.decode("utf-8", "ignore")
            decoded.append(text if text.strip() else "[binary] " + m[:64].hex())
        return [_record(self, stream, _request(stream) or b"", "\n".join(decoded), CONFIDENCE_HIGH)]


class ReGeorgPlugin(AnalyzerPlugin):
    name = "regeorg"
    category = "tunnel"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        request = _request(stream)
        if not request:
            return None
        headers, body = _headers_and_body(request)
        haystack = (_request_line(request) + "\n" + _decoded_text(headers) + "\n" + _decoded_text(body)).lower()
        if any(token in haystack for token in (
            "cmd=connect", "cmd=read", "cmd=forward", "cmd=disconnect",
            "x-cmd:", "x-target:", "x-port:", "x-status:", "neoreg", "regeorg",
        )):
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                ["命中 reGeorg/Neo-reGeorg HTTP 隧道命令或 X-CMD/X-TARGET 头"],
                {"uri": _path(request)},
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        request = _request(stream)
        headers, body = _headers_and_body(request)
        fields = [_request_line(request)]
        fields.extend(f"{k}={_try_b64_text(v) or v}" for k, v in _form_pairs(body))
        for line in _decoded_text(headers).splitlines():
            if line.lower().startswith(("x-cmd:", "x-target:", "x-port:", "x-status:")):
                fields.append(line)
        return [_record(self, stream, request, "\n".join(fields))]


class NeoReGeorgPlugin(AnalyzerPlugin):
    name = "neo_regeorg"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream))
        text = blob.decode("utf-8", "ignore").lower()
        evidence = []
        has_comment = False
        has_octet = False
        has_random_header = False
        if re.search(rb"<!--\s+[A-Za-z0-9+/_-]{20,}\s+-->", blob):
            has_comment = True
            evidence.append("响应体出现 Neo-reGeorg 可用性探测的 base64 注释标记")
        if b"content-type: application/octet-stream" in blob.lower():
            has_octet = True
            evidence.append("POST 使用 application/octet-stream 传输 BLV/base64 隧道体")
        if re.search(rb"\r\n[A-Za-z][A-Za-z0-9-]{8,}:\s*[A-Za-z0-9+/_-]{16,}", blob):
            has_random_header = True
            evidence.append("出现随机头名 + 变形 base64 值的 Neo-reGeorg 传输形态")
        if "neoreg" in text:
            evidence.append("明文中出现 neoreg 标记")
        if has_comment and len(evidence) >= 2:
            return DetectionResult(self.name, 0.9, CONFIDENCE_HIGH, evidence)
        if has_octet and has_random_header and b"phpsessid=" in blob.lower():
            return DetectionResult(self.name, 0.9, CONFIDENCE_HIGH, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class WeevelyPlugin(AnalyzerPlugin):
    name = "weevely"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        raw = (_decoded_text(headers) + "\n" + _decoded_text(body)).lower()
        if "weevely" in raw:
            return DetectionResult(self.name, 0.88, CONFIDENCE_HIGH, ["出现 weevely 会话标记"])
        if ("gzinflate" in raw or "str_rot13" in raw) and "eval" in raw:
            return DetectionResult(self.name, 0.8, CONFIDENCE_MEDIUM, ["出现 weevely 常见 PHP 混淆执行结构"])
        for _, value in _all_pairs(headers, body):
            decoded = "\n".join(_decode_candidates(value)).lower()
            if "weevely" in decoded or ("eval" in decoded and "gzinflate" in decoded):
                return DetectionResult(self.name, 0.78, CONFIDENCE_MEDIUM, ["参数可半解出 weevely 混淆载荷"])
        return None

    def analyze(self, stream, context: AnalysisContext):
        request = _request(stream)
        headers, body = _headers_and_body(request)
        decoded = []
        for key, value in _all_pairs(headers, body):
            decoded.append(f"{key}=" + " | ".join(_decode_candidates(value)))
        return [_record(self, stream, request, "\n".join(decoded) or _decoded_text(body), CONFIDENCE_MEDIUM)]


def _checksum8(path):
    clean = path.strip("/")
    if not clean:
        return None
    return sum(clean.encode("utf-8", "ignore")) % 256


class CobaltStrikePlugin(AnalyzerPlugin):
    name = "cobalt_strike"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        request = _request(stream)
        if not request:
            return None
        headers, _ = _headers_and_body(request)
        path = _path(request)
        text = (_request_line(request) + "\n" + _decoded_text(headers)).lower()
        evidence = []
        if _checksum8(path) in (92, 93) and 2 <= len(path.strip("/")) <= 8:
            evidence.append("URI checksum8 命中 Cobalt Strike stager 常见校验值")
        if "msie 9.0" in text and "trident/5.0" in text:
            evidence.append("User-Agent 命中 Cobalt Strike 常见 IE9/Trident 指纹")
        if "jquery" in text and (".js" in path or ".php" in path):
            evidence.append("URI/UA 组合符合 Beacon profile 常见伪装")
        if len(evidence) >= 2:
            return DetectionResult(self.name, 0.84, CONFIDENCE_MEDIUM, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class MeterpreterPlugin(AnalyzerPlugin):
    name = "meterpreter"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        request = _request(stream)
        if not request:
            return None
        headers, _ = _headers_and_body(request)
        text = (_request_line(request) + "\n" + _decoded_text(headers)).lower()
        evidence = []
        if "initm" in text or "initjm" in text or "meterpreter" in text:
            evidence.append("URI/头部出现 Meterpreter reverse_http 初始化标记")
        if "msie 6.1" in text and "windows nt" in text:
            evidence.append("User-Agent 命中 Meterpreter 常见 IE6.1 指纹")
        if "cache-control: no-cache" in text and "connection: keep-alive" in text:
            evidence.append("HTTP 头组合符合 Meterpreter 轮询流量模式")
        if len(evidence) >= 2:
            return DetectionResult(self.name, 0.82, CONFIDENCE_MEDIUM, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


# --- 新一代开源 C2（Sliver / Havoc / Merlin）------------------------------
# 这些框架实战占比逐年上升。默认部署多走 TLS/mTLS，其加密流量由 JA3/JA4 指纹侧
# 识别（见 crypto/ja3.py）；此处补齐它们「明文 HTTP profile / demon 传输」的载荷层
# 指纹。判据均取「正常流量几乎不出现」的强特征或组合特征，仅告警不尝试解密。

class HavocPlugin(AnalyzerPlugin):
    """Havoc（C5pider）Demon agent：POST body 以 Demon 魔数 0xDEADBEEF 起始。

    Havoc 的 Demon 每个 agent 包首个 int32 为 DEMON_MAGIC_VALUE=0xDEADBEEF，随后是
    4 字节 AgentID。该魔数出现在 HTTP POST body 起始几乎不可能来自正常流量，特异性高。
    """

    name = "havoc"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    _MAGIC = b"\xde\xad\xbe\xef"

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        _headers, body = _headers_and_body(request)
        if body[:4] == self._MAGIC and len(body) >= 8:
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                [f"POST body 以 Havoc Demon 魔数 0xDEADBEEF 起始，AgentID={body[4:8].hex()}"],
            )
        # base64 HTTP profile：magic 的 base64 前缀为 '3q2+'
        if body[:4] == b"3q2+":
            return DetectionResult(
                self.name, 0.82, CONFIDENCE_MEDIUM,
                ["POST body 为 Havoc Demon 魔数 0xDEADBEEF 的 base64 起始（3q2+…）"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


_SLIVER_STATIC_EXT = re.compile(r"\.(js|css|png|jpe?g|gif|woff2?|html?|ico|svg)(\?|$)", re.I)
# Sliver 默认会话 Cookie 名池里较特异的几个（短名如 SID/SSID 易撞正常流量，不采纳）
_SLIVER_COOKIES = ("csrf-state", "awsalbcors", "apisid")


class SliverPlugin(AnalyzerPlugin):
    """Sliver（BishopFox）HTTP(S) C2：POST 加密体到「静态资源类」URI 伪装。

    默认 HTTP C2 把植入端回连伪装成对 .js/.png/.woff 等静态文件的请求，但用 POST
    提交加密消息（正常浏览器只会 GET 静态资源）。结合 Go-http-client UA 或 Sliver
    默认 Cookie 池命中作二次确认，压制误报。默认多走 TLS，此为明文 profile 兜底。
    """

    name = "sliver"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        if not _SLIVER_STATIC_EXT.search(_path(request)) or len(body.strip()) < 16:
            return None
        low = headers.lower()
        go_ua = b"go-http-client" in low
        cookie_hit = b"cookie:" in low and any(c.encode() in low for c in _SLIVER_COOKIES)
        if not (go_ua or cookie_hit):
            return None
        evidence = ["POST 提交加密体到静态资源类 URI（Sliver HTTP C2 伪装为静态文件请求）"]
        if go_ua:
            evidence.append("User-Agent 为 Go-http-client（Go 编写的植入端默认）")
        if cookie_hit:
            evidence.append("Cookie 名命中 Sliver 默认会话 Cookie 池")
        return DetectionResult(self.name, 0.8, CONFIDENCE_MEDIUM, evidence)

    def analyze(self, stream, context: AnalysisContext):
        return []


class MerlinPlugin(AnalyzerPlugin):
    """Merlin（Ne0nd0g）C2：JWT(JWE) 承载 gob 消息 + application/octet-stream 载荷。

    Merlin 用 `Authorization: Bearer <JWT>` 携带会话令牌，消息体是不透明二进制
    （octet-stream）。单看 JWT bearer 会撞正常 REST API，故要求 JWT + (octet-stream
    或 Go UA) 组合，且 body 非空，压制普通 JSON API 误报。
    """

    name = "merlin"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        request = _request(stream)
        if not request or not request.startswith(b"POST "):
            return None
        headers, body = _headers_and_body(request)
        low = headers.lower()
        has_jwt = bool(re.search(rb"authorization:\s*bearer\s+eyj", low))
        octet = b"content-type: application/octet-stream" in low
        go_ua = b"go-http-client" in low
        if not (has_jwt and (octet or go_ua) and len(body.strip()) >= 16):
            return None
        evidence = ["Authorization: Bearer JWT（Merlin JWE 会话令牌形态）"]
        if octet:
            evidence.append("Content-Type: application/octet-stream 承载不透明二进制体")
        if go_ua:
            evidence.append("User-Agent 为 Go-http-client")
        return DetectionResult(self.name, 0.72, CONFIDENCE_MEDIUM, evidence)

    def analyze(self, stream, context: AnalysisContext):
        return []


_BORE_CTRL = re.compile(
    rb'\{"(Challenge|Connection|Accept|Authenticate)":"'
    rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\}')
_BORE_HELLO = re.compile(rb'\{"Hello":\d{1,5}\}')


class BorePlugin(AnalyzerPlugin):
    """bore（ekzhang/bore）TCP 隧道：明文 serde-JSON 控制协议，特征极强、误报极低。

    控制通道用换行分隔的 serde 标签枚举消息：`{"Hello":<port>}`、`{"Challenge":"<uuid>"}`、
    `{"Connection":"<uuid>"}`、`{"Accept":"<uuid>"}`、`"Heartbeat"`。带 UUID 的控制消息
    正常流量几乎不出现，直接高置信度告警。bore 常被用作内网端口对外暴露的轻量隧道。
    """

    name = "bore"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream))
        m = _BORE_CTRL.search(blob)
        if m:
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                [f"命中 bore 隧道控制协议 JSON 消息: {m.group(0).decode('latin1')[:80]}"])
        # 无 UUID 消息时的兜底：{"Hello":port} 与 Heartbeat 须同现，避免误报
        if _BORE_HELLO.search(blob) and b'"Heartbeat"' in blob:
            return DetectionResult(
                self.name, 0.8, CONFIDENCE_MEDIUM,
                ['命中 bore 隧道 {"Hello":port} + Heartbeat 控制序列'])
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


# hoaxshell/Villain 默认会话头：X-<4hex>-<4hex>: <8hex>-<8hex>-<8hex>（非标准 UUID 的
# 三段十六进制），正常流量几乎不出现，特异性极高。
_HOAXSHELL_HDR = re.compile(
    rb"X-[0-9a-f]{4}-[0-9a-f]{4}:\s*[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}", re.I)
_HOAX_PATH = re.compile(r"^/[0-9a-zA-Z]{6,10}$")


class VillainPlugin(AnalyzerPlugin):
    """Villain / hoaxshell PowerShell HTTP C2：把 C2 流量伪装成普通 Web 请求。

    默认会话头 X-xxxx-xxxx: 8hex-8hex-8hex 极特异（直接高置信度）；兜底用
    「User-Agent 含 WindowsPowerShell + GET 短随机路径轮询」组合，压制正常 PowerShell 访问误报。
    """

    name = "villain_hoaxshell"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream))
        if _HOAXSHELL_HDR.search(blob):
            return DetectionResult(
                self.name, 0.9, CONFIDENCE_HIGH,
                ["命中 hoaxshell/Villain 自定义会话头 X-xxxx-xxxx: 8hex-8hex-8hex"])
        if b"windowspowershell" in blob.lower():
            request = _request(stream)
            if request and request.startswith(b"GET ") and _HOAX_PATH.match(_path(request)):
                return DetectionResult(
                    self.name, 0.8, CONFIDENCE_MEDIUM,
                    ["User-Agent 含 WindowsPowerShell + GET 短随机路径（hoaxshell 轮询形态）"])
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class GenericHttpTunnelPlugin(AnalyzerPlugin):
    name = "http_tunnel_tools"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        request = _request(stream)
        if not request:
            return None
        headers, body = _headers_and_body(request)
        text = (_request_line(request) + "\n" + _decoded_text(headers) + "\n" + _decoded_text(body)).lower()
        hits = []
        for token in ("tunna", "pystinger", "abptts", "x-abptts", "x-tunna", "x-pystinger"):
            if token in text:
                hits.append(token)
        if hits:
            return DetectionResult(
                self.name, 0.86, CONFIDENCE_HIGH,
                [f"命中 HTTP 隧道工具特征: {', '.join(sorted(set(hits)))}"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class SocksProxyPlugin(AnalyzerPlugin):
    name = "socks_proxy"
    category = "tunnel"
    requires_key = False
    can_decrypt = True

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        evidence = []
        if len(blob) >= 3 and blob[0] == 5 and 1 <= blob[1] <= 8 and len(blob) >= 2 + blob[1]:
            evidence.append("命中 SOCKS5 握手版本/认证协商")
        if (len(blob) >= 9 and blob[0] == 4 and blob[1] in (1, 2)
                and int.from_bytes(blob[2:4], "big") > 0 and b"\x00" in blob[8:64]):
            evidence.append("命中 SOCKS4 CONNECT 握手")
        if evidence:
            return DetectionResult(self.name, 0.88, CONFIDENCE_HIGH, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        lines = []
        for data in _flows(stream):
            if len(data) >= 4 and data[0] == 5:
                lines.append(f"SOCKS5 raw={data[:64].hex()}")
            elif len(data) >= 9 and data[0] == 4:
                cmd = data[1]
                port = int.from_bytes(data[2:4], "big")
                ip = ".".join(str(b) for b in data[4:8])
                lines.append(f"SOCKS4 cmd={cmd} target={ip}:{port}")
        return [_record(self, stream, b"", "\n".join(lines), CONFIDENCE_HIGH)]


class ChiselPlugin(AnalyzerPlugin):
    """jpillora/chisel 隧道识别 + 取证画像。

    chisel 是攻击者常用的快速 TCP/UDP over HTTP 隧道：客户端（多为被控主机）以
    WebSocket 升级连到 chisel 服务端（C2），子协议固定为 ``chisel-vN``；升级后在
    WebSocket 二进制帧内再跑一层 SSH（版本旗标 ``SSH-chisel-vN-server/client``）承载
    加密的多路复用隧道。隧道的 remotes（如 ``R:socks``、端口转发）走 SSH 加密通道，
    无密钥不可解，因此本插件只作识别与画像：提取 C2 地址、通信角色、是否 TLS 包裹、
    内嵌 SSH 指纹与 KEX、``--auth`` 凭据，供应急分析定位。"""

    name = "chisel"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    # 版本无关：兼容历史 chisel-v2 与未来版本，只认 chisel-v<数字>
    _PROTO_RE = re.compile(rb"sec-websocket-protocol:\s*(chisel-v\d+)", re.I)
    _SSH_BANNER_RE = re.compile(rb"SSH-(chisel-v\d+)-(server|client)")
    _KEX_RE = re.compile(
        rb"(curve25519-sha256|ecdh-sha2-nistp\d+|diffie-hellman-group[\w-]+)")

    def _profile(self, stream):
        """从重组流提取 chisel 隧道画像；非 chisel 返回 None。"""
        proto = ssh_banner = None
        client_key = server_key = None  # ((ip,port),(ip,port)) 方向键
        c2_host = auth_b64 = None
        for key, data in stream.directions.items():
            data = bytes(data)
            if proto is None:
                m = self._PROTO_RE.search(data)
                if m:
                    proto = m.group(1).decode()
            # 发出 WebSocket 升级请求的一方即 chisel 客户端（被控主机）
            if client_key is None and data[:4] in (b"GET ", b"POST"):
                if b"pgrade" in data[:512] and (proto or b"chisel-v" in data.lower()):
                    client_key = key
                    mh = re.search(rb"[Hh]ost:\s*([^\r\n]+)", data)
                    if mh:
                        c2_host = mh.group(1).decode("latin1", "ignore").strip()
                    ma = re.search(rb"[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)", data)
                    if ma:
                        auth_b64 = ma.group(1).decode("latin1", "ignore")
            if ssh_banner is None:
                mb = self._SSH_BANNER_RE.search(data)
                if mb:
                    ssh_banner = (mb.group(1).decode(), mb.group(2).decode())
                    if mb.group(2) == b"server":
                        server_key = key
        if proto is None and ssh_banner is None:
            return None
        version = proto or (ssh_banner[0] if ssh_banner else "chisel-v?")
        # 角色补全：客户端已知则对端为服务端，反之亦然
        if server_key is None and client_key is not None:
            server_key = (client_key[1], client_key[0])
        if client_key is None and server_key is not None:
            client_key = (server_key[1], server_key[0])
        blob = b"\n".join(_flows(stream))
        kex = sorted({m.group(1).decode() for m in self._KEX_RE.finditer(blob)})
        tls = any(d[:1] == b"\x16" for d in _flows(stream) if d)
        dirs = stream.directions
        return {
            "version": version,
            "client_key": client_key,
            "server_key": server_key,
            "c2_host": c2_host,
            "auth_b64": auth_b64,
            "ssh_banner": ssh_banner,
            "kex": kex,
            "tls": tls,
            "hassh": self._hassh(dirs.get(client_key), is_server=False) if client_key else None,
            "hassh_server": self._hassh(dirs.get(server_key), is_server=True) if server_key else None,
            "behavior": None if tls else self._behavior(
                bytes(dirs.get(client_key) or b""), bytes(dirs.get(server_key) or b"")),
        }

    @staticmethod
    def _hassh(direction_bytes, is_server):
        if not direction_bytes:
            return None
        return hassh_from_ws_direction(bytes(direction_bytes), is_server=is_server)

    @staticmethod
    def _behavior(c2s_bytes, s2c_bytes):
        """基于 WebSocket 帧大小/方向/数量推断隧道用途（不解密，纯元数据）。"""
        up = frame_sizes_after_handshake(c2s_bytes)      # 客户端→服务端
        down = frame_sizes_after_handshake(s2c_bytes)    # 服务端→客户端
        n = len(up) + len(down)
        total = sum(up) + sum(down)
        if n < 12 or total < 2500:
            return {"label": "隧道已建立但载荷极少，疑似空闲/仅握手，不足以判定用途",
                    "frames": n, "bytes": total}
        sizes = up + down
        mean = total / n
        small_ratio = sum(1 for s in sizes if s < 200) / n
        up_bytes, down_bytes = sum(up), sum(down)
        dominant = max(up_bytes, down_bytes) / total
        big_dir = "上行(客户端→C2，疑似数据外传)" if up_bytes >= down_bytes else "下行(C2→客户端，疑似投递)"
        if dominant >= 0.85 and mean > 400:
            label = f"批量传输，方向以{big_dir}为主"
        elif small_ratio >= 0.6 and mean < 300:
            label = "交互式会话（shell/命令行，双向小帧突发、含击键节奏特征）"
        else:
            label = "多路复用代理转发或混合流量（中等帧、双向活跃，疑似 SOCKS/端口转发）"
        return {"label": label, "frames": n, "bytes": total,
                "mean_frame": round(mean, 1), "small_ratio": round(small_ratio, 2),
                "up_bytes": up_bytes, "down_bytes": down_bytes}

    def _evidence(self, prof):
        ev = [f"WebSocket 子协议命中 chisel 握手指纹：{prof['version']}"]
        if prof["ssh_banner"]:
            ver, role = prof["ssh_banner"]
            ev.append(f"WebSocket 帧内嵌 SSH 版本旗标 SSH-{ver}-{role}（隧道上跑加密 SSH）")
        if prof["c2_host"]:
            ev.append(f"chisel 服务端(C2)地址：{prof['c2_host']}")
        elif prof["server_key"]:
            ip, port = prof["server_key"][0]
            ev.append(f"chisel 服务端(C2)地址：{ip}:{port}")
        if prof["client_key"]:
            ip, port = prof["client_key"][0]
            ev.append(f"chisel 客户端(被控端)：{ip}:{port}")
        if prof["auth_b64"]:
            cred = ""
            try:
                cred = base64.b64decode(prof["auth_b64"] + "=" * (-len(prof["auth_b64"]) % 4)).decode("latin1", "ignore")
            except (binascii.Error, ValueError):
                cred = ""
            ev.append(f"启用 --auth 认证，凭据 user:pass = {cred or prof['auth_b64']}")
        if prof["kex"]:
            ev.append(f"隧道内 SSH 密钥交换算法：{', '.join(prof['kex'])}")
        if prof["hassh"]:
            md5, _algo, name = prof["hassh"]
            ev.append(f"客户端 HASSH 指纹：{md5}" + (f"（{name}）" if name else ""))
        if prof["hassh_server"]:
            md5, _algo, name = prof["hassh_server"]
            ev.append(f"服务端 HASSH-Server 指纹：{md5}" + (f"（{name}）" if name else ""))
        if prof["behavior"]:
            b = prof["behavior"]
            detail = f"（帧数 {b['frames']}、共 {b['bytes']}B" + (
                f"、均值 {b['mean_frame']}B、小帧占比 {b['small_ratio']}）" if "mean_frame" in b else "）")
            ev.append(f"隧道行为倾向：{b['label']}{detail}")
        if prof["tls"]:
            ev.append("隧道经 TLS 包裹（chisel client https://…），载荷与 SSH 指纹不可见，仅凭 WS 握手识别")
        return ev

    def detect(self, stream):
        prof = self._profile(stream)
        if prof is None:
            return None
        return DetectionResult(
            self.name, 0.96, CONFIDENCE_HIGH, self._evidence(prof),
            metadata={
                "c2": prof["c2_host"],
                "version": prof["version"],
                "tls": prof["tls"],
                "authenticated": bool(prof["auth_b64"]),
                "hassh": prof["hassh"][0] if prof["hassh"] else None,
                "hassh_server": prof["hassh_server"][0] if prof["hassh_server"] else None,
                "behavior": prof["behavior"]["label"] if prof["behavior"] else None,
            },
        )

    def analyze(self, stream, context: AnalysisContext):
        return []


class FastTunnelPlugin(AnalyzerPlugin):
    name = "fast_tunnel"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream)).lower()
        if b"ft_version:" in blob and b"ft_token:" in blob and b"upgrade: websocket" in blob:
            return DetectionResult(
                self.name, 0.94, CONFIDENCE_HIGH,
                ["命中 FastTunnel FT_VERSION/FT_TOKEN WebSocket 握手"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class FrpPlugin(AnalyzerPlugin):
    name = "frp"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if b'"privilege_key"' in blob and b'"version"' in blob and b'"pool_count"' in blob:
            return DetectionResult(
                self.name, 0.94, CONFIDENCE_HIGH,
                ["命中 frp 登录 JSON（version/privilege_key/pool_count）"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class NpsPlugin(AnalyzerPlugin):
    name = "nps"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        evidence = []
        if blob.startswith(b"TST") or b"TST" in blob[:32]:
            evidence.append("命中 nps/npc TST 握手")
        if re.search(rb"\x06\x00\x00\x000\.\d+\.\d+", blob) or re.search(rb"\x07\x00\x00\x000\.\d+\.\d+", blob):
            evidence.append("命中 nps/npc 版本协商帧")
        if evidence:
            return DetectionResult(self.name, 0.9, CONFIDENCE_HIGH, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class VenomPlugin(AnalyzerPlugin):
    name = "venom"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if b"ABCDEFGH" in blob[:128] and b"VCMD" in blob[:256]:
            return DetectionResult(
                self.name, 0.95, CONFIDENCE_HIGH,
                ["命中 Venom ABCDEFGH/VCMD 明文握手"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class StowawayPlugin(AnalyzerPlugin):
    name = "stowaway"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if b"IAMNEWHEREIAMADMINXD" in blob or b"THEREISNOROUTE" in blob:
            return DetectionResult(
                self.name, 0.95, CONFIDENCE_HIGH,
                ["命中 Stowaway IAMNEWHEREIAMADMINXD/THEREISNOROUTE 协议标记"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class LanproxyPlugin(AnalyzerPlugin):
    name = "lanproxy"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if re.search(rb"\x00\x00\x00\*\x01\x00\x00\x00.{5}\x20[0-9a-f]{32}", blob, re.S):
            return DetectionResult(
                self.name, 0.86, CONFIDENCE_MEDIUM,
                ["命中 Lanproxy 注册帧长度/类型 + 32位十六进制 clientKey 形态"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class TermitePlugin(AnalyzerPlugin):
    name = "termite"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if b"agent" in blob[:256] and (b"kali" in blob[:512] or b"localhost.localdomain" in blob[:512]):
            return DetectionResult(
                self.name, 0.82, CONFIDENCE_MEDIUM,
                ["命中 Termite agent 主机信息注册帧特征"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class CloudTunnelPlugin(AnalyzerPlugin):
    name = "cloud_tunnel"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream)).lower()
        evidence = []
        if b"tunnels.api.visualstudio.com" in blob:
            evidence.append("TLS ClientHello SNI 命中 VSCode Tunnel")
        if b"cftunnel.com" in blob:
            evidence.append("TLS ClientHello SNI 命中 Cloudflare Tunnel")
        if evidence:
            return DetectionResult(self.name, 0.92, CONFIDENCE_HIGH, evidence)
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


class VShellPlugin(AnalyzerPlugin):
    name = "vshell"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"".join(_flows(stream))
        if blob.startswith(b"l64   ") or (blob.count(b"\x99") > 128 and b"l64" in blob[:64]):
            return DetectionResult(
                self.name, 0.86, CONFIDENCE_MEDIUM,
                ["命中 VShell stager/l64 与 0x99 填充流量特征"],
            )
        return None

    def analyze(self, stream, context: AnalysisContext):
        return []


# ---------------------------------------------------------------------------
# 通用 Web 漏洞利用 / 写 Webshell / 明文 RCE 检测（覆盖非三大 webshell 的入口攻击）
# ---------------------------------------------------------------------------

# 明文即证据：这些攻击载荷本身可读，直接把请求行/载荷作为记录内容进主结果。
# 签名尽量取「专属特征」以压制误报（如 jndi:、call_user_func_array、INTO OUTFILE）。
_EXPLOIT_SIGNATURES = [
    (re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis)", re.I),
     "Log4Shell(JNDI)", "JNDI 注入 / 远程代码执行", 0.95),
    (re.compile(r"invokefunction|call_user_func_array\b", re.I),
     "ThinkPHP RCE", "命令执行(ThinkPHP)", 0.9),
    (re.compile(r"into\s+(outfile|dumpfile)\b", re.I),
     "SQLi 写文件", "SQL 注入写 Webshell", 0.9),
    (re.compile(r"runtime\.getruntime|processbuilder|t\(\s*java\.lang\.runtime", re.I),
     "Java RCE", "命令执行(Java 反射)", 0.88),
    (re.compile(r"%\{\s*\(#|#context\[|#_memberaccess|\bognl\b", re.I),
     "Struts/OGNL", "OGNL 注入 / 远程代码执行", 0.88),
    (re.compile(r"\b(shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(", re.I),
     "PHP 命令执行", "命令执行(PHP 危险函数)", 0.82),
    # 命令注入：仅用真正的 shell 操作符（; | || && $( `）作分隔，排除 URL 参数分隔符 &；
    # 命令后不得紧跟 = 或字母（避免 id=、identity 等参数名/单词误报）。
    (re.compile(r"(?:[;|`]|\|\||&&|\$\()\s*"
                r"(id|whoami|uname|ifconfig|ipconfig|systeminfo|net\s+user|"
                r"cat\s+/etc/(passwd|shadow)|/bin/(ba)?sh|cmd\.exe|curl\s|wget\s)"
                r"(?![=\w])", re.I),
     "命令注入", "命令注入", 0.85),
    (re.compile(r"(?:^|[?&])(cmd|command|exec)=.{0,40}?"
                r"(whoami|ipconfig|systeminfo|net\s+user|/bin/(ba)?sh|cmd\.exe|/etc/passwd)", re.I),
     "命令执行", "命令执行(参数注入)", 0.82),

    # --- SQL 注入（用几乎只在注入 payload 出现的强特征，避免正常参数误报）---
    (re.compile(r"\b(extractvalue|updatexml)\s*\(\s*\d", re.I),
     "SQL注入(报错)", "SQL 报错注入(extractvalue/updatexml)", 0.9),
    (re.compile(r"\bunion\s+(all\s+)?select\b", re.I),
     "SQL注入(UNION)", "SQL 联合查询注入", 0.9),
    (re.compile(r"\bwaitfor\s+delay\s+['\"]", re.I),
     "SQL注入(时间盲注)", "SQL 时间盲注(MSSQL waitfor)", 0.85),
    (re.compile(r"['\")\s](and|or|;)\b[^\n]{0,40}?\b(sleep|benchmark|pg_sleep)\s*\(\s*\d", re.I),
     "SQL注入(时间盲注)", "SQL 时间盲注(sleep/benchmark)", 0.85),
    (re.compile(r"\bselect\b[^\n]{0,80}?\bfrom\b[^\n]{0,40}?"
                r"(information_schema|sysobjects|pg_catalog|mysql\.user)", re.I),
     "SQL注入(枚举)", "SQL 注入枚举系统库表", 0.85),

    # --- 任意文件读取 / 路径穿越（要求多层穿越或明确敏感文件/伪协议）---
    (re.compile(r"(\.\./|\.\.%2f|\.\.\\|\.\.%5c){2,}", re.I),
     "路径穿越", "目录穿越 / 任意文件读取", 0.85),
    (re.compile(r"(/etc/(passwd|shadow)\b|/proc/self/environ\b|/windows/win\.ini\b|\bboot\.ini\b)", re.I),
     "任意文件读取", "读取敏感系统文件", 0.85),
    (re.compile(r"php://(filter|input)|file:///|expect://|zip://|phar://", re.I),
     "PHP伪协议", "PHP 伪协议文件读取 / 反序列化", 0.82),

    # --- SSRF（用云元数据地址 / 危险协议 / 参数携带内网 URL 等强特征）---
    (re.compile(r"\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b", re.I),
     "SSRF(云元数据)", "SSRF 访问云元数据服务", 0.9),
    (re.compile(r"\b(gopher|dict)://", re.I),
     "SSRF(危险协议)", "SSRF gopher/dict 协议利用", 0.85),
    # 注：不检测「参数携带内网 URL」——正常微服务/内部系统流量大量带内网地址，
    # 无法可靠区分 SSRF 攻击与正常内网调用，会误报。SSRF 仅保留云元数据 / gopher-dict
    # 这类正常流量几乎不出现的强特征。
]

# 上传/写 Webshell：multipart 文件名为脚本后缀、或 PUT/POST 脚本体
_WEBSHELL_FILENAME = re.compile(
    r'filename\s*=\s*"[^"]+\.(php\d?|phtml|jsp|jspx|jspa|asp|aspx|ashx|asmx|cer|war)"', re.I)
_SCRIPT_URI = re.compile(r"\.(php\d?|phtml|jsp|jspx|asp|aspx|ashx|asmx|war)(/|$)", re.I)
_SCRIPT_BODY = re.compile(
    r"<\?php|<%@\s*page|<%[=!\s]|<jsp:|eval\s*\(\s*\$_(POST|GET|REQUEST)|"
    r"Runtime\.getRuntime|ProcessBuilder", re.I)
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"OPTIONS ", b"HEAD ", b"DELETE ", b"PATCH ")


def _match_exploit(method: str, path: str, decoded: str, raw_body: bytes):
    """在「URL 解码后的请求行+参数+报文体」上匹配漏洞利用/写马特征。

    返回 (family, behavior, confidence, evidence) 或 None。
    """
    # 1) 上传/写 Webshell：multipart 脚本文件名
    m = _WEBSHELL_FILENAME.search(decoded)
    if m:
        return ("Webshell上传", "上传 Webshell 文件", 0.85, m.group(0)[:120])
    # 1b) multipart 上传：文件名非脚本后缀（如 shell.png 图片马 / 改名绕后缀），
    #     但内容含 webshell 代码——按上传归类，不误判为菜刀命令交互
    if 'filename="' in decoded.lower():
        bm = _SCRIPT_BODY.search(decoded)
        if bm:
            return ("Webshell上传", "上传含 Webshell 代码的文件（图片马/绕后缀上传）",
                    0.85, bm.group(0)[:120])
    # 2) PUT/POST 直接写脚本文件（Tomcat PUT、任意文件写）
    if method in ("PUT", "POST") and _SCRIPT_URI.search(path) and _SCRIPT_BODY.search(decoded):
        bm = _SCRIPT_BODY.search(decoded)
        return ("Webshell上传", f"{method} 写入脚本文件", 0.85,
                f"{method} {path} -> {bm.group(0)}")
    # 3) 明文 RCE / 注入签名
    best = None
    for rx, family, behavior, conf in _EXPLOIT_SIGNATURES:
        mm = rx.search(decoded)
        if mm and (best is None or conf > best[2]):
            best = (family, behavior, conf, mm.group(0)[:120])
    return best


class WebExploitPlugin(AnalyzerPlugin):
    """通用 Web 漏洞利用 / 写 Webshell / 明文命令执行检测。

    针对非三大 webshell 的「入口攻击」流量（RCE、模板/表达式注入、SQLi 写马、
    脚本文件上传等）。载荷为明文，直接把命令/载荷作为证据写入主结果。
    """

    name = "web_exploit"
    category = "webshell"
    requires_key = False
    can_decrypt = True

    def _iter_request_matches(self, stream):
        """产出 (txn, family, behavior, confidence, evidence)。"""
        txns = iter_http_transactions(stream.packets)
        results = []
        for txn in txns:
            if not txn.request:
                continue
            head, body = txn.request.head, txn.request.body
            if not head.startswith(_HTTP_METHODS):
                continue
            line = head.split(b"\r\n", 1)[0].decode("utf-8", "ignore")
            parts = line.split()
            method = parts[0] if parts else ""
            path = urlsplit(parts[1]).path if len(parts) >= 2 else ""
            # URL 解码请求行 + 报文体（log4j 等载荷经 URL 编码）
            raw = line + "\n" + body.decode("utf-8", "ignore")
            decoded = unquote_plus(raw)
            hit = _match_exploit(method, path, decoded + "\n" + raw, body)
            if hit:
                results.append((txn, method, path, line, decoded, hit))
        return results

    def detect(self, stream):
        matches = self._iter_request_matches(stream)
        if not matches:
            return None
        # 取置信度最高的一条作为流级识别结果
        _txn, _m, _p, _line, _dec, (family, behavior, conf, ev) = max(
            matches, key=lambda x: x[5][2])
        label = CONFIDENCE_HIGH if conf >= 0.85 else CONFIDENCE_MEDIUM
        return DetectionResult(
            self.name, conf, label,
            [f"{family}: {behavior}", f"命中特征: {ev}"],
            {"family": family},
        )

    def analyze(self, stream, context: AnalysisContext):
        records = []
        for txn, method, path, line, decoded, (family, behavior, conf, ev) in \
                self._iter_request_matches(stream):
            client_ip, _cp = txn.client
            server_ip, server_port = txn.server
            payload = decoded if len(decoded) <= 4000 else decoded[:4000]
            resp = txn.response.body.decode("utf-8", "ignore")[:2000] if txn.response else None
            label = CONFIDENCE_HIGH if conf >= 0.85 else CONFIDENCE_MEDIUM
            rec = AnalysisRecord(
                analyzer=self.name,
                stream_id=stream.stream_id,
                http_transaction_id=f"{stream.stream_id}#tx{txn.index:03d}",
                timestamp=txn.start_time,
                request_time=txn.request_time,
                response_time=txn.response_time,
                last_packet_time=txn.last_packet_time,
                duration_ms=txn.duration_ms,
                packet_start=txn.packet_start,
                packet_end=txn.packet_end,
                method=method or None,
                uri=path or None,
                src_ip=client_ip or None,
                dst_ip=server_ip or None,
                client_ip=client_ip or None,
                server_ip=server_ip or None,
                server_port=server_port or None,
                raw_src_ip=(txn.request.src_ip if txn.request else None),
                raw_dst_ip=(txn.request.dst_ip if txn.request else None),
                logical_direction="request+response" if resp else "request",
                request=payload,
                response=resp,
                decoded_command=payload,
                decoded_response=resp,
                content_preview=make_preview(payload),
                content_sha256=content_sha256(payload),
                content_type="web_exploit",
                decode_status=DECODE_TEXT,
                is_valid_target_flow=True,
                decrypt_status=DECRYPT_SUCCESS,
                confidence=label,
                detect_confidence=label,
                risk_level=RISK_HIGH,
                risk_score=90,
                behavior_tags=[behavior],
                evidence_excerpt=ev,
                primary_family=family,
                candidate_families=[family],
                family_confidence=label,
                family_evidence=f"命中特征: {ev}",
                analyst_note=f"检测到 {family}（{behavior}）",
            )
            # 上传/写入的脚本体若是 .NET/IIS 或 PHP 常驻内存马，附研判结论。写入
            # family_evidence（规则引擎注解会覆盖 analyst_note/evidence_excerpt，此字段不覆盖）。
            if family == "Webshell上传":
                from wsat.report.memshell import analyze_memshell, format_verdict
                verdict = format_verdict(analyze_memshell(txn.request.body if txn.request else b""))
                if verdict:
                    rec.family_evidence += "；内存马研判: " + verdict.splitlines()[0]
            records.append(rec)
        return records
