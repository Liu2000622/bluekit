# -*- coding: utf-8 -*-
"""新增 webshell / HTTP/TCP 隧道插件。"""

import base64
import binascii
import gzip
import re
import zlib
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from analyzers.base import AnalysisContext, AnalyzerPlugin, DetectionResult
from analysis_record import (
    AnalysisRecord,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DECRYPT_SUCCESS,
    DECODE_TEXT,
    RISK_HIGH,
    content_sha256,
    make_preview,
)
from http_transactions import iter_http_transactions
from pcap_utils import split_http_message
from webshell_crypto import iter_http_messages


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
            if decoded and (
                ("ini_set" in decoded and "set_time_limit" in decoded)
                or "eval(" in decoded
                or "assert(" in decoded
                or "system(" in decoded
                or "$_post" in decoded
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
        decoded = []
        for key, value in _all_pairs(headers, body):
            decoded.append(f"{key}=" + " | ".join(_decode_candidates(value)))
        response = _response(stream)
        if response:
            rhead, rbody = split_http_message(response)
            rtext = _http_entity_text(rhead, rbody)
            runs = _b64_runs_text(rtext)
            if runs:
                decoded.append("response_b64=" + "\n".join(runs[:5]))
        return [_record(self, stream, request, "\n".join(decoded), CONFIDENCE_MEDIUM)]


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
    name = "chisel"
    category = "tunnel"
    requires_key = False
    can_decrypt = False

    def detect(self, stream):
        blob = b"\n".join(_flows(stream)).lower()
        if b"sec-websocket-protocol: chisel-v3" in blob or b"ssh-chisel-v3" in blob:
            return DetectionResult(
                self.name, 0.96, CONFIDENCE_HIGH,
                ["命中 chisel-v3 WebSocket/SSH 握手指纹"],
            )
        return None

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
            records.append(rec)
        return records
