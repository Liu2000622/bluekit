# -*- coding: utf-8 -*-
"""
统一分析记录结构与解密有效性校验。

三个分析器（suo5 / 哥斯拉 / 冰蝎）统一产出 AnalysisRecord，携带：
  - P0 误报过滤字段：decrypt_status / is_valid_target_flow / confidence / filter_reason
  - P1 风险标注字段：behavior_tags / risk_level / risk_score / matched_rules /
                      evidence_excerpt / analyst_note

report_writer 依据 is_valid_target_flow 将记录分流到「原始解密结果」或「过滤/失败明细」。
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

# --- 解密状态常量 ---
DECRYPT_SUCCESS = "success"
DECRYPT_FAILED = "failed"
SUSPECTED_FALSE_POSITIVE = "suspected_false_positive"
HANDSHAKE_VALIDATION_FAILED = "handshake_validation_failed"

# --- 置信度常量 ---
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# --- 风险等级常量 ---
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"
RISK_INFO = "info"

# --- 解码分层状态（decode_status；区别于加解密层面的 decrypt_status） ---
DECODE_TEXT = "text"                    # 可读明文（命令/代码/JSON）→ 成功解密结果
DECODE_BINARY_PAYLOAD = "binary_payload"  # Java class / 序列化 / PE 等结构化二进制载荷
DECODE_PARTIAL = "partially_decoded"    # base64/JSON 内嵌未继续解码
DECODE_ERROR = "decode_error"           # UTF-8 解码失败
DECODE_GARBLED = "garbled"              # 明显乱码（密钥错误/非目标）
DECODE_FAILED = "failed"                # 无内容 / 解密失败

# --- Webshell / 隧道家族标识 ---
FAMILY_UNKNOWN = "unknown"


@dataclass
class AnalysisRecord:
    """一条分析记录：一次请求/响应的解密与研判结果。"""
    analyzer: str                              # suo5 / godzilla / behinder
    stream_id: str = ""                        # 'ip:port <-> ip:port' 或流索引
    timestamp: Optional[float] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    uri: Optional[str] = None
    direction: Optional[str] = None            # Request / Response
    request: Optional[str] = None              # 解密后的请求明文
    response: Optional[str] = None             # 解密后的响应明文
    content: Optional[str] = None              # 单向内容（冰蝎逐包时使用）

    # --- P0：误报过滤 ---
    decrypt_status: str = DECRYPT_SUCCESS
    is_valid_target_flow: bool = True
    confidence: str = CONFIDENCE_HIGH
    filter_reason: Optional[str] = None

    # --- P1：风险标注（阶段2填充） ---
    behavior_tags: List[str] = field(default_factory=list)
    risk_level: str = RISK_INFO
    risk_score: int = 0
    matched_rules: List[str] = field(default_factory=list)
    evidence_excerpt: Optional[str] = None
    analyst_note: Optional[str] = None

    # --- 事务级定位（HTTP 事务粒度：一次请求/响应 = 一条记录） ---
    http_transaction_id: Optional[str] = None
    method: Optional[str] = None
    packet_start: Optional[int] = None         # 事务首包在 PCAP 中的序号
    packet_end: Optional[int] = None           # 事务末包序号
    request_time: Optional[float] = None
    response_time: Optional[float] = None
    last_packet_time: Optional[float] = None
    duration_ms: Optional[float] = None

    # --- IP 角色规范化（HTTP webshell：区分攻击端 / 被控 Web 服务端） ---
    client_ip: Optional[str] = None            # 发起 HTTP 请求方（通常为攻击端）
    server_ip: Optional[str] = None            # Web 服务端（被控 webshell 所在主机）
    server_port: Optional[int] = None
    raw_src_ip: Optional[str] = None           # 保留原始包方向
    raw_dst_ip: Optional[str] = None
    logical_direction: Optional[str] = None    # request / response

    # --- 内容分层（不再截断覆盖：Excel 放摘要，完整内容落地 artifact） ---
    content_preview: Optional[str] = None
    content_full_ref: Optional[str] = None
    content_sha256: Optional[str] = None
    # --- 二进制文件载荷（class/gzip/序列化/PE 等）：保留原始字节 + 落盘为对应类型文件 ---
    raw_payload: Optional[bytes] = None
    payload_file: Optional[str] = None
    payload_type: Optional[str] = None
    decoded_command: Optional[str] = None      # 结构化后的指令
    decoded_response: Optional[str] = None      # 结构化后的响应

    # --- 解码分层判定 ---
    decode_layer: Optional[str] = None         # 解码到第几层（如 base64->aes->gzip）
    content_type: Optional[str] = None
    readable_ratio: float = 0.0
    is_binary: bool = False
    is_garbled: bool = False
    decode_status: str = DECODE_TEXT
    next_decode_hint: Optional[str] = None

    # --- 检测置信度（识别层，区别于攻击风险 risk_level） ---
    detect_confidence: Optional[str] = None

    # --- 家族识别（避免把 Behinder/Rebeyond 误标为 Godzilla） ---
    primary_family: Optional[str] = None
    candidate_families: List[str] = field(default_factory=list)
    family_confidence: Optional[str] = None
    family_evidence: Optional[str] = None

    def primary_text(self) -> str:
        """返回用于规则匹配 / 展示的主要明文（请求+响应+内容拼接）。"""
        parts = [p for p in (self.request, self.response, self.content) if p]
        return "\n".join(parts)


# --- 解密有效性校验（P0 误报过滤核心） ---

# 仅在「数据起始处」出现才算数的二进制魔数：单独在大段乱码里偶然命中 2~4 字节的
# 概率很高，只有出现在偏移 0 才有意义，据此避免错误密钥解出的乱码被误判为有效。
_START_MARKERS = (
    b"\xac\xed\x00\x05",    # Java 序列化流头 (STREAM_MAGIC 0xACED + VERSION 5)
    b"\xca\xfe\xba\xbe",    # Java .class 文件魔数（冰蝎/哥斯拉加载器类载荷）
    b"MZ",                  # Windows PE / .NET payload（哥斯拉 C# 载荷）
)

# 出现在任意位置即可的可读结构标记（足够长，随机命中概率可忽略）
_STRUCTURED_MARKERS = (
    b"methodName", b"parameters", b"session",
)


def readable_ratio(data: bytes) -> float:
    """
    估算字节串中「可读字符」比例：ASCII 可打印、常见空白、以及能被 UTF-8
    正确解码的多字节字符（如中文）都算可读；解码失败的字节算不可读。
    返回 0.0~1.0。空输入返回 0.0。
    """
    if not data:
        return 0.0
    text = data.decode("utf-8", "replace")
    if not text:
        return 0.0
    readable = 0
    for ch in text:
        o = ord(ch)
        if ch in "\t\n\r" or 0x20 <= o < 0x7f or o >= 0xa0:
            readable += 1
    # 解码失败会引入替换符 �，已在上面按“不可读”计入（o=0xFFFD>=0xa0
    # 会被误判为可读，这里显式扣除）
    replacement = text.count("�")
    readable -= replacement
    return max(0.0, readable) / len(text)


def _is_common_script(o: int) -> bool:
    """码位是否属于 webshell 取证内容中常见的脚本块。"""
    return (
        o < 0x80                        # ASCII
        or 0xA0 <= o <= 0xFF            # Latin-1 补充（重音拉丁）
        or 0x0370 <= o <= 0x04FF        # 希腊 + 西里尔
        or 0x3000 <= o <= 0x30FF        # CJK 标点 + 假名
        or 0x3400 <= o <= 0x9FFF        # CJK 扩展A + 统一表意
        or 0xAC00 <= o <= 0xD7A3        # 谚文
        or 0xF900 <= o <= 0xFAFF        # CJK 兼容
        or 0xFF00 <= o <= 0xFFEF        # 全角
    )


def exotic_ratio(text: str) -> float:
    """
    生僻块字符占比：真实命令/代码为纯 ASCII，中文集中在 CJK 块，占比≈0；
    错误密钥解出的乱码散落在 IPA/Thaana/符号等大量互不相关的生僻块，占比高。
    """
    if not text:
        return 0.0
    exotic = sum(1 for ch in text if ord(ch) >= 0x80 and not _is_common_script(ord(ch)))
    return exotic / len(text)


def _plaintext_ratios(text):
    """
    一次遍历算 (可读率, 生僻率, 控制字符率)，等价于分别调用 readable_ratio /
    exotic_ratio 加控制字符统计，但只扫描一遍、每字符只取一次 ord —— 大 body
    的解密有效性判定原本三次逐字符扫描是主要性能瓶颈。
    """
    n = len(text)
    if not n:
        return 0.0, 0.0, 0.0
    readable = exotic = control = 0
    for ch in text:
        o = ord(ch)
        if ch in "\t\n\r":
            readable += 1
        elif o < 0x20:
            control += 1
        elif o < 0x7f:
            readable += 1
        elif o >= 0xa0 and ch != "�":
            readable += 1
        if o >= 0x80 and not _is_common_script(o):
            exotic += 1
    return readable / n, exotic / n, control / n


def looks_like_valid_plaintext(data, min_ratio: float = 0.75,
                               max_exotic: float = 0.10) -> bool:
    """
    判断一段解密结果是否像「有效的结构化/可读明文」，用于区分真实目标流量
    与假握手/错误密钥产生的乱码。

    判据：
      1. 含已知结构化标记（Java 序列化头、webshell 关键字段名等）→ 有效；
      2. 生僻块字符占比过高 → 乱码，无效（拦截 XOR/AES 错误密钥的伪解密）；
      3. 否则要求可读字符比例达到阈值。
    """
    if data is None:
        return False
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass") if _has_surrogate(data) else data.encode("utf-8", "ignore")
    if not isinstance(data, (bytes, bytearray)):
        return False
    if len(data) == 0:
        return False

    data = bytes(data)
    for marker in _START_MARKERS:
        if data.startswith(marker):
            return True
    for marker in _STRUCTURED_MARKERS:
        if marker in data:
            return True

    # 比例类判据（可读率/生僻率/控制字符）只需代表性采样 + 单次遍历：真实明文与错误
    # 密钥乱码的字符分布在前若干 KB 即可判定，避免对 MB 级 body 多次逐字符 ord。
    sample = data[:4096]
    text = sample.decode("utf-8", "replace")
    if not text:
        return False
    readable, exotic, control = _plaintext_ratios(text)
    if exotic > max_exotic:
        return False
    # 控制字符判据：真实命令/代码/JSON 几乎无控制字符（除 \t\n\r），
    # 错误密钥解出的乱码常含散落的 \x00/\x01/\x14 等控制字节。
    if control > 0.05:
        return False
    return readable >= min_ratio


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _to_bytes(data) -> Optional[bytes]:
    """把 str/bytes 统一为 bytes；无法处理返回 None。"""
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        if _has_surrogate(data):
            return data.encode("utf-8", "surrogatepass")
        return data.encode("utf-8", "ignore")
    return None


# 结构化二进制载荷魔数 → (content_type, 下一步分析建议)
_BINARY_MARKERS = (
    (b"\xca\xfe\xba\xbe", "java_class", "Java .class 字节码，可用 jd-gui/CFR 反编译还原逻辑"),
    (b"\xac\xed\x00\x05", "java_serialized", "Java 序列化流，可用 SerializationDumper 解析"),
    (b"PK\x03\x04", "zip_jar", "ZIP/JAR 归档，可解压后逐类分析"),
    (b"MZ", "pe_dotnet", "PE/.NET 载荷，可用 dnSpy/ILSpy 分析"),
)

# 常见脚本/命令关键字，用于给可读明文再细分 content_type
_SCRIPT_HINTS = (
    ("php", re.compile(r"<\?php|eval\(|assert\(|base64_decode\(|system\(", re.I)),
    ("jsp", re.compile(r"<%|Runtime\.getRuntime|ProcessBuilder|javax\.", re.I)),
    ("aspx", re.compile(r"<%@|Response\.Write|System\.Diagnostics", re.I)),
    ("shell", re.compile(r"\b(whoami|uname|id|ifconfig|ipconfig|cat\s+/etc|net\s+user)\b", re.I)),
)


def classify_content(data) -> dict:
    """
    对一段「解密/解码后的内容」做分层判定，供报告按可读明文 / 二进制载荷 /
    半解码 / 乱码 / 解码失败分流，避免把乱码、字节码 payload 误当有效明文。

    返回 dict：content_type / readable_ratio / is_binary / is_garbled /
              decode_status / next_decode_hint。
    """
    result = {
        "content_type": "unknown",
        "readable_ratio": 0.0,
        "is_binary": False,
        "is_garbled": False,
        "decode_status": DECODE_FAILED,
        "next_decode_hint": "",
    }
    raw = _to_bytes(data)
    if not raw:
        return result

    ratio = readable_ratio(raw)
    result["readable_ratio"] = round(ratio, 3)

    # 1) 结构化二进制载荷（Java class / 序列化 / PE / ZIP）——起始魔数判定
    for marker, ctype, hint in _BINARY_MARKERS:
        if raw.startswith(marker):
            result.update(content_type=ctype, is_binary=True,
                          decode_status=DECODE_BINARY_PAYLOAD, next_decode_hint=hint)
            return result

    text = raw.decode("utf-8", "replace")
    stripped = text.strip()
    lower = text.lower()
    ctrl = sum(1 for ch in text if ord(ch) < 0x20 and ch not in "\t\n\r")
    ctrl_ratio = ctrl / len(text)
    degraded = ("�" in text) or ctrl_ratio > 0.02

    # 1b) Java 字节码/类载荷：解密返回值经有损转码后魔数（CAFEBABE）可能已丢，
    #     用「斜杠形类路径」常量池特征兜底。合法可读文本用点号(java.lang.)，类常量池
    #     用斜杠(java/lang/)，据此区分，避免把提到 Java 的正常响应误判为载荷。
    if "net/rebeyond/behinder" in lower or "getbasicsinfo" in lower:
        result.update(content_type="java_class", is_binary=True,
                      decode_status=DECODE_BINARY_PAYLOAD,
                      next_decode_hint="Behinder Java 载荷（魔数经转码丢失），可用 jd-gui/CFR 反编译")
        return result
    if degraded and any(tok in text for tok in ("java/lang/", "Ljava/", "java/io/", "java/util/", "/payload/")):
        result.update(content_type="java_class", is_binary=True,
                      decode_status=DECODE_BINARY_PAYLOAD,
                      next_decode_hint="Java 字节码/类载荷（魔数经转码丢失），可用 jd-gui/CFR 反编译")
        return result

    # 2) JSON（可读结构）或 JSON 内嵌未解码 base64
    if stripped[:1] in ("{", "["):
        try:
            json.loads(stripped)
            result.update(content_type="json", decode_status=DECODE_TEXT)
            return result
        except Exception:
            if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", stripped):
                result.update(content_type="json_base64", decode_status=DECODE_PARTIAL,
                              next_decode_hint="JSON 字段疑似含 base64，需二次解码")
                return result

    # 3) 纯 base64 长串，未继续解码
    if len(stripped) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", stripped):
        result.update(content_type="base64", decode_status=DECODE_PARTIAL,
                      next_decode_hint="疑似 base64，需二次解码后再判定")
        return result

    # 4) 乱码 / 二进制：生僻块字符占比高、控制字符多、或可读率过低
    if exotic_ratio(text) > 0.10 or ctrl_ratio > 0.05 or ratio < 0.60:
        result.update(content_type="garbled", is_garbled=True,
                      is_binary=ctrl_ratio > 0.30,
                      decode_status=DECODE_GARBLED,
                      next_decode_hint="可读率低/生僻字符或控制字节多，疑似密钥错误或未识别加密")
        return result

    # 5) 可读明文——再细分脚本/命令类型
    ctype = "text"
    for name, rx in _SCRIPT_HINTS:
        if rx.search(text):
            ctype = name
            break
    result.update(content_type=ctype, decode_status=DECODE_TEXT)
    return result


def make_preview(text, limit: int = 400) -> Optional[str]:
    """生成 Excel 展示用摘要：保留前 limit 字符，超出以标记提示完整内容见 artifact。"""
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f" …[已截断，共 {len(text)} 字符，完整内容见 artifact]"


def content_sha256(data) -> Optional[str]:
    """计算内容 SHA-256，作为完整证据的可校验指纹。"""
    raw = _to_bytes(data)
    if raw is None:
        return None
    return hashlib.sha256(raw).hexdigest()
