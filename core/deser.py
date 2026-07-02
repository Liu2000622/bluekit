"""Java 反序列化数据识别 —— 离线、只读分析，不执行任何字节码。

输入可以是：原始字节、Base64、Hex。自动识别序列化头，扫描已知 gadget 特征类名。
"""
from __future__ import annotations

import base64
import re

# Java 序列化流魔数：0xAC 0xED 0x00 0x05
MAGIC = bytes([0xAC, 0xED, 0x00, 0x05])
MAGIC_B64_PREFIX = "rO0AB"          # base64(0xACED0005...) 常见前缀
MAGIC_HEX_PREFIX = "aced0005"

# 常见反序列化利用链 / 危险类特征（ysoserial 等）
GADGET_SIGNATURES = [
    ("CommonsCollections", rb"org/apache/commons/collections"),
    ("CommonsBeanutils", rb"org/apache/commons/beanutils"),
    ("Groovy", rb"org/codehaus/groovy/runtime"),
    ("Spring", rb"org/springframework/(core|beans|aop)"),
    ("Rome", rb"com/sun/syndication|rome"),
    ("JdbcRowSet/JNDI", rb"com/sun/rowset/JdbcRowSetImpl"),
    ("TemplatesImpl", rb"com/sun/org/apache/xalan/.*TemplatesImpl"),
    ("Hibernate", rb"org/hibernate"),
    ("C3P0", rb"com/mchange/v2/c3p0"),
    ("BeanShell", rb"bsh/"),
    ("Clojure", rb"clojure/"),
    ("Fastjson", rb"com\.alibaba\.fastjson|autoTypeSupport|@type"),
    ("TransformerChain", rb"InvokerTransformer|ChainedTransformer|InstantiateTransformer"),
    ("Runtime/exec", rb"java/lang/Runtime|ProcessBuilder|getRuntime"),
    ("TemplatesEval", rb"newTransformer|getOutputProperties|defineClass"),
    ("URLClassLoader", rb"java/net/URLClassLoader"),
    ("JNDI/LDAP", rb"javax/naming|InitialContext|ldap://|rmi://"),
]


def to_bytes(text: str) -> bytes:
    """把用户输入（base64 / hex / 原文）尽力转成字节。"""
    t = text.strip()
    # hex?
    hex_candidate = re.sub(r"[\s:0x]", "", t, flags=re.I)
    if re.fullmatch(r"[0-9a-fA-F]+", hex_candidate) and len(hex_candidate) % 2 == 0 \
            and hex_candidate.lower().startswith(MAGIC_HEX_PREFIX):
        return bytes.fromhex(hex_candidate)
    # base64?
    if t.startswith(MAGIC_B64_PREFIX) or re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", t):
        try:
            b = base64.b64decode(re.sub(r"\s", "", t) + "===", validate=False)
            if b[:2] == MAGIC[:2]:
                return b
        except Exception:
            pass
    # 原始 latin-1 字节
    return t.encode("latin-1", "ignore")


def analyze(text: str) -> str:
    data = to_bytes(text)
    lines = []
    lines.append(f"字节长度: {len(data)}")
    if data[:4] == MAGIC:
        lines.append("✅ 识别为 Java 序列化流 (magic AC ED 00 05)")
    elif data[:2] == MAGIC[:2]:
        lines.append("⚠️ 疑似 Java 序列化流（magic 前两字节匹配，版本号异常）")
    else:
        lines.append("❌ 未识别到 Java 序列化魔数（可能不是 Java 反序列化数据）")

    # 抽取可打印的类名 / 字符串
    strings = _printable_strings(data, minlen=4)
    class_like = [s for s in strings if re.search(r"[a-zA-Z]+(/|\.)[a-zA-Z]", s)]

    # gadget 匹配
    hits = []
    for name, pat in GADGET_SIGNATURES:
        if re.search(pat, data, re.I):
            hits.append(name)
    lines.append("")
    if hits:
        lines.append("🚨 命中 gadget / 危险特征:")
        for h in hits:
            lines.append(f"    - {h}")
    else:
        lines.append("未命中已知 gadget 特征（不代表安全，可能是自定义链或加密封装）")

    lines.append("")
    lines.append(f"引用的类 / 路径（前 40）:")
    for s in class_like[:40]:
        lines.append(f"    {s}")
    if not class_like:
        lines.append("    （未抽到明显类名）")
    return "\n".join(lines)


def _printable_strings(data: bytes, minlen: int = 4) -> list[str]:
    out, cur = [], []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    # 去重保序
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq
