"""tshark 封装 —— 内嵌 Wireshark 分析引擎（离线）。

tshark 是 Wireshark 的命令行版，拥有同一套协议解析器和 display filter 语法。
本模块只负责：定位 tshark 二进制、构造命令、跑命令收结果。GUI 层做展示。

tshark 二进制查找顺序：
  1) 随包 portable：<app>/third_party/tshark/tshark(.exe)
  2) 环境变量 BLUEKIT_TSHARK
  3) 常见安装路径（Windows: Program Files\\Wireshark；*nix: PATH）
"""
from __future__ import annotations

import os
import shutil
import subprocess

from core.paths import find_resource


def _candidates() -> list[str]:
    exe = "tshark.exe" if os.name == "nt" else "tshark"
    cands = [
        find_resource(os.path.join("third_party", "tshark", exe)) or "",
        os.environ.get("BLUEKIT_TSHARK", ""),
    ]
    if os.name == "nt":
        cands += [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
    else:
        cands += ["/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"]
    which = shutil.which("tshark")
    if which:
        cands.append(which)
    return [c for c in cands if c]


def find_tshark() -> str | None:
    for c in _candidates():
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def find_wireshark_gui() -> str | None:
    """定位 Wireshark GUI，用于"在 Wireshark 中打开"。优先用随包内嵌的。"""
    exe = "Wireshark.exe" if os.name == "nt" else "Wireshark"
    bundled = find_resource(os.path.join("third_party", "tshark", exe))
    if bundled:
        return bundled
    if os.name == "nt":
        for p in (r"C:\Program Files\Wireshark\Wireshark.exe",
                  r"C:\Program Files (x86)\Wireshark\Wireshark.exe"):
            if os.path.isfile(p):
                return p
        return shutil.which("Wireshark")
    for p in ("/Applications/Wireshark.app/Contents/MacOS/Wireshark",
              "/usr/bin/wireshark", "/usr/local/bin/wireshark"):
        if os.path.isfile(p):
            return p
    return shutil.which("wireshark")


class TsharkNotFound(RuntimeError):
    pass


def _run(args: list[str], timeout: int = 120) -> str:
    bin_ = find_tshark()
    if not bin_:
        raise TsharkNotFound(
            "未找到 tshark。请把 portable Wireshark 放到 "
            "third_party/tshark/，或安装 Wireshark，或设置环境变量 BLUEKIT_TSHARK。")
    cmd = [bin_] + args
    # PyInstaller 无控制台窗口下：避免弹黑框、补 stdin，防止部分子命令异常
    creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace",
                           stdin=subprocess.DEVNULL,
                           creationflags=creationflags)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"tshark 超时（>{timeout}s）")
    if p.returncode != 0 and not p.stdout:
        raise RuntimeError(p.stderr.strip() or f"tshark 退出码 {p.returncode}")
    return p.stdout


def version() -> str:
    return _run(["-v"], timeout=15).splitlines()[0] if find_tshark() else "tshark 未安装"


def protocol_hierarchy(pcap: str) -> str:
    """协议分层统计（Wireshark 的 Statistics > Protocol Hierarchy）。"""
    return _run(["-r", pcap, "-q", "-z", "io,phs"])


def conversations(pcap: str) -> str:
    """会话列表（IP conversations）。"""
    return _run(["-r", pcap, "-q", "-z", "conv,ip"])


def packet_list(pcap: str, display_filter: str = "", limit: int = 500) -> str:
    """数据包列表，支持 Wireshark display filter 语法。"""
    args = ["-r", pcap, "-n"]
    if display_filter.strip():
        args += ["-Y", display_filter.strip()]
    # 精简列：编号/时间/源/目的/协议/长度/信息
    args += ["-T", "fields",
             "-e", "frame.number", "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
             "-e", "frame.len", "-e", "_ws.col.Info",
             "-E", "separator=\t"]
    out = _run(args)
    rows = out.splitlines()
    header = "No.\tTime\tSource\tDest\tProto\tLen\tInfo"
    if len(rows) > limit:
        rows = rows[:limit] + [f"... （已截断，仅显示前 {limit} 条，用过滤器缩小范围）"]
    return header + "\n" + "\n".join(rows)


PACKET_COLUMNS = ["No.", "Time", "Source", "Dest", "Proto", "Len", "Info"]


def packet_rows(pcap: str, display_filter: str = "", limit: int = 1000):
    """结构化取包，供表格(Treeview)渲染。

    返回 (rows, streams, truncated)：
      rows    —— list[tuple]，每行对应 PACKET_COLUMNS
      streams —— list[str]，每行的 tcp.stream 号（用于双击追踪流），无则 ""
      truncated —— 是否被 limit 截断
    """
    args = ["-r", pcap, "-n"]
    if display_filter.strip():
        args += ["-Y", display_filter.strip()]
    args += ["-T", "fields",
             "-e", "frame.number", "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
             "-e", "frame.len", "-e", "tcp.stream", "-e", "_ws.col.Info",
             "-E", "separator=\t", "-E", "occurrence=f"]
    out = _run(args)
    rows, streams = [], []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            parts += [""] * (8 - len(parts))
        no, t, src, dst, proto, ln, stream, info = parts[:8]
        rows.append((no, t, src, dst, proto, ln, info))
        streams.append(stream)
    truncated = len(rows) > limit
    if truncated:
        rows, streams = rows[:limit], streams[:limit]
    return rows, streams, truncated


def build_filter(src: str = "", dst: str = "", proto: str = "",
                 port: str = "", contains: str = "", url: str = "") -> str:
    """按表单字段拼 Wireshark display filter。"""
    parts = []
    if proto.strip():
        parts.append(proto.strip().lower())
    if src.strip():
        parts.append(f"ip.src == {src.strip()}")
    if dst.strip():
        parts.append(f"ip.dst == {dst.strip()}")
    if port.strip().isdigit():
        parts.append(f"tcp.port == {port.strip()} || udp.port == {port.strip()}")
    if url.strip():
        u = url.strip().replace('"', '\\"')
        # 同时匹配 host / uri / 完整 URL，域名或路径片段都能命中
        parts.append(f'http.host contains "{u}" || http.request.uri contains "{u}" '
                     f'|| http.request.full_uri contains "{u}"')
    if contains.strip():
        esc = contains.strip().replace('"', '\\"')
        parts.append(f'frame contains "{esc}"')
    # 含 || 的组要加括号保证优先级
    parts = [f"({p})" if "||" in p else p for p in parts]
    return " && ".join(parts)


# 常用过滤器预设（下拉直接选）
FILTER_PRESETS = [
    ("全部", ""),
    ("HTTP 请求", "http.request"),
    ("HTTP 响应", "http.response"),
    ("DNS 查询", "dns.flags.response == 0"),
    ("TCP 建连(SYN)", "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
    ("含 union select(疑似SQLi)", 'frame contains "union select"'),
    ("含 /bin/ 或 cmd.exe(疑似RCE)", 'frame matches "/bin/|cmd\\.exe"'),
    ("MySQL", "mysql"),
    ("Redis", "redis"),
    ("RDP", "rdp || tpkt"),
    ("ICMP", "icmp"),
]


def follow_tcp_stream(pcap: str, stream_index: int = 0) -> str:
    """追踪 TCP 流（Follow TCP Stream）。"""
    return _run(["-r", pcap, "-q", "-z", f"follow,tcp,ascii,{stream_index}"])


def http_requests(pcap: str) -> str:
    """快速抽取所有 HTTP 请求行（应急最常看的）。"""
    args = ["-r", pcap, "-n", "-Y", "http.request",
            "-T", "fields",
            "-e", "ip.src", "-e", "http.request.method",
            "-e", "http.host", "-e", "http.request.uri",
            "-e", "http.user_agent", "-E", "separator=\t"]
    out = _run(args)
    return "src\tmethod\thost\turi\tuser_agent\n" + out


def open_in_wireshark(pcap: str) -> bool:
    gui = find_wireshark_gui()
    if not gui:
        return False
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW（GUI 自己开窗）
    subprocess.Popen([gui, "-r", pcap], stdin=subprocess.DEVNULL, **kw)
    return True


def bundled_wireshark() -> bool:
    """是否用的是随包内嵌的 Wireshark（而非本地安装）。"""
    exe = "Wireshark.exe" if os.name == "nt" else "Wireshark"
    return bool(find_resource(os.path.join("third_party", "tshark", exe)))
