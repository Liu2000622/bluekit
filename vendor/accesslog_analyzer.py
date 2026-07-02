#!/usr/bin/env python3
"""accesslog-analyzer — single-file build for intranet deployment.

直接运行：
    python3 accesslog-analyzer.py

依赖：仅 Python 3.7+ 标准库（gzip/json/re/pathlib/...），无任何 pip 包。
全程无外网调用，适合气隙网络 / 内网堡垒机。

要修改路径或阈值，找到本文件中 `CONFIG —` 那段常量直接编辑。
"""
from __future__ import annotations

import csv
import gzip
import html
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta  # bluekit: 补 timedelta（原 dist 漏导入）
from pathlib import Path
from typing import Iterable, Iterator, Optional
from urllib.parse import unquote_plus



# ========================================================================
# === rules/patterns.py
# ========================================================================

"""Simplified rule set — only path-traversal payloads.

Behavioral rules (error bursts, dir enumeration) live in detectors.py.
New / baseline-diff URL detection lives in anomaly.py.
"""


HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Only one payload signature is kept: classic path / directory traversal.
# Covers raw "../", URL-encoded "%2e%2e/", "..%2f", "%252e%252e" (double enc),
# Windows "..\", and obvious sensitive-file probes.
URI_RULES = [
    ("PATH-TRAVERSAL", HIGH,
     r"(?:\.\./){2,}"
     r"|(?:%2e%2e[%2f%5c/\\]){2,}"
     r"|(?:%252e%252e){2,}"
     r"|(?:\.\.\\){2,}"
     r"|/etc/(?:passwd|shadow|hosts|self/environ)"
     r"|(?:c:\\\\?|c:/)(?:windows|winnt)/",
     "URL contains path-traversal sequence"),
]

# UA rules dropped entirely — too noisy on Tomcat / common-log formats that
# don't even carry a User-Agent field.
UA_RULES: list = []

SEVERITY_WEIGHT = {HIGH: 10, MEDIUM: 4, LOW: 1}


def _compile(rules):
    return [(rid, sev, re.compile(pat, re.IGNORECASE), desc)
            for rid, sev, pat, desc in rules]


COMPILED_URI = _compile(URI_RULES)
COMPILED_UA = _compile(UA_RULES)


# ========================================================================
# === parser.py
# ========================================================================

"""Access log parser — handles multiple common formats automatically.

A line is first tried against the original strict nginx format (the one this
tool was built for); if that fails, a token-based auto-parser kicks in. The
auto-parser identifies fields by *content* rather than fixed position, so it
copes with:

  - nginx custom log_format (with upstream_addr / ups_resp_time / request_time)
  - Apache / Tomcat "combined" log_format (with referer + UA)
  - Apache / Tomcat "common" log_format (no referer / UA)
  - Variants with X-Forwarded-For, extra response time fields, etc.

It does not assume any particular filename or extension — each line is
classified independently.
"""


# Original strict format (fast path). If this matches, no need to tokenize.
LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>.*?)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<body_bytes_sent>\d+|-)\s+'
    r'"(?P<http_referer>.*?)"\s+'
    r'"(?P<http_user_agent>.*?)"\s+'
    r'"(?P<http_x_forwarded_for>.*?)"\s+'
    r'(?P<upstream_addr>\S+)\s+'
    r'ups_resp_time:\s*(?P<upstream_response_time>\S+)\s+'
    r'request_time:\s*(?P<request_time>\S+)\s*$'
)

REQUEST_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>HTTP/\S+))?$'
)

# Token classifiers used by the auto-parser.
_IP4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_IP6_RE = re.compile(r'^[0-9a-fA-F:]+$')
_IP_PORT_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$')
_TIME_RE = re.compile(
    r'^\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}$'
)
_UA_HINTS = re.compile(
    r'Mozilla|MSIE|Trident|AppleWebKit|Chrome|Safari|Firefox|Edge|Opera|'
    r'curl|Wget|python-requests|Go-http-client|libwww-perl|Java/|'
    r'Apache-HttpClient|okhttp|sqlmap|nikto|nmap|nuclei|xray|gobuster|'
    r'dirsearch|masscan|Bot|Spider|Crawler',
    re.IGNORECASE,
)


@dataclass
class LogEntry:
    raw: str
    line_no: int
    remote_addr: str
    remote_user: str
    time_local: str
    timestamp: Optional[datetime]
    request: str
    method: str
    uri: str
    path: str
    query: str
    decoded_uri: str
    protocol: str
    status: int
    body_bytes_sent: int
    http_referer: str
    http_user_agent: str
    http_x_forwarded_for: str
    upstream_addr: str
    upstream_response_time: Optional[float]
    request_time: Optional[float]
    source_file: str = ""

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def is_server_error(self) -> bool:
        return self.status >= 500


def _parse_time(t: str) -> Optional[datetime]:
    try:
        return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_float(s: str) -> Optional[float]:
    if s in ("-", ""):
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _safe_decode(s: str) -> str:
    try:
        return unquote_plus(unquote_plus(s))
    except Exception:
        return s


def _build_request_parts(request: str) -> tuple[str, str, str, str, str, str]:
    """Return (method, uri, protocol, path, query, decoded_uri)."""
    rm = REQUEST_RE.match(request)
    if rm:
        method = rm.group("method")
        uri = rm.group("uri")
        protocol = rm.group("proto") or ""
    else:
        method = ""
        uri = request
        protocol = ""
    if "?" in uri:
        path, _, query = uri.partition("?")
    else:
        path, query = uri, ""
    return method, uri, protocol, path, query, _safe_decode(uri)


# --------------------------------------------------------------------------
# Strict-format fast path
# --------------------------------------------------------------------------

def _parse_strict(line: str, line_no: int) -> Optional[LogEntry]:
    m = LOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    method, uri, protocol, path, query, decoded = _build_request_parts(g["request"])
    bbs = g["body_bytes_sent"]
    return LogEntry(
        raw=line, line_no=line_no,
        remote_addr=g["remote_addr"],
        remote_user=g["remote_user"],
        time_local=g["time_local"],
        timestamp=_parse_time(g["time_local"]),
        request=g["request"],
        method=method, uri=uri, protocol=protocol,
        path=path, query=query, decoded_uri=decoded,
        status=int(g["status"]),
        body_bytes_sent=0 if bbs == "-" else int(bbs),
        http_referer=g["http_referer"],
        http_user_agent=g["http_user_agent"],
        http_x_forwarded_for=g["http_x_forwarded_for"],
        upstream_addr=g["upstream_addr"],
        upstream_response_time=_parse_float(g["upstream_response_time"]),
        request_time=_parse_float(g["request_time"]),
    )


# --------------------------------------------------------------------------
# Auto-parser
# --------------------------------------------------------------------------

def _tokenize(line: str) -> list[tuple[str, str]]:
    """Split into (text, kind) tokens. Kind is 'plain' | 'quoted' | 'bracketed'."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
            continue
        if c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                # tolerate escaped quotes
                if line[j] == '\\' and j + 1 < n:
                    j += 2
                else:
                    j += 1
            tokens.append((line[i + 1:j], "quoted"))
            i = j + 1 if j < n else n
        elif c == '[':
            close = line.find(']', i)
            if close == -1:
                j = i
                while j < n and not line[j].isspace():
                    j += 1
                tokens.append((line[i:j], "plain"))
                i = j
            else:
                tokens.append((line[i + 1:close], "bracketed"))
                i = close + 1
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            tokens.append((line[i:j], "plain"))
            i = j
    return tokens


def _is_ip(s: str) -> bool:
    if not s:
        return False
    if _IP4_RE.match(s):
        return True
    return ':' in s and len(s) >= 3 and bool(_IP6_RE.match(s))


def _is_status(s: str) -> bool:
    return s.isdigit() and 100 <= int(s) <= 599


def _is_float(s: str) -> bool:
    if s in ("-", ""):
        return False
    try:
        float(s)
        return True
    except ValueError:
        return False


def _looks_like_ua(s: str) -> bool:
    return bool(_UA_HINTS.search(s))


def _looks_like_referer(s: str) -> bool:
    return s.startswith(("http://", "https://", "//"))


def _looks_like_xff(s: str) -> bool:
    if s in ("-", "", "unknown"):
        return True
    parts = [p.strip() for p in s.split(",")]
    return bool(parts) and all(_is_ip(p) or p == "unknown" for p in parts)


def _parse_auto(line: str, line_no: int) -> Optional[LogEntry]:
    tokens = _tokenize(line)
    if len(tokens) < 5:
        return None

    # Mandatory: remote_addr (first plain IP)
    remote_addr = ""
    for t, k in tokens:
        if k == "plain" and _is_ip(t):
            remote_addr = t
            break
    if not remote_addr:
        return None

    # Mandatory: time_local (first bracketed token matching Apache time format)
    time_local = ""
    time_idx = -1
    for i, (t, k) in enumerate(tokens):
        if k == "bracketed" and _TIME_RE.match(t):
            time_local = t
            time_idx = i
            break
    if not time_local:
        return None

    # Mandatory: request (first quoted token after the time)
    request = ""
    request_idx = -1
    for i in range(time_idx + 1, len(tokens)):
        t, k = tokens[i]
        if k == "quoted":
            request = t
            request_idx = i
            break
    if not request:
        return None

    # Mandatory: status (first 100-599 plain integer after request)
    status = -1
    status_idx = -1
    for i in range(request_idx + 1, len(tokens)):
        t, k = tokens[i]
        if k == "plain" and _is_status(t):
            status = int(t)
            status_idx = i
            break
    if status == -1:
        return None

    # Optional: body_bytes (next plain int or "-" after status)
    body_bytes = 0
    next_idx = status_idx + 1
    if next_idx < len(tokens):
        t, k = tokens[next_idx]
        if k == "plain":
            if t == "-":
                next_idx += 1
            elif t.isdigit():
                body_bytes = int(t)
                next_idx += 1

    remaining = tokens[next_idx:]

    referer = ""
    user_agent = ""
    xff = ""
    upstream_addr = ""
    upstream_response_time: Optional[float] = None
    request_time: Optional[float] = None

    # Pass 1: labeled values like "ups_resp_time: 0.012"
    consumed: set[int] = set()
    for i, (t, k) in enumerate(remaining):
        if i in consumed or k != "plain" or not t.endswith(":"):
            continue
        if i + 1 >= len(remaining):
            continue
        label = t[:-1].lower()
        val_t, val_k = remaining[i + 1]
        if val_k != "plain":
            continue
        fv = _parse_float(val_t)
        if label in ("ups_resp_time", "upstream_response_time"):
            upstream_response_time = fv
            consumed.add(i); consumed.add(i + 1)
        elif label == "request_time":
            request_time = fv
            consumed.add(i); consumed.add(i + 1)

    # Pass 2: upstream_addr (first ip:port plain token)
    for i, (t, k) in enumerate(remaining):
        if i in consumed:
            continue
        if k == "plain" and _IP_PORT_RE.match(t):
            upstream_addr = t
            consumed.add(i)
            break

    # Pass 3: quoted strings — positional with type-based swap
    quoted_pos = [i for i, (t, k) in enumerate(remaining)
                  if k == "quoted" and i not in consumed]
    quoted_vals = [remaining[i][0] for i in quoted_pos]
    if len(quoted_vals) >= 1:
        referer = quoted_vals[0]
    if len(quoted_vals) >= 2:
        user_agent = quoted_vals[1]
    if len(quoted_vals) >= 3:
        xff = quoted_vals[2]

    # Refinements: if positions look wrong, swap by content
    if referer and user_agent:
        if _looks_like_ua(referer) and not _looks_like_ua(user_agent):
            referer, user_agent = user_agent, referer
        if xff and _looks_like_ua(xff) and _looks_like_xff(user_agent):
            user_agent, xff = xff, user_agent

    # Pass 4: unlabeled floats → response times if we don't have them yet
    unlabeled_floats: list[float] = []
    for i, (t, k) in enumerate(remaining):
        if i in consumed or k != "plain":
            continue
        if _is_float(t):
            fv = _parse_float(t)
            if fv is not None:
                unlabeled_floats.append(fv)
    if upstream_response_time is None and unlabeled_floats:
        upstream_response_time = unlabeled_floats[0]
    if request_time is None and len(unlabeled_floats) >= 2:
        request_time = unlabeled_floats[1]
    elif request_time is None and len(unlabeled_floats) == 1 and upstream_response_time is None:
        request_time = unlabeled_floats[0]

    # Clean up sentinel "-" values to empty strings for downstream simplicity
    referer = "" if referer == "-" else referer
    user_agent = "" if user_agent == "-" else user_agent
    xff = "" if xff == "-" else xff
    upstream_addr = "" if upstream_addr == "-" else upstream_addr

    method, uri, protocol, path, query, decoded = _build_request_parts(request)

    return LogEntry(
        raw=line, line_no=line_no,
        remote_addr=remote_addr,
        remote_user="",
        time_local=time_local,
        timestamp=_parse_time(time_local),
        request=request,
        method=method, uri=uri, protocol=protocol,
        path=path, query=query, decoded_uri=decoded,
        status=status,
        body_bytes_sent=body_bytes,
        http_referer=referer,
        http_user_agent=user_agent,
        http_x_forwarded_for=xff,
        upstream_addr=upstream_addr,
        upstream_response_time=upstream_response_time,
        request_time=request_time,
    )


def parse_line(line: str, line_no: int = 0) -> Optional[LogEntry]:
    """Parse one log line. Tries strict nginx format first, then auto."""
    line = line.rstrip("\n").rstrip("\r")
    if not line.strip():
        return None
    return _parse_strict(line, line_no) or _parse_auto(line, line_no)


# --------------------------------------------------------------------------
# File I/O helpers
# --------------------------------------------------------------------------

def _open_text(path: str | Path):
    """Open a regular or .gz log file as text."""
    p = str(path)
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def parse_file(path: str | Path) -> Iterator[tuple[int, LogEntry | None, str]]:
    """Yield (line_no, entry_or_None, raw_line). entry is None on parse failure."""
    with _open_text(path) as f:
        for i, line in enumerate(f, 1):
            entry = parse_line(line, i)
            yield i, entry, line.rstrip("\n")


def parse_lines(lines: Iterable[str]) -> Iterator[tuple[int, LogEntry | None, str]]:
    for i, line in enumerate(lines, 1):
        entry = parse_line(line, i)
        yield i, entry, line.rstrip("\n")


def discover_logs(path: str | Path, glob: str = "*") -> list[Path]:
    """Return the list of candidate log files under `path`.

    - If `path` is a regular file, returns [path] regardless of glob.
    - If `path` is a directory, returns all matching files (sorted; pass
      "**/*" for recursive). No filename convention assumed.
    """
    p = Path(path)
    if not p.exists():
        return []
    if p.is_file():
        return [p]
    return sorted(f for f in p.glob(glob) if f.is_file())


def parse_paths(paths: Iterable[str | Path]) -> Iterator[
    tuple[Path, int, LogEntry | None, str]
]:
    """Iterate (source_file, line_no, entry_or_None, raw_line) over many files."""
    for path in paths:
        p = Path(path)
        for line_no, entry, raw in parse_file(p):
            yield p, line_no, entry, raw


# ========================================================================
# === anomaly.py
# ========================================================================

"""Anomalous-path detection.

Two modes:

1. Baseline mode — caller provides a set of "known" normalized paths from
   historical logs. Any path in the current log whose normalized form is NOT
   in that set and that has >= min_hits is flagged.

2. Burst mode — no baseline. Within a single log file, flag paths whose
   first_seen falls in the later portion of the log's time range AND whose
   hits are concentrated in a small time window relative to the file. This
   catches "this URL never appeared, then suddenly got hammered for 10
   minutes" — the classic shape of fresh exploit traffic.

Path normalization collapses numeric ids, UUIDs and long hex segments so
that `/user/100` and `/user/101` are treated as the same path for the
purposes of baseline matching.
"""




_NUM_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalize_path(path: str) -> str:
    """Collapse high-cardinality path segments so similar URLs group together."""
    if not path:
        return path
    parts = path.split("/")
    out = []
    for p in parts:
        if not p:
            out.append(p)
        elif _NUM_RE.match(p):
            out.append("<n>")
        elif _UUID_RE.match(p):
            out.append("<uuid>")
        elif _HEX_RE.match(p):
            out.append("<hex>")
        elif _DATE_RE.match(p):
            out.append("<date>")
        else:
            out.append(p)
    return "/".join(out)


@dataclass
class PathStats:
    path: str                        # normalized
    sample_uri: str = ""             # original URI for human reading
    hits: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ips: set[str] = field(default_factory=set)
    statuses: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    source_files: set[str] = field(default_factory=set)

    def add(self, entry: LogEntry):
        self.hits += 1
        if entry.timestamp:
            if self.first_seen is None or entry.timestamp < self.first_seen:
                self.first_seen = entry.timestamp
            if self.last_seen is None or entry.timestamp > self.last_seen:
                self.last_seen = entry.timestamp
        self.ips.add(entry.remote_addr)
        self.statuses[entry.status] += 1
        self.methods[entry.method] += 1
        if entry.source_file:
            self.source_files.add(entry.source_file)
        if not self.sample_uri:
            self.sample_uri = entry.uri


def collect_paths(entries: Iterable[LogEntry]) -> dict[str, PathStats]:
    paths: dict[str, PathStats] = {}
    for e in entries:
        key = normalize_path(e.path)
        ps = paths.get(key)
        if ps is None:
            ps = PathStats(path=key)
            paths[key] = ps
        ps.add(e)
    return paths


@dataclass
class PathAnomaly:
    path: str
    sample_uri: str
    hits: int
    unique_ips: int
    first_seen: datetime | None
    last_seen: datetime | None
    statuses: dict[int, int]
    reasons: list[str]
    score: int


def _classify_score(ps: PathStats, *, baseline_unknown: bool,
                    concentrated: bool, late_appearance: bool) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = ps.hits

    if baseline_unknown:
        reasons.append("not present in baseline")
        score += 5
    if late_appearance:
        reasons.append("first appears late in log window")
        score += 3
    if concentrated:
        reasons.append("hits concentrated in a narrow time window")
        score += 3

    successes = sum(c for s, c in ps.statuses.items() if 200 <= s < 400)
    server_err = sum(c for s, c in ps.statuses.items() if s >= 500)
    not_found = ps.statuses.get(404, 0)

    if successes > 0:
        reasons.append(f"{successes} successful response(s) — endpoint works")
        score += successes  # working endpoint = much more suspicious
    if server_err > 0:
        reasons.append(f"{server_err} server error(s) — possible exploit / crash")
        score += server_err * 2
    if not_found == ps.hits:
        reasons.append("all 404s — probing rather than exploitation")
        # don't reduce score below hits; this is informative

    if len(ps.ips) >= 5:
        reasons.append(f"{len(ps.ips)} distinct source IPs — widespread")
        score += 5
    elif len(ps.ips) == 1:
        reasons.append("single source IP — targeted")

    return score, reasons


def detect_anomalous_paths(
    current: Iterable[LogEntry],
    baseline: Iterable[LogEntry] | None = None,
    *,
    min_hits: int = 5,
    late_threshold: float = 0.5,
    concentration_ratio: float = 0.1,
) -> list[PathAnomaly]:
    """
    min_hits             — ignore paths hit fewer than this many times
    late_threshold       — in burst mode, "late" means first_seen falls in the
                           last (1 - late_threshold) fraction of the file's
                           time range. 0.5 => second half of the log.
    concentration_ratio  — in burst mode, "concentrated" means the path's
                           own time window <= this fraction of the file's
                           total time window.
    """
    current_list = list(current)
    cur_paths = collect_paths(current_list)

    baseline_keys: set[str] | None = None
    if baseline is not None:
        baseline_keys = set(collect_paths(baseline).keys())

    # File time range — only meaningful for burst mode.
    timestamps = [e.timestamp for e in current_list if e.timestamp]
    if timestamps:
        file_start = min(timestamps)
        file_end = max(timestamps)
        file_span = (file_end - file_start).total_seconds()
    else:
        file_start = file_end = None
        file_span = 0.0

    # In multi-file burst mode, a path that appears across many source files is
    # almost certainly normal traffic, not "new". Require <= 10% of files.
    all_source_files: set[str] = set()
    for ps in cur_paths.values():
        all_source_files.update(ps.source_files)
    total_source_files = len(all_source_files)
    burst_max_files = max(1, int(total_source_files * 0.1)) if total_source_files else 0

    # Without a baseline AND with multiple source files, the heuristic burst
    # mode produces too many false positives (any endpoint that wasn't called
    # earlier in the time window looks "new"). The user explicitly asked for
    # historical comparison, so in that case we just bail out.
    if baseline is None and total_source_files > 1:
        return []

    anomalies: list[PathAnomaly] = []
    for key, ps in cur_paths.items():
        if ps.hits < min_hits:
            continue

        baseline_unknown = baseline_keys is not None and key not in baseline_keys
        late_appearance = False
        concentrated = False

        if baseline is None and file_span > 60 and ps.first_seen and file_start:
            elapsed = (ps.first_seen - file_start).total_seconds()
            late_appearance = elapsed > file_span * late_threshold

            if ps.first_seen and ps.last_seen:
                path_span = (ps.last_seen - ps.first_seen).total_seconds()
                concentrated = (path_span <= file_span * concentration_ratio
                                or path_span < 60)

        if baseline_keys is not None:
            if not baseline_unknown:
                continue
        else:
            # Burst mode: late + concentrated + path appears in few source files
            # (so legit endpoints that show up in many daily log files are
            # excluded — they're just normal traffic, not anomalies)
            if not (late_appearance and concentrated):
                continue
            if total_source_files > 1 and len(ps.source_files) > burst_max_files:
                continue

        score, reasons = _classify_score(
            ps,
            baseline_unknown=baseline_unknown,
            concentrated=concentrated,
            late_appearance=late_appearance,
        )

        anomalies.append(PathAnomaly(
            path=ps.path,
            sample_uri=ps.sample_uri,
            hits=ps.hits,
            unique_ips=len(ps.ips),
            first_seen=ps.first_seen,
            last_seen=ps.last_seen,
            statuses=dict(ps.statuses),
            reasons=reasons,
            score=score,
        ))

    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


# ========================================================================
# === detectors.py
# ========================================================================

"""Detection logic — three focused signals:

  A. ERROR-BURST   short-window concentration of 4xx/5xx from one source
  B. PATH-ENUM     same source probing many distinct paths (dir bruteforce)
  C. PATH-TRAVERSAL  single-line payload signature (./../etc/passwd 等)

(B and C together = "URL path traversal behavior" — payload + scanner shape.)

New-URL-vs-baseline is handled in anomaly.py.
"""






@dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    field: str
    snippet: str = ""


@dataclass
class Incident:
    """One detector hit on one log line."""
    entry: LogEntry
    finding: Finding


def _client_id(entry: LogEntry) -> str:
    """Attacker identifier: first XFF IP if present, else remote_addr.

    In LB / 反代 部署里 remote_addr 是 LB 的 IP，所有真实客户端会被压到同
    一个桶，per-IP 聚合就废了。XFF 链的最前一个 IP 才是真实客户端（最常
    见的 nginx/Tomcat 配置），按它聚合才能把真攻击者分出来。
    """
    xff = (entry.http_x_forwarded_for or "").strip()
    if xff and xff != "-":
        first = xff.split(",")[0].strip()
        if first and first != "-" and first.lower() != "unknown":
            return first
    return entry.remote_addr


# --------------------------------------------------------------------------
# C. Per-line payload signature: PATH-TRAVERSAL
# --------------------------------------------------------------------------

def detect_line(entry: LogEntry) -> list[Finding]:
    findings: list[Finding] = []
    targets = {entry.uri, entry.decoded_uri}
    for rid, sev, regex, desc in COMPILED_URI:
        for t in targets:
            m = regex.search(t)
            if m:
                findings.append(Finding(rid, sev, desc, "uri", m.group(0)[:120]))
                break
    return findings


# --------------------------------------------------------------------------
# Per-IP aggregation (still used by report / IP rollup)
# --------------------------------------------------------------------------

@dataclass
class IPStats:
    total: int = 0
    errors_4xx: int = 0
    errors_5xx: int = 0
    statuses: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    uris: set = field(default_factory=set)
    user_agents: set = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    score: int = 0
    bytes_out: int = 0
    auth_failures: int = 0


# --------------------------------------------------------------------------
# A. Sliding-window error-burst detector
# --------------------------------------------------------------------------

@dataclass
class ErrorBurst:
    client_id: str           # XFF 真实客户端 IP（如有），否则 remote_addr
    remote_addr: str         # 原始 remote_addr（一般是 LB / 网关 IP）
    xff: str                 # 完整 XFF 链
    user_agent: str
    window_start: datetime
    window_end: datetime
    error_count: int
    status_breakdown: Counter
    top_paths: list[tuple[str, int]]
    sample_uri: str
    source_files: set
    severity: str


def detect_error_bursts(entries: list[LogEntry],
                        window_seconds: int = 60,
                        min_errors: int = 20) -> list[ErrorBurst]:
    """按 client_id（XFF 优先）聚合，找出 ≥ min_errors 个 4xx/5xx 集中在
    window_seconds 秒内的攻击源。"""
    by_client: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if e.status >= 400 and e.timestamp:
            by_client[_client_id(e)].append(e)

    bursts: list[ErrorBurst] = []
    delta = timedelta(seconds=window_seconds)
    for cid, errs in by_client.items():
        if len(errs) < min_errors:
            continue
        errs.sort(key=lambda e: e.timestamp)
        best_i = best_j = 0
        best_count = 0
        j = 0
        for i in range(len(errs)):
            if j < i:
                j = i
            while j + 1 < len(errs) and errs[j + 1].timestamp - errs[i].timestamp <= delta:
                j += 1
            count = j - i + 1
            if count > best_count:
                best_count = count
                best_i, best_j = i, j
        if best_count < min_errors:
            continue
        window = errs[best_i:best_j + 1]
        path_counter = Counter(e.path for e in window)
        sb = Counter(e.status for e in window)
        sample = next((e for e in window if e.status >= 500), window[0])
        sev = "HIGH" if sb.get(500, 0) + sb.get(502, 0) + sb.get(503, 0) >= 5 \
              else ("HIGH" if best_count >= min_errors * 5 else "MEDIUM")
        bursts.append(ErrorBurst(
            client_id=cid,
            remote_addr=sample.remote_addr,
            xff=sample.http_x_forwarded_for,
            user_agent=sample.http_user_agent,
            window_start=window[0].timestamp,
            window_end=window[-1].timestamp,
            error_count=best_count,
            status_breakdown=sb,
            top_paths=path_counter.most_common(5),
            sample_uri=sample.uri,
            source_files={e.source_file for e in window if e.source_file},
            severity=sev,
        ))
    bursts.sort(key=lambda b: (-b.error_count, b.window_start))
    return bursts


# --------------------------------------------------------------------------
# B. Per-IP path enumeration (directory bruteforce signature)
# --------------------------------------------------------------------------

@dataclass
class PathEnum:
    client_id: str           # XFF 真实客户端 IP（如有），否则 remote_addr
    remote_addr: str         # 原始 remote_addr
    xff: str                 # 完整 XFF 链
    user_agent: str
    distinct_paths: int
    total_requests: int
    not_found_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    sample_paths: list[str]
    source_files: set
    severity: str


def detect_path_enumeration(entries: list[LogEntry],
                            min_distinct_paths: int = 10
                            ) -> list[PathEnum]:
    """按 client_id（XFF 优先）聚合：同一客户端探测 ≥ min_distinct_paths
    个不同路径就报。不再要求 404 比例 —— 攻击者扫到的合法端点会返回 200，
    硬卡 404 反而漏报。"""
    by_client: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        by_client[_client_id(e)].append(e)
    results: list[PathEnum] = []
    for cid, group in by_client.items():
        paths = {e.path for e in group}
        if len(paths) < min_distinct_paths:
            continue
        nf = sum(1 for e in group if e.status == 404)
        ts = [e.timestamp for e in group if e.timestamp]
        sample = group[0]
        results.append(PathEnum(
            client_id=cid,
            remote_addr=sample.remote_addr,
            xff=sample.http_x_forwarded_for,
            user_agent=sample.http_user_agent,
            distinct_paths=len(paths),
            total_requests=len(group),
            not_found_count=nf,
            first_seen=min(ts) if ts else None,
            last_seen=max(ts) if ts else None,
            sample_paths=sorted(paths)[:8],
            source_files={e.source_file for e in group if e.source_file},
            severity="HIGH" if len(paths) >= min_distinct_paths * 5 else "MEDIUM",
        ))
    results.sort(key=lambda r: -r.distinct_paths)
    return results


# --------------------------------------------------------------------------
# Top-level: build per-IP stats + collect signature incidents + bursts + enum
# --------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    by_ip: dict[str, IPStats]
    incidents: list[Incident]
    error_bursts: list[ErrorBurst]
    path_enums: list[PathEnum]


def analyze(entries: Iterable[LogEntry],
            burst_window_seconds: int = 60,
            burst_min_errors: int = 20,
            enum_min_paths: int = 10) -> AnalysisResult:
    entries_list = list(entries)
    by_ip: dict[str, IPStats] = defaultdict(IPStats)
    incidents: list[Incident] = []

    for e in entries_list:
        s = by_ip[e.remote_addr]
        s.total += 1
        s.statuses[e.status] += 1
        s.methods[e.method] += 1
        s.uris.add(e.path)
        s.user_agents.add(e.http_user_agent)
        s.bytes_out += e.body_bytes_sent
        if not s.first_seen:
            s.first_seen = e.time_local
        s.last_seen = e.time_local
        if 400 <= e.status < 500:
            s.errors_4xx += 1
        if e.status >= 500:
            s.errors_5xx += 1
        if e.status in (401, 403):
            s.auth_failures += 1
        for f in detect_line(e):
            s.findings.append(f)
            s.score += SEVERITY_WEIGHT.get(f.severity, 0)
            incidents.append(Incident(entry=e, finding=f))

    bursts = detect_error_bursts(entries_list,
                                 window_seconds=burst_window_seconds,
                                 min_errors=burst_min_errors)
    enums = detect_path_enumeration(entries_list,
                                    min_distinct_paths=enum_min_paths)

    # Per-IP rollup uses remote_addr; cross-reference by client_id when needed.
    # (Bursts/enums are reported in their own tables — this is just so the
    # legacy "Top suspicious sources" section also picks them up when the
    # client_id happens to equal remote_addr i.e. no XFF.)
    for b in bursts:
        s = by_ip.get(b.client_id) or by_ip.get(b.remote_addr)
        if s:
            s.findings.append(Finding(
                "ERROR-BURST", b.severity,
                f"{b.error_count} 4xx/5xx in {(b.window_end - b.window_start).total_seconds():.0f}s",
                "behavior"))
            s.score += SEVERITY_WEIGHT[b.severity]
    for p in enums:
        s = by_ip.get(p.client_id) or by_ip.get(p.remote_addr)
        if s:
            s.findings.append(Finding(
                "PATH-ENUM", p.severity,
                f"{p.distinct_paths} distinct paths probed",
                "behavior"))
            s.score += SEVERITY_WEIGHT[p.severity]

    return AnalysisResult(by_ip=dict(by_ip), incidents=incidents,
                          error_bursts=bursts, path_enums=enums)


# ========================================================================
# === report.py
# ========================================================================

"""Table-style report rendering — HTML and CSV.

聚合粒度：(severity, rule_id, remote_addr, xff, path) — 同一个攻击者
对同一个 URL 用同一种方式打多次，合并成一行展示，避免 sqlmap 那种千行
报告。展示字段就是用户在防御场景里真正想看的：

  严重度 | 攻击类型 | 命中 | 源IP | XFF / 真实IP | 方法 | URL |
  状态码 | UA | 时间窗口 | 来源文件

所有输出都是离线生成的本地文件，零外网资源（无 CDN 字体 / 无外链 JS）。
"""




SEV_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class IncidentRow:
    severity: str
    rule_id: str
    description: str
    remote_addr: str
    xff: str
    method: str
    path: str
    sample_uri: str
    sample_ua: str
    sample_referer: str
    statuses: Counter = field(default_factory=Counter)
    hits: int = 0
    first_seen: str = ""
    last_seen: str = ""
    source_files: set = field(default_factory=set)


def aggregate(incidents: Iterable[Incident]) -> list[IncidentRow]:
    rows: dict[tuple, IncidentRow] = {}
    for inc in incidents:
        e = inc.entry
        f = inc.finding
        xff = e.http_x_forwarded_for or ""
        key = (f.severity, f.rule_id, e.remote_addr, xff, e.path)
        r = rows.get(key)
        if r is None:
            r = IncidentRow(
                severity=f.severity,
                rule_id=f.rule_id,
                description=f.description,
                remote_addr=e.remote_addr,
                xff=xff,
                method=e.method,
                path=e.path,
                sample_uri=e.uri,
                sample_ua=e.http_user_agent,
                sample_referer=e.http_referer,
                first_seen=e.time_local,
                last_seen=e.time_local,
            )
            rows[key] = r
        r.hits += 1
        r.statuses[e.status] += 1
        if not r.first_seen:
            r.first_seen = e.time_local
        r.last_seen = e.time_local
        if e.source_file:
            r.source_files.add(e.source_file)
    return sorted(rows.values(),
                  key=lambda r: (-SEV_RANK.get(r.severity, 0), -r.hits))


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

def write_csv(rows: Iterable[IncidentRow],
              bursts: list[ErrorBurst],
              enums: list[PathEnum],
              anomalies: list,
              path: str) -> None:
    """One CSV with a `category` column distinguishing the 3 detections."""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([
            "category", "severity", "remote_addr", "xff_real_ip",
            "user_agent", "metric", "detail", "time_window",
            "statuses", "sample_uri", "source_files",
        ])
        # A. Error bursts
        for b in bursts:
            top_paths = "; ".join(f"{p}×{n}" for p, n in b.top_paths)
            dur = (b.window_end - b.window_start).total_seconds() if b.window_end else 0
            w.writerow([
                "A:ERROR-BURST", b.severity, b.client_id, b.xff,
                b.user_agent,
                f"{b.error_count} errors in {dur:.0f}s",
                f"top paths: {top_paths}",
                f"{b.window_start} → {b.window_end}",
                "; ".join(f"{s}:{n}" for s, n in sorted(b.status_breakdown.items())),
                b.sample_uri,
                "; ".join(sorted(b.source_files)),
            ])
        # B. New URLs (baseline / burst)
        for a in anomalies:
            w.writerow([
                "B:NEW-URL", "MEDIUM", "(multi)", "",
                "",
                f"{a.hits} hits across {a.unique_ips} IPs",
                "; ".join(a.reasons),
                f"{a.first_seen} → {a.last_seen}",
                "; ".join(f"{s}:{n}" for s, n in sorted(a.statuses.items()))
                if not isinstance(a.statuses, Counter)
                else "; ".join(f"{s}:{n}" for s, n in sorted(a.statuses.items())),
                a.sample_uri or a.path,
                "",
            ])
        # C1. Path enumeration (behavior)
        for p in enums:
            w.writerow([
                "C:PATH-ENUM", p.severity, p.client_id, p.xff,
                p.user_agent,
                f"{p.distinct_paths} distinct paths, {p.not_found_count}/{p.total_requests} 404",
                "; ".join(p.sample_paths[:5]),
                f"{p.first_seen} → {p.last_seen}",
                "",
                p.sample_paths[0] if p.sample_paths else "",
                "; ".join(sorted(p.source_files)),
            ])
        # C2. Path traversal payload (signature)
        for r in rows:
            w.writerow([
                "C:PATH-TRAVERSAL", r.severity, r.remote_addr, r.xff,
                r.sample_ua,
                f"{r.hits} hits on path",
                r.description,
                f"{r.first_seen} → {r.last_seen}",
                "; ".join(f"{s}:{n}" for s, n in sorted(r.statuses.items())),
                r.sample_uri,
                "; ".join(sorted(r.source_files)),
            ])


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_HTML_CSS = """
body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC",
       Arial, sans-serif; margin: 1.5em; color: #222; background: #fff; }
h1 { font-size: 1.5em; border-bottom: 2px solid #444; padding-bottom: .2em; }
h2 { font-size: 1.15em; margin-top: 2em; color: #333; }
.summary { margin: 1em 0; padding: .8em 1em; background: #f5f7fa;
           border-left: 4px solid #36c; font-size: 13px; }
.summary code { background: #fff; padding: 0 4px; border-radius: 3px;
                border: 1px solid #ddd; }
table { border-collapse: collapse; width: 100%; font-size: 12.5px;
        table-layout: auto; }
th, td { border: 1px solid #d0d0d0; padding: 5px 7px; text-align: left;
         vertical-align: top; }
th { background: #eef1f6; position: sticky; top: 0; }
tr:nth-child(even) { background: #fafbfc; }
.sev { font-weight: bold; text-align: center; white-space: nowrap; }
.sev-HIGH   { background: #fde7e7; color: #b30000; }
.sev-MEDIUM { background: #fff4d6; color: #8a5a00; }
.sev-LOW    { background: #e6efff; color: #1f4fa8; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: ui-monospace, "SF Mono", Consolas, "Courier New",
        monospace; word-break: break-all; max-width: 380px; }
.truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; }
.truncate:hover { white-space: normal; overflow: visible; word-break: break-all; }
.small { font-size: 11px; color: #666; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px;
       font-size: 11px; background: #eef; color: #339; margin-right: 3px; }
.tag-200 { background: #e3f5e6; color: #1a7a30; }
.tag-3xx { background: #e3eef5; color: #1a567a; }
.tag-4xx { background: #fff4e3; color: #8a5a00; }
.tag-5xx { background: #fde7e7; color: #b30000; }
"""


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _status_tag_cls(s: int) -> str:
    if s == 200:
        return "tag tag-200"
    if 300 <= s < 400:
        return "tag tag-3xx"
    if 400 <= s < 500:
        return "tag tag-4xx"
    if s >= 500:
        return "tag tag-5xx"
    return "tag"


def _status_cell(statuses: Counter) -> str:
    return "".join(
        f'<span class="{_status_tag_cls(s)}">{s}:{n}</span>'
        for s, n in sorted(statuses.items())
    )


def _incident_table_html(rows: list[IncidentRow]) -> str:
    if not rows:
        return '<p class="small">未检测到签名级攻击行为。</p>'
    head = (
        "<thead><tr>"
        "<th>严重度</th><th>攻击类型</th><th>命中</th>"
        "<th>源 IP</th><th>XFF / 真实 IP</th>"
        "<th>方法</th><th>URL / 路径</th>"
        "<th>状态码</th><th>User-Agent</th>"
        "<th>时间窗口</th><th>来源文件</th>"
        "</tr></thead>"
    )
    body_rows = []
    for r in rows:
        time_window = (f"{r.first_seen}<br><span class='small'>→ {r.last_seen}</span>"
                       if r.first_seen != r.last_seen
                       else r.first_seen)
        src_files = "<br>".join(_esc(s) for s in sorted(r.source_files)) or "-"
        body_rows.append(
            "<tr>"
            f'<td class="sev sev-{r.severity}">{r.severity}</td>'
            f"<td>{_esc(r.description)}"
            f'<br><span class="small">{_esc(r.rule_id)}</span></td>'
            f'<td class="num">{r.hits}</td>'
            f'<td class="mono">{_esc(r.remote_addr)}</td>'
            f'<td class="mono">{_esc(r.xff) or "-"}</td>'
            f"<td>{_esc(r.method) or '-'}</td>"
            f'<td class="mono">{_esc(r.sample_uri or r.path)}</td>'
            f"<td>{_status_cell(r.statuses)}</td>"
            f'<td class="mono truncate" title="{_esc(r.sample_ua)}">'
            f"{_esc(r.sample_ua) or '-'}</td>"
            f'<td class="small mono">{time_window}</td>'
            f'<td class="mono small">{src_files}</td>'
            "</tr>"
        )
    return f"<table>{head}<tbody>{''.join(body_rows)}</tbody></table>"


def _anomaly_table_html(anomalies) -> str:
    if not anomalies:
        return '<p class="small">未发现新出现 / 突发的异常路径。</p>'
    head = (
        "<thead><tr>"
        "<th>路径</th><th>命中</th><th>独立源 IP</th>"
        "<th>状态码</th><th>时间窗口</th><th>判定原因</th>"
        "</tr></thead>"
    )
    rows = []
    for a in anomalies:
        statuses = Counter(a.statuses) if not isinstance(a.statuses, Counter) else a.statuses
        fs = a.first_seen.isoformat() if a.first_seen else "-"
        ls = a.last_seen.isoformat() if a.last_seen else "-"
        time_window = (f"{fs}<br><span class='small'>→ {ls}</span>"
                       if fs != ls else fs)
        reasons = "<br>".join(f"· {_esc(r)}" for r in a.reasons) or "-"
        rows.append(
            "<tr>"
            f'<td class="mono">{_esc(a.sample_uri or a.path)}'
            f'<br><span class="small">{_esc(a.path)}</span></td>'
            f'<td class="num">{a.hits}</td>'
            f'<td class="num">{a.unique_ips}</td>'
            f"<td>{_status_cell(statuses)}</td>"
            f'<td class="small mono">{time_window}</td>'
            f"<td>{reasons}</td>"
            "</tr>"
        )
    return f"<table>{head}<tbody>{''.join(rows)}</tbody></table>"


def _burst_table_html(bursts: list[ErrorBurst]) -> str:
    if not bursts:
        return '<p class="small">未检测到错误突发。</p>'
    head = (
        "<thead><tr>"
        "<th>严重度</th><th>攻击源 (client)</th><th>原始 IP</th>"
        "<th>XFF 链</th>"
        "<th>错误数</th><th>时间窗口</th><th>状态码分布</th>"
        "<th>TOP 目标路径</th><th>UA</th><th>来源文件</th>"
        "</tr></thead>"
    )
    rows = []
    for b in bursts:
        dur = (b.window_end - b.window_start).total_seconds() if b.window_end else 0
        time_window = (f"{b.window_start.isoformat()}<br>"
                       f"<span class='small'>→ {b.window_end.isoformat()} "
                       f"({dur:.0f}s)</span>")
        top_paths = "<br>".join(
            f'<span class="mono">{_esc(p)}</span> '
            f'<span class="small">×{n}</span>'
            for p, n in b.top_paths
        )
        src = "<br>".join(_esc(s) for s in sorted(b.source_files)) or "-"
        rows.append(
            "<tr>"
            f'<td class="sev sev-{b.severity}">{b.severity}</td>'
            f'<td class="mono"><b>{_esc(b.client_id)}</b></td>'
            f'<td class="mono small">{_esc(b.remote_addr)}</td>'
            f'<td class="mono small">{_esc(b.xff) or "-"}</td>'
            f'<td class="num">{b.error_count}</td>'
            f'<td class="small mono">{time_window}</td>'
            f"<td>{_status_cell(b.status_breakdown)}</td>"
            f'<td>{top_paths}</td>'
            f'<td class="mono truncate" title="{_esc(b.user_agent)}">'
            f'{_esc(b.user_agent) or "-"}</td>'
            f'<td class="mono small">{src}</td>'
            "</tr>"
        )
    return f"<table>{head}<tbody>{''.join(rows)}</tbody></table>"


def _enum_table_html(enums: list[PathEnum]) -> str:
    if not enums:
        return '<p class="small">未检测到目录遍历 / 路径枚举行为。</p>'
    head = (
        "<thead><tr>"
        "<th>严重度</th><th>攻击源 (client)</th><th>原始 IP</th>"
        "<th>XFF 链</th>"
        "<th>不同路径数</th><th>总请求</th><th>404 数</th>"
        "<th>时间窗口</th><th>样本路径</th><th>UA</th>"
        "</tr></thead>"
    )
    rows = []
    for p in enums:
        fs = p.first_seen.isoformat() if p.first_seen else "-"
        ls = p.last_seen.isoformat() if p.last_seen else "-"
        time_window = (f"{fs}<br><span class='small'>→ {ls}</span>"
                       if fs != ls else fs)
        samples = "<br>".join(f'<span class="mono">{_esc(sp)}</span>'
                              for sp in p.sample_paths)
        rows.append(
            "<tr>"
            f'<td class="sev sev-{p.severity}">{p.severity}</td>'
            f'<td class="mono"><b>{_esc(p.client_id)}</b></td>'
            f'<td class="mono small">{_esc(p.remote_addr)}</td>'
            f'<td class="mono small">{_esc(p.xff) or "-"}</td>'
            f'<td class="num">{p.distinct_paths}</td>'
            f'<td class="num">{p.total_requests}</td>'
            f'<td class="num">{p.not_found_count}</td>'
            f'<td class="small mono">{time_window}</td>'
            f'<td>{samples}</td>'
            f'<td class="mono truncate" title="{_esc(p.user_agent)}">'
            f'{_esc(p.user_agent) or "-"}</td>'
            "</tr>"
        )
    return f"<table>{head}<tbody>{''.join(rows)}</tbody></table>"


def write_html(rows: list[IncidentRow], anomalies: list,
               bursts: list[ErrorBurst], enums: list[PathEnum],
               summary: dict, path: str) -> None:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_html = (
        f"<b>日志路径</b>：<code>{_esc(summary.get('log_path'))}</code> &nbsp; "
        f"<b>已解析</b>：{summary.get('parsed', 0):,} 行 &nbsp; "
        f"<b>独立源 IP</b>：{summary.get('unique_ips', 0):,} &nbsp; "
        f"<b>异常路径模式</b>：<code>{_esc(summary.get('newpath_mode', '-'))}</code>"
        "<br>"
        f"<b>错误突发</b>：{len(bursts)} 个源 IP &nbsp; "
        f"<b>路径枚举</b>：{len(enums)} 个源 IP &nbsp; "
        f"<b>新增 URL</b>：{len(anomalies)} 个 &nbsp; "
        f"<b>路径遍历载荷</b>：{len(rows)} 条聚合记录"
    )
    page = (
        '<!DOCTYPE html>\n'
        '<html lang="zh-CN"><head><meta charset="utf-8">'
        '<title>Access-log analysis report</title>'
        f'<style>{_HTML_CSS}</style></head><body>'
        '<h1>Access-log 攻击行为分析报告</h1>'
        f'<div class="summary">{summary_html}</div>'
        '<h2>A. 错误突发（短时窗内大量 4xx/5xx）</h2>'
        f'{_burst_table_html(bursts)}'
        '<h2>B. 新增 URL（基线对比 / 突发访问）</h2>'
        f'{_anomaly_table_html(anomalies)}'
        '<h2>C. 路径遍历 / 目录枚举（载荷 + 行为）</h2>'
        f'{_enum_table_html(enums)}'
        '<h3 class="small">路径遍历载荷命中（PATH-TRAVERSAL）</h3>'
        f'{_incident_table_html(rows)}'
        f'<p class="small">生成时间：{generated} &nbsp;·&nbsp; '
        '本报告为离线生成，未嵌入任何外网资源。</p>'
        '</body></html>\n'
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# ========================================================================
# === analyze.py
# ========================================================================

#!/usr/bin/env python3
"""Nginx access-log attack analyzer.

直接运行即可：
    python3 analyze.py

会自动扫描 LOG_PATH 下所有 access 日志（含 .gz 归档）一起分析。
需要修改路径或阈值时，编辑下方 CONFIG 区域。
"""









# =========================================================================
# CONFIG — 所有可调项都写在这里。改完保存就生效，不用传命令行参数。
# =========================================================================

# 要分析的日志路径，可以是：
#   - 单个文件: "./access.log"
#   - 一个目录: "./logs"  (会扫描目录里所有匹配 LOG_GLOB 的文件)
# 支持 .gz 归档（nginx logrotate 产生的 .log.2.gz 等自动解压）。
# 文件名不限——任何能解析成 nginx 访问日志的文件都会被读入；解析不出
# 任何一行的文件会被静默跳过，所以同目录里放 README、配置等无关文件
# 也没关系。
LOG_PATH = "./logs"

# 目录模式下匹配文件的 glob，默认递归扫描所有子目录：
#   "**/*"   —— 递归扫描所有子目录（如 /var/log/nginx/{site}/access.log）
#   "*"      —— 只看 LOG_PATH 这一层，不进子目录
#   "*.log*" —— 只看带 .log 字样的（更严格）
LOG_GLOB = "**/*"

# 历史"已知正常"基线路径（文件或目录）。存在则启用基线对比模式；
# 不存在或设为 None 则自动回退到单文件突发模式。
BASELINE_PATH = "./baseline"
BASELINE_GLOB = "**/*"

# 结构化 JSON 报告输出路径。设为 None 则不写文件。
JSON_OUTPUT = "./report.json"

# HTML 表格式报告输出路径（最常用）：浏览器直接打开就能看。
# 表头：严重度 / 攻击类型 / 命中 / 源IP / XFF / 方法 / URL /
#       状态码 / UA / 时间窗口 / 来源文件
HTML_OUTPUT = "./report.html"

# CSV 报告输出路径：用 Excel / 数据分析工具继续处理时用。
CSV_OUTPUT = "./report.csv"

# 报告中最低保留的攻击命中严重度："LOW" / "MEDIUM" / "HIGH"
MIN_SEVERITY = "LOW"

# 按风险分排序，展示前 N 个可疑 IP
TOP_IPS = 20

# === 检测阈值 ===
# A. 错误突发：单 IP 在 BURST_WINDOW_SECONDS 内出现 ≥ BURST_MIN_ERRORS 次
#    4xx/5xx 即报。
BURST_WINDOW_SECONDS = 60
BURST_MIN_ERRORS = 20

# B. 异常新增路径（基线对比模式下生效）
NEWPATH_MIN_HITS = 5
NEWPATH_TOP = 15

# C. 路径遍历 / 目录爆破：同一客户端（XFF 真实 IP 优先，无 XFF 则回退
#    remote_addr）探测的不同路径数 ≥ ENUM_MIN_PATHS。
#    不再要求 404 比例——攻击者扫到的合法端点会返回 200。
ENUM_MIN_PATHS = 10

# 颜色输出。在非 TTY（被管道 / 重定向）下会自动关闭。
USE_COLOR = True

# =========================================================================


SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class C:
    RED = "\033[31m"
    YEL = "\033[33m"
    CYN = "\033[36m"
    GRN = "\033[32m"
    DIM = "\033[2m"
    BLD = "\033[1m"
    END = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("RED", "YEL", "CYN", "GRN", "DIM", "BLD", "END"):
            setattr(cls, k, "")


def sev_color(sev: str) -> str:
    return {"HIGH": C.RED, "MEDIUM": C.YEL, "LOW": C.CYN}.get(sev, "")


def _human_bytes(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def _rel(path: Path, root: Path) -> str:
    """Display path relative to root if possible, else just the name."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _load_logs(path: str | None, glob: str, label: str
               ) -> tuple[list, list, list]:
    """Return (entries, per_file_stats, skipped_files).

    Files that yield zero parseable lines are treated as "not an nginx
    access log" and skipped silently — the user can drop any kind of file
    in the log directory without it polluting the report.
    """
    if not path:
        return [], [], []
    files = discover_logs(path, glob)
    if not files:
        return [], [], []

    print(f"  {label:<13}: {path}  ({len(files)} candidate file"
          f"{'s' if len(files) != 1 else ''})")
    entries = []
    per_file = []
    skipped = []
    root = Path(path) if Path(path).is_dir() else Path(path).parent
    for src in files:
        try:
            size = src.stat().st_size
        except OSError:
            size = 0
        parsed_n = 0
        errors_n = 0
        rel_name = _rel(src, root)
        try:
            for _line_no, entry, _raw in parse_file(src):
                if entry is None:
                    errors_n += 1
                else:
                    entry.source_file = rel_name
                    entries.append(entry)
                    parsed_n += 1
        except (OSError, EOFError) as exc:
            skipped.append((src, f"read error: {exc}"))
            continue
        if parsed_n == 0:
            skipped.append((src, "not an access log (0 lines parsed)"))
        else:
            per_file.append({
                "path": src, "parsed": parsed_n,
                "errors": errors_n, "size": size,
            })
    return entries, per_file, skipped


def main():
    if not USE_COLOR or not sys.stdout.isatty():
        C.disable()

    log_files = discover_logs(LOG_PATH, LOG_GLOB)
    if not log_files:
        print(f"{C.RED}error: no log files found at: {LOG_PATH}{C.END}", file=sys.stderr)
        print(f"  请把 access.log 放到 {Path(LOG_PATH).resolve()} 下，"
              f"或修改 analyze.py 顶部的 LOG_PATH 常量。", file=sys.stderr)
        sys.exit(2)

    print(f"{C.BLD}Access-log analysis report{C.END}")
    parsed, per_file, skipped = _load_logs(LOG_PATH, LOG_GLOB, "log source")
    log_root = Path(LOG_PATH)
    for f in per_file:
        display = _rel(f["path"], log_root)
        print(f"    {C.DIM}· {display:<40} {f['parsed']:>9,} lines  "
              f"{_human_bytes(f['size']):>6}{C.END}")
    if skipped:
        print(f"    {C.DIM}skipped {len(skipped)} non-log file"
              f"{'s' if len(skipped) != 1 else ''}: "
              f"{', '.join(_rel(s[0], log_root) for s in skipped[:5])}"
              f"{' ...' if len(skipped) > 5 else ''}{C.END}")
    parse_errors = sum(f["errors"] for f in per_file)

    if not parsed:
        print("no parseable log lines found — check LOG_PATH / LOG_GLOB.",
              file=sys.stderr)
        sys.exit(1)

    # 多文件输入时按时间戳排序，保证 first_seen/last_seen、burst 检测都准确
    parsed.sort(key=lambda e: e.timestamp or 0)

    # 检测（路径遍历签名 + 错误突发 + 目录爆破 + 行为聚合）
    result = analyze(
        parsed,
        burst_window_seconds=BURST_WINDOW_SECONDS,
        burst_min_errors=BURST_MIN_ERRORS,
        enum_min_paths=ENUM_MIN_PATHS,
    )
    by_ip = result.by_ip
    incidents = result.incidents
    error_bursts = result.error_bursts
    path_enums = result.path_enums

    min_sev = SEV_ORDER[MIN_SEVERITY]
    filtered = {
        ip: s for ip, s in by_ip.items()
        if any(SEV_ORDER[f.severity] >= min_sev for f in s.findings)
    }

    print(f"  parsed lines : {len(parsed):,}")
    if parse_errors:
        print(f"  {C.YEL}unparseable  : {parse_errors:,}{C.END}")
    print(f"  unique IPs   : {len(by_ip):,}")
    print(f"  flagged IPs  : {len(filtered):,} (min severity {MIN_SEVERITY})")

    rule_counts: Counter = Counter()
    for s in by_ip.values():
        for f in s.findings:
            if SEV_ORDER[f.severity] >= min_sev:
                rule_counts[(f.severity, f.rule_id, f.description)] += 1
    if rule_counts:
        print(f"\n{C.BLD}Top rules triggered:{C.END}")
        for (sev, rid, desc), n in sorted(
            rule_counts.items(), key=lambda kv: (-kv[1], kv[0][0])
        )[:15]:
            print(f"  {sev_color(sev)}[{sev:<6}]{C.END} {rid:<18} {n:>5}x  {desc}")

    # ---------- 可疑源 IP ----------
    ranked = sorted(filtered.items(), key=lambda kv: kv[1].score, reverse=True)
    if ranked:
        print(f"\n{C.BLD}Top suspicious sources (by score):{C.END}")
        for ip, s in ranked[:TOP_IPS]:
            print(f"\n  {C.BLD}{ip}{C.END}  "
                  f"score={C.RED if s.score >= 20 else C.YEL if s.score >= 8 else C.CYN}{s.score}{C.END}  "
                  f"reqs={s.total}  "
                  f"4xx={s.errors_4xx}  5xx={s.errors_5xx}  "
                  f"uris={len(s.uris)}  uas={len(s.user_agents)}")
            print(f"    window: {C.DIM}{s.first_seen} → {s.last_seen}{C.END}")

            grouped: Counter = Counter()
            samples: dict = {}
            for f in s.findings:
                if SEV_ORDER[f.severity] < min_sev:
                    continue
                key = (f.severity, f.rule_id, f.description)
                grouped[key] += 1
                samples.setdefault(key, f.snippet)
            for (sev, rid, desc), n in sorted(
                grouped.items(), key=lambda kv: (-SEV_ORDER[kv[0][0]], -kv[1])
            ):
                snip = samples.get((sev, rid, desc), "")
                line = f"      {sev_color(sev)}[{sev}]{C.END} {rid} x{n}  {desc}"
                if snip:
                    line += f"  {C.DIM}{snip!r}{C.END}"
                print(line)

    # ---------- 异常路径 ----------
    baseline_entries = []
    baseline_used = False
    if BASELINE_PATH and discover_logs(BASELINE_PATH, BASELINE_GLOB):
        print()
        baseline_entries, b_files, b_skipped = _load_logs(
            BASELINE_PATH, BASELINE_GLOB, "baseline")
        baseline_root = Path(BASELINE_PATH)
        for f in b_files:
            display = _rel(f["path"], baseline_root)
            print(f"    {C.DIM}· {display:<40} {f['parsed']:>9,} lines{C.END}")
        if b_skipped:
            print(f"    {C.DIM}skipped {len(b_skipped)} non-log file"
                  f"{'s' if len(b_skipped) != 1 else ''}{C.END}")
        baseline_used = bool(baseline_entries)

    path_anomalies = detect_anomalous_paths(
        parsed,
        baseline=baseline_entries if baseline_used else None,
        min_hits=NEWPATH_MIN_HITS,
    )
    mode = "baseline-diff" if baseline_used else "burst"
    if path_anomalies:
        print(f"\n{C.BLD}Anomalous paths ({mode} mode):{C.END}")
        for a in path_anomalies[:NEWPATH_TOP]:
            status_str = ", ".join(
                f"{s}:{n}" for s, n in sorted(a.statuses.items())
            )
            fs = a.first_seen.isoformat() if a.first_seen else "?"
            ls = a.last_seen.isoformat() if a.last_seen else "?"
            print(f"\n  {C.BLD}{a.path}{C.END}  "
                  f"score={C.RED if a.score >= 20 else C.YEL}{a.score}{C.END}  "
                  f"hits={a.hits}  ips={a.unique_ips}")
            print(f"    sample : {C.DIM}{a.sample_uri}{C.END}")
            print(f"    window : {C.DIM}{fs} → {ls}{C.END}")
            print(f"    status : {status_str}")
            for r in a.reasons:
                print(f"      - {r}")
    else:
        print(f"\n{C.DIM}No anomalous paths detected ({mode} mode, "
              f"min hits={NEWPATH_MIN_HITS}).{C.END}")

    # ---------- 表格式报告（HTML / CSV）----------
    incident_rows = aggregate(incidents)
    if incident_rows:
        sev_count = Counter(r.severity for r in incident_rows)
        print(f"\n{C.BLD}Aggregated incidents (by URL × attack × source):{C.END}  "
              f"{len(incident_rows)} rows  "
              f"({C.RED}HIGH {sev_count.get('HIGH', 0)}{C.END}  "
              f"{C.YEL}MEDIUM {sev_count.get('MEDIUM', 0)}{C.END}  "
              f"{C.CYN}LOW {sev_count.get('LOW', 0)}{C.END})")

    summary_for_html = {
        "log_path": LOG_PATH,
        "parsed": len(parsed),
        "unique_ips": len(by_ip),
        "newpath_mode": mode,
    }
    if HTML_OUTPUT:
        write_html(incident_rows, path_anomalies, error_bursts,
                   path_enums, summary_for_html, HTML_OUTPUT)
        print(f"HTML report → {HTML_OUTPUT}")
    if CSV_OUTPUT:
        write_csv(incident_rows, error_bursts, path_enums,
                  path_anomalies, CSV_OUTPUT)
        print(f"CSV report  → {CSV_OUTPUT}")

    # ---------- JSON 输出 ----------
    if JSON_OUTPUT:
        out = {
            "summary": {
                "log_path": LOG_PATH,
                "log_files": [
                    {"path": str(f["path"]), "parsed": f["parsed"],
                     "errors": f["errors"], "size": f["size"]}
                    for f in per_file
                ],
                "skipped_files": [
                    {"path": str(p), "reason": reason} for p, reason in skipped
                ],
                "parsed": len(parsed),
                "parse_errors": parse_errors,
                "unique_ips": len(by_ip),
                "flagged_ips": len(filtered),
                "min_severity": MIN_SEVERITY,
                "newpath_mode": mode,
            },
            "rule_counts": [
                {"severity": sev, "rule_id": rid, "description": desc, "count": n}
                for (sev, rid, desc), n in rule_counts.most_common()
            ],
            "ips": [
                {
                    "ip": ip,
                    "score": s.score,
                    "total": s.total,
                    "errors_4xx": s.errors_4xx,
                    "errors_5xx": s.errors_5xx,
                    "auth_failures": s.auth_failures,
                    "unique_uris": len(s.uris),
                    "unique_uas": len(s.user_agents),
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                    "findings": [
                        {"rule_id": f.rule_id, "severity": f.severity,
                         "description": f.description, "field": f.field,
                         "snippet": f.snippet}
                        for f in s.findings
                        if SEV_ORDER[f.severity] >= min_sev
                    ],
                }
                for ip, s in ranked
            ],
            "anomalous_paths": [
                {
                    "path": a.path,
                    "sample_uri": a.sample_uri,
                    "hits": a.hits,
                    "unique_ips": a.unique_ips,
                    "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                    "statuses": a.statuses,
                    "reasons": a.reasons,
                    "score": a.score,
                }
                for a in path_anomalies
            ],
        }
        Path(JSON_OUTPUT).write_text(json.dumps(out, indent=2, ensure_ascii=False))
        print(f"\nJSON report → {JSON_OUTPUT}")

    # 退出码：按最严重命中返回，方便接告警 / CI
    worst = max((SEV_ORDER[sev] for (sev, _, _) in rule_counts), default=-1)
    sys.exit({2: 3, 1: 2, 0: 1, -1: 0}[worst])


if __name__ == "__main__":
    main()
