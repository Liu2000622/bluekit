# -*- coding: utf-8 -*-
"""统一分析器插件接口。"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from analysis_record import AnalysisRecord
from pcap_utils import PacketInfo


@dataclass
class DetectionResult:
    """单条 TCP 流的插件识别结果。"""

    plugin_name: str
    confidence: float
    confidence_label: str
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class StreamData:
    """自动分析引擎传给插件的单条重组流。"""

    key: object
    stream_id: str
    directions: Dict[object, bytes]
    packets: List[PacketInfo] = field(default_factory=list)
    timestamp: Optional[float] = None


@dataclass
class AnalysisContext:
    """插件分析阶段共享上下文。"""

    keys: List[str] = field(default_factory=list)
    uris: List[str] = field(default_factory=list)
    weak_keys: List[str] = field(default_factory=list)
    crypters: List[str] = field(default_factory=list)
    status_callback: Callable[[str], None] = print
    detection: Optional[DetectionResult] = None

    def candidate_keys(self) -> List[str]:
        """返回去重后的用户密钥 + 弱口令候选。"""
        seen = set()
        merged = []
        for key in list(self.keys or []) + list(self.weak_keys or []):
            key = (key or "").strip()
            if key and key not in seen:
                seen.add(key)
                merged.append(key)
        return merged


class AnalyzerPlugin(ABC):
    """所有 webshell / 隧道分析器插件的最小接口。"""

    name: str
    category: str = "webshell"
    requires_key: bool = False
    can_decrypt: bool = True

    @abstractmethod
    def detect(self, stream: StreamData) -> Optional[DetectionResult]:
        """识别单条重组流；无法识别返回 None。"""

    @abstractmethod
    def analyze(self, stream: StreamData, context: AnalysisContext) -> List[AnalysisRecord]:
        """分析单条重组流，返回统一 AnalysisRecord。"""

