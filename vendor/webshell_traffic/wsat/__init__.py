"""Webshell 流量分析引擎（vendored 自 Webshell_traffic_analysis_tool）。

以 `wsat` 命名空间封装，避免与 BlueKit 自身的 core/ 包冲突。
内部各子包（core/crypto/webshell/report/analyzers）的绝对 import 已统一
改写为 `wsat.<pkg>.` 前缀。BlueKit 通过 core/wstraffic.py 适配层调用。
"""
