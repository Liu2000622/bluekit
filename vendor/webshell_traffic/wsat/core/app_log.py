# -*- coding: utf-8 -*-
"""
统一诊断日志（logging）。与 GUI/CLI 的 status_callback（界面进度更新）分工不同：
status_callback 面向最终用户展示分析进度，logging 面向排障，可用 --verbose/--quiet
控制级别，默认写 stderr 不干扰 stdout 的报告结果。
"""

import logging
import sys

_ROOT = "wsa"

_LEVELS = {
    "quiet": logging.WARNING,
    "info": logging.INFO,
    "verbose": logging.DEBUG,
    "debug": logging.DEBUG,
}


def get_logger(name=None):
    """获取项目命名空间下的 logger。"""
    return logging.getLogger(_ROOT if not name else f"{_ROOT}.{name}")


def configure_logging(level="info", stream=None):
    """
    配置根 logger 级别与 handler（幂等：重复调用只调整级别，不重复加 handler）。
    level: quiet(仅警告) / info(默认) / verbose|debug(调试)。
    """
    lvl = _LEVELS.get(level, logging.INFO)
    logger = logging.getLogger(_ROOT)
    logger.setLevel(lvl)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))
        logger.addHandler(handler)
    for h in logger.handlers:
        h.setLevel(lvl)
    return logger
