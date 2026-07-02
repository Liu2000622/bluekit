# -*- coding: utf-8 -*-
"""分析器插件注册入口。"""
from __future__ import annotations

from analyzers.additional_plugins import (
    AntSwordPlugin,
    ChopperPlugin,
    ChiselPlugin,
    CloudTunnelPlugin,
    CobaltStrikePlugin,
    FastTunnelPlugin,
    FrpPlugin,
    GenericHttpTunnelPlugin,
    LanproxyPlugin,
    MeterpreterPlugin,
    NeoReGeorgPlugin,
    NpsPlugin,
    ReGeorgPlugin,
    SocksProxyPlugin,
    StowawayPlugin,
    TermitePlugin,
    VenomPlugin,
    VShellPlugin,
    WeevelyPlugin,
    WebExploitPlugin,
)
from analyzers.legacy_plugins import BehinderPlugin, GodzillaPlugin, Suo5Plugin


def get_default_plugins():
    """返回内置分析器插件实例。"""
    return [
        Suo5Plugin(),
        GodzillaPlugin(),
        BehinderPlugin(),
        ChopperPlugin(),
        AntSwordPlugin(),
        WebExploitPlugin(),
        NeoReGeorgPlugin(),
        ReGeorgPlugin(),
        WeevelyPlugin(),
        SocksProxyPlugin(),
        ChiselPlugin(),
        FastTunnelPlugin(),
        FrpPlugin(),
        NpsPlugin(),
        VenomPlugin(),
        StowawayPlugin(),
        LanproxyPlugin(),
        TermitePlugin(),
        CloudTunnelPlugin(),
        VShellPlugin(),
        CobaltStrikePlugin(),
        MeterpreterPlugin(),
        GenericHttpTunnelPlugin(),
    ]
