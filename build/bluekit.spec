# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置 —— Windows 64 位 / onedir。
# 在 Windows x64 上执行： pyinstaller build\bluekit.spec
#
# 依赖（WebShell 流量分析 Tab 需要）：scapy / pycryptodome / openpyxl
#   打包前： pip install pyinstaller scapy pycryptodome openpyxl
#
# onedir 产物（dist\BlueKit\ 整目录一起分发）：
#   BlueKit.exe
#   _internal\...                      Python 运行时 + 依赖 + 内嵌资源
#     third_party\cfr.jar              反编译器
#     third_party\tshark\tshark.exe    Wireshark 引擎（fetch-tshark.ps1 填充）
#     vendor\webshell_traffic\...      WebShell 流量分析引擎 + 规则
#     vendor\accesslog_analyzer.py     访问日志引擎

from PyInstaller.utils.hooks import collect_all

block_cipher = None

# 收集第三方依赖（含其数据/动态库/子模块）
_datas, _bins, _hidden = [], [], []
for pkg in ("scapy", "Crypto", "openpyxl"):
    d, b, h = collect_all(pkg)
    _datas += d
    _bins += b
    _hidden += h

a = Analysis(
    ['..\\bluekit.py'],
    pathex=['..', '..\\vendor'],
    binaries=_bins,
    datas=[
        ('..\\vendor\\accesslog_analyzer.py', 'vendor'),
        ('..\\vendor\\webshell_traffic', 'vendor\\webshell_traffic'),
        ('..\\third_party\\cfr.jar', 'third_party'),
        ('..\\third_party\\tshark', 'third_party\\tshark'),
    ] + _datas,
    hiddenimports=['accesslog_analyzer'] + _hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'pandas', 'matplotlib', 'scipy', 'test'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BlueKit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,               # GUI 程序，不弹黑框
    disable_windowed_traceback=False,
    target_arch='x86_64',        # Windows 64 位
    codesign_identity=None,
    entitlements_file=None,
    # icon='..\\build\\bluekit.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='BlueKit',
)
