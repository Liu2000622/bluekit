# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置 —— Windows 64 位 / 文件夹(onedir)。
# 在 Windows x64 上执行： pyinstaller build\bluekit.spec
#
# 文件夹版：产物 dist\BlueKit\（BlueKit.exe + _internal\）。秒开（无需每次解压）。
#   分发：整个 BlueKit 文件夹打包成 zip，解压后进文件夹双击 BlueKit.exe，
#   ★ 不要把 BlueKit.exe 单独拖出来（会报 python311.dll 找不到）。
#
# 依赖（WebShell 流量分析 Tab 需要）：scapy / pycryptodome / openpyxl
#   打包前： pip install pyinstaller scapy pycryptodome openpyxl
#
# 本 spec 同时用于两条构建腿（见 .github/workflows/build-windows.yml）：
#   常规版  Python 3.11 + 最新 PyInstaller（Win 8.1/10/11）
#   Win7 版 Python 3.8 + PyInstaller 5.13.2 + Wireshark 3.6.x（Win7 SP1；
#           5.x 的 onedir 没有 _internal 子目录、文件平铺在 exe 旁，同样正常）
#
# 内嵌资源（运行时解到临时目录，core/paths.py 通过 sys._MEIPASS 定位）：
#   third_party\tshark\tshark.exe   Wireshark 引擎（fetch-tshark.ps1 填充）
#   third_party\cfr.jar             反编译器
#   vendor\webshell_traffic\wsat\   WebShell 流量分析引擎（wsat 包，含 core/crypto/
#                                   webshell/report/analyzers 子包 + rules\ 规则 +
#                                   tools\cfr.jar；绝对 import 已改写为 wsat.* 前缀，
#                                   与 BlueKit 自身的 core\ 包互不冲突）
#   vendor\accesslog_analyzer.py    访问日志引擎

from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

_datas, _bins, _hidden = [], [], []
for pkg in ("scapy", "Crypto", "openpyxl"):
    d, b, h = collect_all(pkg)
    _datas += d
    _bins += b
    _hidden += h

# WebShell 流量分析引擎（vendor\webshell_traffic\wsat 包）：整包编入 PYZ，
# collect_submodules 会顺带把引擎用到的全部 stdlib/第三方依赖拉进图里，
# 避免“仅作 datas 平铺、PyInstaller 不分析其 import”导致的运行时缺模块。
# 引擎在打包态用 sys._MEIPASS 定位资源，故规则/CFR 需落到 _MEIPASS 根：
#   rules\risk_rules.json / rules\threat_intel.json  ← wsat\rules\
#   tools\cfr.jar                                    ← wsat\tools\cfr.jar
_hidden += collect_submodules('wsat')

a = Analysis(
    ['..\\bluekit.py'],
    pathex=['..', '..\\vendor', '..\\vendor\\webshell_traffic'],
    binaries=_bins,
    datas=[
        ('..\\vendor\\accesslog_analyzer.py', 'vendor'),
        ('..\\vendor\\webshell_traffic\\wsat\\rules', 'rules'),
        ('..\\vendor\\webshell_traffic\\wsat\\tools\\cfr.jar', 'tools'),
        ('..\\third_party\\cfr.jar', 'third_party'),
        ('..\\third_party\\tshark', 'third_party\\tshark'),
        ('..\\build\\bluekit.ico', '.'),
        ('..\\build\\bluekit-preview.png', '.'),
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

# 文件夹版：EXE 只放启动器，资源由 COLLECT 收进 _internal\
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
    icon='..\\build\\bluekit.ico',
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
