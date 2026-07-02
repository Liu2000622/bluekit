# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置 —— Windows 64 位 / 单文件(onefile)。
# 在 Windows x64 上执行： pyinstaller build\bluekit.spec
#
# 单文件：产物就一个 dist\BlueKit.exe，双击即用，无需带 _internal 文件夹。
#   代价：首次/每次启动会先解压到临时目录，比 onedir 略慢几秒；exe 较大(~180MB+)。
#
# 依赖（WebShell 流量分析 Tab 需要）：scapy / pycryptodome / openpyxl
#   打包前： pip install pyinstaller scapy pycryptodome openpyxl
#
# 内嵌资源（运行时解到临时目录，core/paths.py 通过 sys._MEIPASS 定位）：
#   third_party\tshark\tshark.exe   Wireshark 引擎（fetch-tshark.ps1 填充）
#   third_party\cfr.jar             反编译器
#   vendor\webshell_traffic\...     WebShell 流量分析引擎 + 规则
#   vendor\accesslog_analyzer.py    访问日志引擎

from PyInstaller.utils.hooks import collect_all

block_cipher = None

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

# 单文件：把 binaries/datas/zipfiles 全塞进 EXE，不用 COLLECT
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='BlueKit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,               # GUI 程序，不弹黑框
    disable_windowed_traceback=False,
    target_arch='x86_64',        # Windows 64 位
    codesign_identity=None,
    entitlements_file=None,
    # icon='..\\build\\bluekit.ico',
)
