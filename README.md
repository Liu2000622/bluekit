# BlueKit —— 蓝队离线研判工具

本机运行、**纯离线、零外网请求**的蓝队应急研判 GUI。参考 BlueTeamTools 的离线研判思路自研，
**去掉了所有联网功能与上机/反制功能**，专注在分析师本机做离线分析，并集成了自研的访问日志分析引擎。

- 形态：Python + Tkinter GUI，目标 **Windows 64 位 exe**
- 依赖：**仅 Python 3.11 标准库**（流量分析额外依赖本机/随包 tshark；反编译额外依赖 java + cfr.jar）
- 定位：和 memshell-forensics（上机取证）、accesslog-analyzer（日志引擎）同属 defence-tool 套件

## 功能 Tab

| Tab | 能力 | 依赖 |
|---|---|---|
| **访问日志分析** | 集成 accesslog-analyzer：SQLi/XSS/RCE/Log4Shell 等载荷签名、扫描器 UA、异常/突发路径、高危 IP 排行 | 无 |
| **流量分析(Wireshark)** | 内嵌 **tshark**（Wireshark 引擎）：过滤器构造表单 + 数据包表格 + URL 过滤 + 双击追踪 TCP 流 + 可疑包标红 + 一键“在 Wireshark 打开” | tshark |
| **WebShell 流量分析** | 集成 pcap 全自动分析引擎（vendored `wsat`）：无需密钥自动识别并解密 suo5/哥斯拉/冰蝎/菜刀/蚁剑/Weevely/reGeorg 及 FRP/NPS/Chisel/CS/Meterpreter 等隧道与 C2；新增 **DNS 隧道检测 · TLS 解密(RSA/KeyLog) · JA3/HASSH 指纹 · 威胁情报 IOC 命中 · HTTP/2 与 WebSocket 重组**，出 **Excel + HTML** 双报告 | scapy·pycryptodome·openpyxl |
| **WebShell 解密** | 手工解密：冰蝎/哥斯拉（AES-ECB/XOR）、蚁剑（base64/rot13）、通用模式，gzip 自动解压 | 无（自研纯 Python AES） |
| **编解码** | Base64/Hex/URL/Unicode/HTML/Gzip 编解码 + JWT 解码，均支持多重编码 | 无 |
| **反序列化查看** | 识别 Java 序列化流(`AC ED 00 05`/`rO0AB`)、扫 ysoserial gadget 特征、抽类名 | 无 |
| **工具箱** | 文件头(magic)识别（查改后缀/webshell 伪装）、.class 反编译(CFR，用于看内存马 dump) | java+cfr.jar |

## 相比 BlueTeamTools 的裁剪

- ❌ 去掉（联网）：资产测绘(FOFA/Shodan/Quake/Hunter/微步)、VirusTotal、在线 IP 归属
- ❌ 去掉（上机/反制）：CobaltStrike 爆破、NPS 利用、Burp/ZAP 反制
- 🔄 PCAP 分析 → 换成**内嵌真正的 Wireshark 引擎(tshark)**，能力更强、过滤语法一致
- ➕ 新增：**访问日志攻击分析**（BlueTeamTools 没有）

## 运行

**源码调试（任意平台）：**
```bash
python3 bluekit.py
```

**打 Windows exe（两种方式）：**
- **本地 Windows：** 见 `build/BUILD-WINDOWS.md`（PyInstaller 不能跨平台，exe 必须在 Windows x64 上打）。
- **云端自动出包（无需 Windows 机器）：** 把项目推到 GitHub，`.github/workflows/build-windows.yml` 会在 Windows runner 上自动装 Wireshark、打包、内嵌 tshark、编译成 Inno Setup 安装程序；打 `v*` tag 自动挂到 Release：
  - `BlueKit-windows-x64-setup.exe` —— Windows 8.1/10/11（Python 3.11 运行时，推荐）
  - `BlueKit-win7-x64-setup.exe` —— Windows 7 SP1 兼容版（Python 3.8 + Wireshark 3.6.24 + PyInstaller 5.13.2；Python 3.9+ 的 `python3xx.dll` 依赖 Win8+ 系统组件，在 Win7 上无法加载，Win7 用户必须用这个包）

  双击安装即用（默认装到用户目录、无需管理员权限，自动创建桌面快捷方式），不再需要手动解压 zip。

## 目录结构

```
bluekit/
├── bluekit.py              # GUI 主入口，组装 Notebook
├── core/                   # 纯逻辑（可脱离 GUI 单测）
│   ├── accesslog.py        #   访问日志分析适配层（调 vendor 引擎）
│   ├── codec.py            #   编解码
│   ├── deser.py            #   反序列化识别
│   ├── filetype.py         #   文件头识别
│   ├── tshark.py           #   Wireshark 引擎(tshark)封装
│   └── decompile.py        #   CFR 反编译封装
├── tabs/                   # 各功能 Tab 的界面
├── vendor/
│   ├── accesslog_analyzer.py   # vendored 自研日志引擎（单文件）
│   └── webshell_traffic/wsat/  # vendored WebShell 流量分析引擎（core/crypto/
│                               #   webshell/report/analyzers 子包 + rules/ + tools/cfr.jar）
├── third_party/
│   ├── cfr.jar             # 反编译器（已带）
│   └── tshark/             # 放 portable tshark（见其 README.txt）
└── build/
    ├── bluekit.spec        # PyInstaller 配置（Windows x64 / onedir）
    └── BUILD-WINDOWS.md    # 打包说明
```

## 依赖

- **大部分 Tab 纯标准库、零依赖**（访问日志/编解码/反序列化/文件头/反编译/WebShell解密/流量分析-Wireshark）。
- 仅 **WebShell 流量分析** Tab 需要 `scapy / pycryptodome / openpyxl`（见 `requirements.txt`）；未安装时该 Tab 优雅降级提示，不影响其它 Tab。打包 exe 已内置这三个库。

## 安全性

分析过程**不发起任何网络连接**：核心逻辑无 socket / http 客户端代码；tshark、java 都是本机进程调用。适合内网 / 气隙环境。

## 版本

- **v0.6.1** —— 修复 v0.6.0 打包漏装 wsat 引擎导致「WebShell 流量分析」报 `No module named wsat`（win7/win10 均受影响）：spec 在 `collect_submodules('wsat')` 前把 `vendor\webshell_traffic` 注入 `sys.path`（否则收集为空），并把 wsat 源码树平铺进包作兜底；CI 冒烟测试增加 wsat 可用性与打包产物校验。
- **v0.6.0** —— WebShell 流量分析引擎升级到 `Webshell_traffic_analysis_tool` 最新版（vendored 为 `wsat` 包，与 BlueKit 自身 `core/` 命名空间隔离）：新增 DNS 隧道检测、TLS 解密(RSA/KeyLog)、JA3/HASSH 指纹、威胁情报 IOC 命中、HTTP/2 与 WebSocket 重组，输出 Excel + HTML 双报告。Win7(Python 3.8) / Win10+(Python 3.11) 两条构建腿同步升级（引擎经校验为 Python 3.8 兼容）。
- **v0.3.0** —— 集成 WebShell 流量(pcap)全自动分析引擎（新 Tab）；工具箱支持 jar/war 整包反编译 + 恶意特征定位；UI 统一美化。
- **v0.2.0** —— WebShell 手工解密 Tab（自研纯 Python AES，FIPS-197 通过）；GitHub Actions 云端出 exe。
- **v0.1.0** —— 首版 MVP：访问日志分析 / 流量分析(Wireshark) / 编解码 / 反序列化 / 工具箱。

> WebShell 解密说明：这几款工具版本/加密器众多，密钥派生随连接密码与配置变化。当前实现覆盖**最常见默认算法**，并提供「通用模式」兜底。解不出时先核对密码/密钥/模式。
