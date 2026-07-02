# 在 Windows 64 位上打包 BlueKit.exe

> ⚠️ PyInstaller **不能跨平台**：Windows 的 `.exe` 必须在 Windows 上打。
> 在 mac/Linux 上只能开发调试，出不了 Windows exe。

## 1. 准备环境（Windows x64）

- 安装 **Python 3.11 x64**（勾选 Add to PATH）
- 安装打包器：
  ```
  pip install pyinstaller
  ```
- 本项目**零第三方运行依赖**（纯标准库），无需 `pip install` 其它包。

## 2. 自动内嵌 tshark（Wireshark 引擎）—— 一条命令

「流量分析」Tab 靠 tshark。打包前跑一次自动填充脚本即可，**无需手动下载**：

```powershell
pwsh build\fetch-tshark.ps1
```

脚本会：本机已装 Wireshark 就直接用；没装则用 `choco install wireshark` 装；
然后把 `tshark.exe` 及其全部 dll 复制到 `third_party\tshark\`。
随后 `pyinstaller` 会按 spec **把整个 `third_party\tshark` 内嵌进 exe 包**，产物自包含、全离线。

> 若既没装 Wireshark 也没有 choco：先 `choco install wireshark -y`（或到 wireshark.org
> 装一次），再跑上面的脚本。
>
> `third_party\cfr.jar`（反编译器）已随仓库带好，无需额外操作；反编译还需目标机有 `java`。

## 3. 打包

在项目根目录（`bluekit\`）执行：

```
pyinstaller build\bluekit.spec
```

产物在 `dist\BlueKit\`：

```
dist\BlueKit\
├── BlueKit.exe              ← 双击运行
└── _internal\...            ← 运行时 + 内嵌的 cfr.jar / tshark（PyInstaller 生成，别删）
```

tshark 与 cfr.jar 已被内嵌进 `_internal\third_party\`，程序会自动定位。
**整个 `dist\BlueKit\` 目录一起拷贝分发**（onedir 模式，不是单文件）。

## 4. 运行

```
BlueKit.exe
```

或命令行调试（能看到报错）：
```
BlueKit.exe
```
源码调试（任意平台）：
```
python bluekit.py
```

## 常见问题

- **流量分析报"未找到 tshark"**：`third_party\tshark\tshark.exe` 没放，或没装 Wireshark。也可设环境变量 `BLUEKIT_TSHARK=C:\path\to\tshark.exe`。
- **反编译报"未找到 java"**：目标机装个 JRE/JDK，或把 java 加进 PATH。
- **想要单文件 exe**：把 spec 里 `EXE(exclude_binaries=True)` 改 onefile 模式，但 tshark 那堆 dll 不适合塞单文件，仍建议 onedir。
- **exe 体积大**：主要是 tshark portable（几十 MB）。不随包、改用已装 Wireshark 可显著减小。

## 5.（可选）GitHub Actions 自动出包

若不想手动在 Windows 上打，可用 CI：`windows-latest` runner 上跑
`pip install pyinstaller` + `pyinstaller build\bluekit.spec`，产物作为 artifact 下载。
需要的话让我生成 workflow。
