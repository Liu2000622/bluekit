# fetch-tshark.ps1  —— 自动把 Wireshark 引擎(tshark) 填充进 third_party\tshark\
# 供打包前调用；填充后 PyInstaller 会按 spec 把整目录内嵌进 exe 包。
#
# 用法（在 bluekit 根目录）:
#   pwsh build\fetch-tshark.ps1                    # 本机 Wireshark / choco 最新版
#   pwsh build\fetch-tshark.ps1 -Version 3.6.24    # 指定版本(官网下载安装包+7z解包)
#                                                  # Win7 兼容包必须用 3.6.x(最后支持 Win7 的分支)
#
# 不指定 -Version 时的查找/获取顺序：
#   1) 已安装的 Wireshark（C:\Program Files\Wireshark）
#   2) choco install wireshark（CI / 有 choco 的机器）

param([string]$Version = "")

$ErrorActionPreference = "Stop"
$dst = Join-Path $PSScriptRoot "..\third_party\tshark"

function Have($c) { return [bool](Get-Command $c -ErrorAction SilentlyContinue) }

if ($Version) {
    # 指定版本：从官网 all-versions 下载 NSIS 安装包，用 7z 直接解出文件（不真正安装）
    if (!(Have 7z)) { throw "需要 7z 解包 Wireshark 安装程序（GitHub runner 自带；本机请先装 7-Zip 并加入 PATH）" }
    $url = "https://www.wireshark.org/download/win64/all-versions/Wireshark-win64-$Version.exe"
    $installer = Join-Path $env:TEMP "wireshark-$Version.exe"
    Write-Host "[fetch-tshark] 下载 $url ..."
    Invoke-WebRequest -Uri $url -OutFile $installer
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Write-Host "[fetch-tshark] 7z 解包到 $dst ..."
    7z x $installer "-o$dst" -y | Out-Null
    # 清理安装器自带的非运行时目录/文件
    foreach ($junk in '$PLUGINSDIR', '$TEMP', 'uninstall.exe') {
        $p = Join-Path $dst $junk
        if (Test-Path $p) { Remove-Item $p -Recurse -Force }
    }
    Remove-Item $installer -Force
} else {
    $ws = "C:\Program Files\Wireshark"
    if (!(Test-Path "$ws\tshark.exe")) {
        Write-Host "[fetch-tshark] 本机未装 Wireshark，尝试用 choco 安装..."
        if (Have choco) {
            choco install wireshark -y --no-progress
        } else {
            throw "未找到 Wireshark，也没有 choco。请先安装 Wireshark(含 tshark) 到默认路径，或安装 chocolatey 后重试。"
        }
    }
    if (!(Test-Path "$ws\tshark.exe")) { throw "安装后仍未找到 $ws\tshark.exe" }
    Write-Host "[fetch-tshark] 复制 Wireshark 运行文件到 $dst ..."
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    # 复制 tshark 运行所需的全部文件（exe + dll + plugins + data）。
    # 离线读取 pcap 不需要 Npcap（Npcap 只用于实时抓包）。
    Copy-Item "$ws\*" $dst -Recurse -Force
}

if (!(Test-Path "$dst\tshark.exe")) { throw "填充后未找到 $dst\tshark.exe" }
$ver = & "$dst\tshark.exe" -v | Select-Object -First 1
Write-Host "[fetch-tshark] 完成：$ver"
Write-Host "[fetch-tshark] third_party\tshark 大小：" (
    "{0:N1} MB" -f ((Get-ChildItem $dst -Recurse | Measure-Object Length -Sum).Sum / 1MB))
