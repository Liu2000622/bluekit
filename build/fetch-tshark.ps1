# fetch-tshark.ps1  —— 自动把 Wireshark 引擎(tshark) 填充进 third_party\tshark\
# 供打包前调用；填充后 PyInstaller 会按 spec 把整目录内嵌进 exe 包。
#
# 查找/获取顺序：
#   1) 已安装的 Wireshark（C:\Program Files\Wireshark）
#   2) choco install wireshark（CI / 有 choco 的机器）
#
# 用法（在 bluekit 根目录）:  pwsh build\fetch-tshark.ps1

$ErrorActionPreference = "Stop"
$dst = Join-Path $PSScriptRoot "..\third_party\tshark"
$ws  = "C:\Program Files\Wireshark"

function Have($c) { return [bool](Get-Command $c -ErrorAction SilentlyContinue) }

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

$ver = & "$dst\tshark.exe" -v | Select-Object -First 1
Write-Host "[fetch-tshark] 完成：$ver"
Write-Host "[fetch-tshark] third_party\tshark 大小：" (
    "{0:N1} MB" -f ((Get-ChildItem $dst -Recurse | Measure-Object Length -Sum).Sum / 1MB))
