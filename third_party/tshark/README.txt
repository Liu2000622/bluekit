把 portable Wireshark 的 tshark 放这里
=====================================

「流量分析」Tab 用 tshark（Wireshark 的命令行引擎）做协议解析。

自动填充（推荐）：
  在 bluekit 根目录执行： pwsh build\fetch-tshark.ps1
  脚本会自动（本机 Wireshark 或 choco 安装）把 tshark.exe + dll 复制到本目录，
  随后 PyInstaller 按 spec 内嵌进 exe 包。CI（GitHub Actions）已自动执行此步。

手动填充（备选）：
  到 https://www.wireshark.org 下载 Windows x64 版，把 tshark.exe 及其同目录的
  所有 dll / 子目录整体拷到本目录 third_party/tshark/。

程序查找 tshark 的顺序：
  1) 本目录 third_party/tshark/tshark.exe（随包 portable，全离线，推荐）
  2) 环境变量 BLUEKIT_TSHARK 指向的路径
  3) 系统已安装的 Wireshark（C:\Program Files\Wireshark\tshark.exe）

License 提醒：
  Wireshark/tshark 为 GPLv2。以独立进程方式调用不影响 BlueKit 自身授权；
  但对外分发时若随包 tshark 二进制，需一并附带 Wireshark 的 GPL 协议与源码获取说明。
  内部自用无此顾虑。
