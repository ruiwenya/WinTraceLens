# WinTraceLens 1.0 基础版 GUI

## 运行方式

双击 `WinTraceLens.exe` 即可打开桌面窗口。程序会在内部启动本地服务并用 WebView2 承载界面，用户不需要手动打开浏览器，也不需要访问 `127.0.0.1`。

建议右键选择“以管理员身份运行”，这样安全日志、登录日志、WFP 审计和部分系统进程信息能采集得更完整。

可选参数：

```powershell
.\WinTraceLens.exe -hash-limit-mb 512
.\WinTraceLens.exe -debug-webview
```

`-addr` 仅用于调试或兼容测试，正常双击运行时不需要指定：

```powershell
.\WinTraceLens.exe -addr 127.0.0.1:8787
```

## 1.0 基础功能

- 进程信息：进程路径、父进程、MD5、签名状态、模块列表、实时网络连接。
- 主机信息：服务、计划任务、启动项、本地用户、镜像劫持。
- 关注项：进程与持久化项中的可疑项汇总。
- 威胁分析：内存异常检测与行为关联分析；内存异常检测包括私有可执行内存、RWX 内存、线程入口异常，行为关联会聚合进程、网络连接、签名、持久化、内存异常和可选文件痕迹。
- 文件痕迹：最近修改文件、最近运行文件、Temp 临时文件；最近修改文件支持选择 C 盘、D 盘、Windows 目录或其他指定目录扫描。
- 历史通信：Sysmon、WFP、防火墙日志、DNS 缓存等可用证据。
- 事件日志：登录、登录失败、RDP、服务创建、用户账户、PowerShell、SQL Server 相关日志；支持选择开始日期、结束日期和最多读取条数，默认读取最近 7 天。
- YARA 扫描：调用本机外部 `yara.exe` / `yara64.exe`，支持选择规则目录并批量检测规则错误、选择文件夹扫描、补充单文件路径扫描、列出进程并默认全选或部分勾选做进程内存扫描、超时、并发限制，并把命中结果关联到 PID、进程名和路径。
- CSV 导出：进程、主机信息、关注项、威胁分析、文件痕迹、历史通信、事件日志均支持导出。

## Windows 兼容性说明

GUI 版依赖 Microsoft Edge WebView2 Runtime。Windows 10/11 和较新的 Windows Server 通常已自带或可通过 Edge/WebView2 Runtime 安装获得。

当前 1.0 GUI 包使用本机 Go 工具链构建，目标为 `windows/amd64`，优先面向：

- Windows 10 / Windows 11
- Windows Server 2016 / 2019 / 2022 / 2025

Windows 7、Windows 8.x、Windows Server 2008 R2、Windows Server 2012 / 2012 R2 属于兼容测试目标。若需要覆盖这些老系统，建议单独使用 Go 1.20.x 构建，并确认系统已安装 WebView2 Runtime 或具备可用的 Edge WebView2 环境：

```powershell
$env:GOOS='windows'
$env:GOARCH='amd64'
go build -trimpath -ldflags "-H windowsgui -s -w -X main.version=1.0.0-basic-gui-win7" -o dist\wintracelens-v1.0-basic-gui-win7\WinTraceLens.exe .\cmd\wintracelensgui
```

老系统能力限制：

- Windows 7 默认 PowerShell 版本较低，建议安装 WMF 5.1；否则部分主机信息、事件日志和 JSON 输出能力可能不可用。
- 内存异常检测依赖进程访问权限；未管理员运行时会跳过较多系统进程或受保护进程。JIT、浏览器、聊天客户端、开发工具、安全软件、PowerShell/.NET 运行时以及 Windows Explorer Shell 扩展也可能出现私有可执行内存或 Hook 行为，程序会做常见软件上下文降噪；由本工具启动的采集用 PowerShell 子进程也会单独标注，但仍需要结合进程路径、签名、网络连接和持久化证据判断。
- `Get-DnsClientCache` 在老系统上不可用时，程序会尝试回退到 `ipconfig /displaydns`。
- Sysmon、WFP 5156/5157、防火墙日志不是 Windows 默认完整历史连接数据库；未安装或未启用时，历史通信页会显示中文提示。
- 安全日志、登录日志、WFP 审计通常需要管理员权限和对应审计策略。
- SQL Server 日志只有在系统安装 SQL Server 服务并产生 Application 日志时才会显示。
- YARA 功能需要用户自行提供兼容当前系统的 YARA 引擎；可将 `yara64.exe` 或 `yara.exe` 放在程序目录、`bin` 子目录，或加入 PATH。

## 打包边界

1.0 基础版是单文件 GUI 工具，HTML/CSS/JS 已嵌入 exe。程序内部使用本地回环地址承载数据接口，但用户交互发生在桌面窗口内。

当前包不包含：

- 驱动或内核采集能力。
- 自动启用审计策略。
- 自动安装 Sysmon。
- 自动安装 WebView2 Runtime。
- 自动提升管理员权限。
- 自动打包 YARA 引擎或第三方 YARA 规则库；规则库进入发行包前必须先做许可证审查。
