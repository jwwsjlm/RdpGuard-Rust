# RdpGuard（Rust）设计说明

## 目标

在 Windows 11 上按可配置间隔检查 RDP 登录失败事件，默认每 60 秒一次。同一来源 IP 在最近 10 分钟内失败达到 5 次时，自动创建入站防火墙阻止规则；规则持续 360 分钟，到期自动解除。

## 实现方案

核心程序使用 Rust 编译为单个 `rdpguard.exe`，并注册为自动启动的 Windows 服务。安装和卸载使用 PowerShell 脚本，因为服务注册与管理员提权由系统脚本处理更直接。

服务以受限文件权限下的 `LocalSystem` 身份运行，按配置的安全间隔执行检查。服务不开放端口、不接受网络输入，也不启动命令行子进程；异常退出时由 Windows 服务恢复机制自动重启。

## 数据流

1. Rust 程序直接调用 Windows Event Log API，查询日志 `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` 中最近 10 分钟的事件 ID `140`。
2. 从事件 XML 的 `EventData/Data[@Name='IPString']` 读取来源 IP；只接受可解析的 IPv4/IPv6 地址，拒绝任意可执行文本。
3. 排除回环、未指定、组播和私有地址，再应用用户配置的白名单。
4. 按 IP 聚合失败次数，达到 5 次的来源进入封禁流程。
5. 直接调用 Windows Firewall COM API 创建命名规则 `RdpGuard AutoBlock <IP>`，阻止该 IP 的所有入站协议和所有网络配置文件。
6. 将 IP、创建时间、过期时间和失败次数写入 `C:\ProgramData\RdpGuard\state.json`。
7. 每次运行先清理已经到期的规则；只有防火墙删除成功后才从状态中移除。

## 配置与文件

- 程序：`C:\ProgramData\RdpGuard\rdpguard.exe`
- 配置：`C:\ProgramData\RdpGuard\config.json`
- 状态：`C:\ProgramData\RdpGuard\state.json`
- 日志：`C:\ProgramData\RdpGuard\rdpguard.log`
- Windows 服务：`RdpGuard`

默认配置：

```json
{
  "check_interval_seconds": 60,
  "window_minutes": 10,
  "failure_threshold": 5,
  "block_minutes": 360,
  "whitelist": []
}
```

达到阈值即封禁，也就是第 5 次失败触发。公网白名单默认为空，避免把曾经成功登录过的地址永久当作可信地址；如果需要，可手动把稳定的管理 IP 加入 `whitelist`。

## 安全与错误处理

- 只有经过 Rust `IpAddr` 校验的地址会传给防火墙命令，防止命令注入。
- 状态文件使用临时文件加原子替换，降低断电或进程终止导致文件损坏的风险。
- 查询事件日志失败时不修改防火墙；错误写入日志并返回非零退出码。
- 已有同名自动规则会先规范化再写入，避免重复规则。
- 现有手动规则 `Codex - Block RDP Failed IPs` 不会被读取、修改或删除。
- `--dry-run` 只报告将要封禁或解封的地址，不改变系统。

## 安装与卸载

`Install-RdpGuard.ps1` 将编译后的程序和默认配置复制到 ProgramData，注册自动启动的 Windows 服务、配置失败恢复并启动服务。安装操作需要管理员权限。

`Uninstall-RdpGuard.ps1` 停止并删除服务及所有 `RdpGuard AutoBlock` 规则；默认保留日志，支持显式参数删除数据目录。

## 测试策略

Rust 单元测试使用固定事件 XML 和临时时钟，覆盖：

- 正确提取 `IPString`；
- 忽略无效、内网和白名单地址；
- 10 分钟窗口边界；
- 4 次不封、5 次封；
- 360 分钟之前保留、到期后解封；
- 重复运行不产生重复状态；
- 损坏配置或事件查询失败时不修改防火墙。

集成验证使用 `--dry-run` 读取本机现有事件，随后检查服务状态、自动启动、失败恢复、配置和程序版本。不会通过制造真实登录失败来测试，以免锁定用户账号。
