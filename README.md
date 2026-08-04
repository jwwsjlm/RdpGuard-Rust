# RdpGuard

[![CI](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml)

轻量级 Windows RDP 防护服务。它自动统计远程桌面失败连接，并通过 Windows 防火墙临时封禁重复攻击的公网 IP。

默认策略：每 60 秒检查一次；同一 IP 在最近 10 分钟内失败 5 次，封禁 360 分钟（6 小时），到期自动解封。

## 功能

- 自动封禁重复失败的公网 IPv4/IPv6 地址。
- 白名单、到期解封、重启后恢复封禁状态。
- Rust 后台服务，直接调用 Windows Event Log 和防火墙 API。
- 独立终端监控器，查看登录成功、登录失败、防护失败和当前连接。
- 只管理 `RdpGuard AutoBlock <IP>` 规则，不修改已有手工规则。

## 系统要求

- Windows 10/11 或仍受支持的 Windows Server。
- 已启用远程桌面。
- 安装和查看 Security 登录日志时需要管理员权限。
- 使用发布包不需要安装 Rust 或其他运行库。

## 快速安装

下载并解压 [最新版本](https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest)，在解压目录打开 PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-RdpGuard.ps1
```

安装器会自动弹出 UAC。确认后，程序安装到：

```text
C:\ProgramData\RdpGuard
```

检查服务：

```powershell
Get-Service RdpGuard
```

正常状态为 `Running`。

## 打开监控器

```powershell
& "C:\ProgramData\RdpGuard\rdpguard-monitor.exe"
```

监控器只读取日志、封禁状态和当前连接，不会修改防火墙。

| 按键 | 作用 |
| --- | --- |
| `Tab` / `Shift+Tab` | 切换 IP 概览、登录事件、当前连接 |
| `1` / `2` / `3` / `4` | 最近 10 分钟、1 小时、24 小时、7 天 |
| `r` | 立即刷新 |
| `↑` / `↓` | 滚动列表 |
| `q` / `Esc` | 退出 |

数据每 30 秒自动刷新。登录成功/失败来自 Security 事件 `4624/4625`；“防护失败”来自 RdpGuard 实际用于封禁的 RdpCoreTS 事件 `140`，两者分开统计。

## 修改配置

管理员 PowerShell 打开配置：

```powershell
notepad "C:\ProgramData\RdpGuard\config.json"
```

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

| 配置项 | 说明 |
| --- | --- |
| `check_interval_seconds` | 检查间隔，默认 60 秒 |
| `window_minutes` | 统计失败的时间范围，默认 10 分钟 |
| `failure_threshold` | 同一 IP 触发封禁的失败次数，默认 5 次 |
| `block_minutes` | 封禁时间，默认 360 分钟 |
| `whitelist` | 永不自动封禁的 IP，例如 `["203.0.113.10"]` |

保存后服务会在下一轮自动读取新配置。建议先把可信固定 IP 加入白名单，再降低失败阈值。

## 日志和规则

查看最近日志：

```powershell
Get-Content "C:\ProgramData\RdpGuard\rdpguard.log" -Tail 50
```

查看已封禁 IP：

```powershell
Get-NetFirewallRule -DisplayName "RdpGuard AutoBlock *" |
    Get-NetFirewallAddressFilter
```

相关文件：

```text
C:\ProgramData\RdpGuard\config.json    配置
C:\ProgramData\RdpGuard\state.json     当前封禁及到期时间
C:\ProgramData\RdpGuard\rdpguard.log   运行日志
```

## 升级

下载并解压新版本，再运行新版 `Install-RdpGuard.ps1`。已有配置、状态和日志会保留。

## 卸载

```powershell
.\Uninstall-RdpGuard.ps1
```

同时删除配置和日志：

```powershell
.\Uninstall-RdpGuard.ps1 -RemoveData
```

## 安全建议

RdpGuard 用于降低密码爆破风险，不能替代完整的远程访问防护。请同时启用 NLA、强密码和账户锁定；条件允许时优先通过 VPN、RD Gateway 或固定来源 IP 访问 RDP。

构建、手动诊断和发布说明见 [高级文档](docs/ADVANCED.md)。

## 许可证

[MIT](LICENSE)
