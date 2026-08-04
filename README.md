# RdpGuard

[![CI](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jwwsjlm/RdpGuard-Rust)](https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest)

轻量级 Windows RDP 防护服务：统计远程桌面失败连接，并通过 Windows 防火墙临时封禁重复攻击的公网 IP。

默认策略：每 60 秒检查一次；同一 IP 在最近 10 分钟内失败 5 次，封禁 360 分钟（6 小时），到期自动解封。

## 一行启动

打开 Windows PowerShell 或终端，粘贴：

```powershell
& ([scriptblock]::Create((irm "https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest/download/Install-RdpGuard-Online.ps1")))
```

随后选择：

```text
[1] 安装或配置防护服务
[2] 查看历史登录日志
[3] English / 中文
[0] 退出
```

程序根据 Windows 显示语言自动选择中文或英文，按 `3` 可以切换。发布包会先校验 SHA-256，校验失败不会执行。

## 安装和配置

选择 `1` 后确认 UAC，按提示配置：

- 检查间隔
- 失败统计窗口
- 同一 IP 的失败次数
- 封禁时长
- 单个日志文件上限
- 保留的历史日志文件数
- IPv4/IPv6 白名单

已有安装会显示当前配置，直接按 Enter 保留原值。配置完成后自动安装或升级，原有日志、封禁状态和配置会保留。

检查服务：

```powershell
Get-Service RdpGuard
```

正常状态为 `Running`。

## 查看历史日志

重新运行一行命令并选择 `2`。即使没有安装防护服务，也可以临时查看 Windows 保存的 RDP 登录历史；退出后会删除临时程序。

监控器只在打开时读取一次，不自动刷新，也不常驻后台：

| 按键 | 作用 |
| --- | --- |
| `Tab` / `Shift+Tab` | 切换 IP 历史概览、登录事件 |
| `1` / `2` / `3` / `4` | 最近 10 分钟、1 小时、24 小时、7 天 |
| `r` | 手动重新读取 |
| `l` | 中文 / English |
| `↑` / `↓` | 滚动 |
| `q` / `Esc` | 退出 |

后台 `RdpGuard` 防护服务仍会持续运行并自动封禁；历史日志监控器只是按需查看工具。

## 系统要求

- Windows 10/11 或仍受支持的 Windows Server
- 已启用远程桌面
- 安装服务和读取 Security 登录日志时需要管理员权限
- 使用 Release 不需要安装 Rust 或其他运行库

## 日志和配置

安装目录：

```text
C:\ProgramData\RdpGuard
```

查看最近服务日志：

```powershell
Get-Content "C:\ProgramData\RdpGuard\rdpguard.log" -Tail 50
```

主要文件：

```text
config.json    防护设置
state.json     当前封禁及解封时间
rdpguard.log   服务运行日志
```

日志默认达到 10 MB 时自动轮转，保留 `rdpguard.log.1` 到 `rdpguard.log.5`。可在配置向导或 `config.json` 中调整 `max_log_size_mb` 和 `log_retention_files`。

## 升级

重新运行一行命令，选择 `1`。安装器会下载最新正式版并保留现有数据。

## 手动安装和卸载

无法使用在线方式时，下载并解压[最新 Release](https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest)。

安装或升级：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-RdpGuard.ps1
```

卸载并保留配置、状态和日志：

```powershell
.\Uninstall-RdpGuard.ps1
```

同时删除数据：

```powershell
.\Uninstall-RdpGuard.ps1 -RemoveData
```

## 安全建议

RdpGuard 用于降低密码爆破风险，不能替代完整的远程访问防护。请同时启用 NLA、强密码和账户锁定；条件允许时优先通过 VPN、RD Gateway 或固定来源 IP 访问 RDP。

源码构建、手动诊断和发布说明见[高级文档](docs/ADVANCED.md)。

## 许可证

[MIT](LICENSE)
