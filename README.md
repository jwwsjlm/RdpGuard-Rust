# RdpGuard

[![CI](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jwwsjlm/RdpGuard-Rust)](https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest)

轻量级 Windows RDP 防护服务。默认每分钟检查一次；同一公网 IP 在 10 分钟内失败 5 次后封禁 6 小时。重复攻击会按 6 小时、12 小时、24 小时、48 小时、96 小时递增，最长 7 天；连续 30 天无复犯后重置。

## 系统要求

- Windows 10 22H2/LTSC、Windows 11 或 Windows Server 2019/2022/2025
- x64、ARM64 或 x86
- Windows PowerShell 5.1 及管理员权限

## 一行启动

在 Windows PowerShell 中运行：

```powershell
& ([scriptblock]::Create((irm "https://github.com/jwwsjlm/RdpGuard-Rust/releases/latest/download/Install-RdpGuard-Online.ps1")))
```

```text
[1] 安装或配置防护服务
[2] 查看历史登录日志
[3] English / 中文
[4] 运行诊断
[0] 退出
```

脚本会先请求 UAC，再在受保护目录中下载对应架构的正式版并校验 SHA-256。选择 `1` 后按提示配置；检测到当前公网 RDP 来源时，只会询问是否加入白名单，不会自动放行。

## 查看历史登录

选择 `2`。监控器只在打开、切换时间范围或按 `r` 时读取历史，不自动刷新、不常驻。

| 按键 | 作用 |
| --- | --- |
| `Tab` / `Shift+Tab` | 切换 IP 概览、登录事件 |
| `1` / `2` / `3` / `4` | 10 分钟、1 小时、24 小时、7 天 |
| `r` | 重新读取 |
| `l` | 中文 / English |
| `↑` / `↓` | 滚动 |
| `q` / `Esc` | 退出 |

Security 日志无权限时会显示警告，RDP 失败、封禁状态等可用数据仍会展示。封禁标记以实际 Windows 防火墙规则为准。

## 常用配置

配置文件位于 `C:\ProgramData\RdpGuard\config.json`。通常只需调整：

| 配置 | 默认值 | 含义 |
| --- | ---: | --- |
| `window_minutes` | `10` | 失败统计窗口 |
| `failure_threshold` | `5` | 触发封禁次数 |
| `block_minutes` | `360` | 首次封禁分钟数 |
| `whitelist` | `[]` | 单 IP 或 CIDR 白名单 |

重新运行在线工具并选择 `1` 可安全修改。高级设置包括仅拦截 RDP 端口、递增倍数、最长封禁、容量和心跳间隔。

## 日志与诊断

服务日志：`C:\ProgramData\RdpGuard\rdpguard.log`。动作和错误立即记录，正常健康心跳默认每小时一次；单文件默认 10 MB，保留 5 个历史文件。

在线菜单选择 `4`，或在管理员 PowerShell 中运行：

```powershell
& "C:\ProgramData\RdpGuard\rdpguard.exe" doctor --language zh-CN
```

JSON 输出：

```powershell
& "C:\ProgramData\RdpGuard\rdpguard.exe" doctor --json
```

## 升级与卸载

升级：重新运行一行命令并选择 `1`。升级会预检、备份并等待新服务真正就绪；失败时恢复旧程序、配置和服务。

手动安装必须先打开“以管理员身份运行”的 PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-RdpGuard.ps1
```

卸载：

```powershell
.\Uninstall-RdpGuard.ps1              # 保留配置、状态和日志
.\Uninstall-RdpGuard.ps1 -RemoveData  # 同时删除数据
```

## 安全建议

RdpGuard 用于降低爆破风险，不能替代 NLA、强密码、账户锁定、VPN 或 RD Gateway。公网开放 3389 会持续被扫描；条件允许时请限制来源地址。

正式 EXE 暂未使用 Authenticode 签名。请通过 Release 的 SHA-256、CycloneDX SBOM 和 GitHub build provenance 验证来源。完整配置、构建和验证方法见[高级文档](docs/ADVANCED.md)，漏洞报告见[安全策略](SECURITY.md)。

许可证：[MIT](LICENSE)
