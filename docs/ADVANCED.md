# RdpGuard 高级说明

本页面向需要从源码构建、手动诊断或维护 Release 的用户。普通安装请直接阅读项目根目录的 `README.md`。

## 配置范围

| 配置项 | 允许范围 |
| --- | ---: |
| `check_interval_seconds` | 10–3600 秒 |
| `window_minutes` | 1–1440 分钟 |
| `failure_threshold` | 1–10000 次 |
| `block_minutes` | 1–525600 分钟 |

所有数值必须是 JSON 正整数。`whitelist` 只支持单个 IPv4/IPv6 地址，不支持端口、主机名或 CIDR。

配置无效、事件查询失败、防火墙修改失败或状态保存失败时，本轮采用保守策略，不记录未实际生效的封禁。服务会按保守间隔重试。

## 手动诊断

发布目录中执行只读检查：

```powershell
.\rdpguard.exe --dry-run `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

`--dry-run` 读取真实事件和已有状态，但不修改防火墙、状态文件或日志。

真实执行一轮会修改系统，只能在管理员 PowerShell 中用于诊断：

```powershell
.\rdpguard.exe --once `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

服务详情与恢复策略：

```powershell
sc.exe qc RdpGuard
sc.exe qfailure RdpGuard
```

## 从源码构建

安装 Rust stable 和 Visual Studio Build Tools 的“使用 C++ 的桌面开发”组件：

```powershell
rustup default stable
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
Copy-Item .\target\release\rdpguard.exe .\rdpguard.exe -Force
Copy-Item .\target\release\rdpguard-monitor.exe .\rdpguard-monitor.exe -Force
```

后台服务使用 Windows Event Log、Firewall COM 和 Windows Service API。监控器额外使用 Security 事件日志、IP Helper TCP 表和 Ratatui/Crossterm；监控器按需启动，不会进入服务进程。

## 发布

Cargo 版本与 Git 标签必须一致：

```powershell
git tag -a v0.3.0 -m "RdpGuard v0.3.0"
git push origin main
git push origin v0.3.0
```

Release 工作流会在 Windows runner 上重新执行格式检查、Clippy、测试和 release 构建，然后发布 ZIP 与 `SHA256SUMS.txt`。

发布 ZIP 包含：

- `rdpguard.exe`
- `rdpguard-monitor.exe`
- 安装器、卸载器和默认配置
- README、更新记录、许可证、测试摘要和本高级文档

## 数据与权限

- 安装目录默认只允许 SYSTEM 和本机管理员访问。
- 监控器只在内存中汇总事件，不保存用户名或登录历史。
- 单个数据源每次最多读取 50,000 条事件，超过时在界面提示结果已截断。
- Security 日志不可用时，监控器仍会尝试显示防护失败、封禁状态和当前 RDP TCP 连接。
