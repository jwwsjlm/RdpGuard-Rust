# RdpGuard 高级说明

普通安装和查看日志请阅读项目根目录的 `README.md`。本页用于源码构建、手动诊断和 Release 维护。

## 配置范围

| 配置项 | 允许范围 |
| --- | ---: |
| `check_interval_seconds` | 10–3600 秒 |
| `window_minutes` | 1–1440 分钟 |
| `failure_threshold` | 1–10000 次 |
| `block_minutes` | 1–525600 分钟 |

`whitelist` 接受单个 IPv4/IPv6 地址，不支持端口、主机名或 CIDR。安装器默认打开交互配置；自动化环境可使用 `-NonInteractive` 保留现有有效配置或采用默认配置。

## 手动诊断

发布目录中执行只读检查：

```powershell
.\rdpguard.exe --dry-run `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

`--dry-run` 不修改防火墙、状态文件或日志。真实执行一轮会修改系统，只能在管理员 PowerShell 中使用：

```powershell
.\rdpguard.exe --once `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

查看服务与恢复策略：

```powershell
sc.exe qc RdpGuard
sc.exe qfailure RdpGuard
```

## 从源码构建

安装 Rust stable 和 Visual Studio Build Tools 的“使用 C++ 的桌面开发”组件：

```powershell
rustup default stable
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Test-InstallerConfig.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Test-OnlineInstaller.ps1
cargo build --release --locked
```

服务使用 Windows Event Log、Firewall COM 和 Windows Service API。监控器使用 Security/RdpCoreTS 历史事件与 Ratatui/Crossterm，只按需运行，不查询实时 TCP 连接。

## 发布

Cargo 版本、在线脚本内的 `$ReleaseTag` 与 Git 标签必须一致：

```powershell
git push origin main
git tag -a v0.3.3 -m "RdpGuard v0.3.3"
git push origin v0.3.3
```

Release 工作流重新执行格式检查、Clippy、Rust/PowerShell 测试和 release 构建，然后发布：

- `RdpGuard-Rust-v0.3.3.zip`
- `SHA256SUMS.txt`
- `Install-RdpGuard-Online.ps1`

ZIP 包含两个 EXE、在线/本地安装器、卸载器、默认配置和文档。`releases/latest/download/Install-RdpGuard-Online.ps1` 指向最新正式版入口；脚本内嵌自身标签，直接下载同标签 ZIP 和校验文件，不依赖 GitHub API 限额。

## 数据与权限

- 安装目录默认只允许 SYSTEM 和本机管理员访问。
- 监控器只在内存中汇总事件，不保存用户名或登录历史。
- 单个事件源每次最多读取 50,000 条，超过时提示结果已截断。
- Security 日志不可用时，监控器仍会尝试显示 RdpCoreTS 防护历史和现有封禁状态。
