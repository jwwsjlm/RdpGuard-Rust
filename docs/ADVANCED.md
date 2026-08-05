# RdpGuard 高级说明

## 完整配置

`schema_version` 当前为 `2`。v0.3.7 配置缺少新字段时会自动使用兼容默认值。

| 配置 | 默认值 | 范围或取值 |
| --- | ---: | --- |
| `check_interval_seconds` | 60 | 10–3600 |
| `window_minutes` | 10 | 1–1440 |
| `failure_threshold` | 5 | 1–10000 |
| `block_minutes` | 360 | 1–525600 |
| `block_scope` | `all_inbound` | `all_inbound` / `rdp_only` |
| `rdp_port` | `null` | 自动读取注册表，或 1–65535 |
| `repeat_block_multiplier` | 2 | 1–16 |
| `max_block_minutes` | 10080 | 不小于首次封禁，最大 525600 |
| `repeat_reset_days` | 30 | 1–3650 |
| `max_active_blocks` | 5000 | 1–100000 |
| `heartbeat_minutes` | 60 | 1–1440 |
| `max_log_size_mb` | 10 | 1–1024 |
| `log_retention_files` | 5 | 1–100 |

`whitelist` 支持 IPv4、IPv6 和 CIDR。IPv4-mapped IPv6 会规范为 IPv4。加入白名单的活动封禁会在下一轮立即解除，同时清除该 IP 的复犯记录。

`all_inbound` 阻止来源 IP 的全部入站协议，兼容旧版本。`rdp_only` 只为实际 RDP 端口建立 TCP/UDP 规则。

## 诊断

```powershell
.\rdpguard.exe doctor --language zh-CN
.\rdpguard.exe doctor --json
```

退出码：`0` 健康，`1` 降级/错误，`2` 参数错误。诊断只读检查服务、版本/架构、配置、两个事件日志、Windows Firewall、规则对账、容量、RDP 端口和当前公网 TCP 来源。

常见错误码：

- `CFG001/CFG002`：配置或 RDP 端口
- `EVT001/EVT002`：RdpCoreTS 或 Security 日志
- `FW001`–`FW005`：防火墙访问、容量、对账、组策略或活动配置未启用
- `STATE001`：状态读取、恢复或写入
- `UPGRADE001`：升级或回滚
- `CONN001`：当前 TCP 会话读取

## 恢复机制

- 每轮先解封到期/白名单 IP，再修复缺失或错误范围的规则并删除孤立规则，最后读取新失败事件。
- `state.json` 损坏时会改名为 `state.json.corrupt-*`，并从防火墙规则描述中的 v2 元数据恢复有效封禁。
- 单 IP 操作失败不会阻断其他 IP；错误集中写入日志。
- 达到活动上限时，完成到期清理后只选择失败次数最多的新 IP，并记录 `FW002`。
- 升级不会删除现有服务；新程序先预检，旧程序/监控器/配置先备份，任一步失败都会回滚并恢复原服务状态。

## 从源码构建

需要最新 Rust stable 和 Visual Studio Build Tools（使用 C++ 的桌面开发）：

```powershell
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Test-InstallerConfig.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\Test-OnlineInstaller.ps1
cargo build --release --locked
```

`.cargo/config.toml` 为 MSVC 目标启用静态 CRT。CI 交叉构建 `x86_64-pc-windows-msvc`、`i686-pc-windows-msvc` 和 `aarch64-pc-windows-msvc`，并验证 PE Machine；x64/x86 额外执行 `--version` 冒烟测试。

## 发布与验证

标签必须与 Cargo 版本及在线脚本 `$ReleaseTag` 一致：

```powershell
git tag -a v0.4.4 -m "RdpGuard v0.4.4"
git push origin main v0.4.4
```

Release 包：

- `RdpGuard-Rust-v0.4.4-windows-x64.zip`
- `RdpGuard-Rust-v0.4.4-windows-arm64.zip`
- `RdpGuard-Rust-v0.4.4-windows-x86.zip`
- 每架构 CycloneDX JSON SBOM
- `SHA256SUMS.txt` 和 GitHub build provenance

校验哈希：

```powershell
Get-FileHash .\RdpGuard-Rust-v0.4.4-windows-x64.zip -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

校验 GitHub 构建证明（需 GitHub CLI）：

```powershell
gh attestation verify .\RdpGuard-Rust-v0.4.4-windows-x64.zip --repo jwwsjlm/RdpGuard-Rust
```
