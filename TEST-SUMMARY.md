# RdpGuard v0.2.0 验收摘要

验收日期：2026-08-04

## 发布策略

- 默认每 60 秒检查一次，可在 10–3600 秒范围内配置。
- 同一公网 IP 在 10 分钟内失败达到 5 次时，封禁 360 分钟。
- 到期自动解封；白名单和未到期封禁状态持久化。
- 只管理名称以 `RdpGuard AutoBlock ` 开头的防火墙规则。

## 自动化验证

- `cargo fmt --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过，零警告。
- `cargo test --all-targets`：23 项测试通过，0 失败。
- `cargo build --release`：通过。
- 安装器和卸载器 PowerShell 语法检查：通过。
- 默认 `config.json` JSON 解析：通过。
- Windows 本机 Event Log `--dry-run`：通过，未修改防火墙、状态或日志。
- 发布程序版本：`rdpguard 0.2.0`。

## 重点覆盖

- 配置默认值、缺失字段兼容和安全范围验证。
- RDP 事件 XML 只提取命名的合法 `IPString`。
- 内网、回环、组播等不可路由来源不会进入封禁。
- 第 5 次失败触发封禁，未达到阈值不封禁。
- 白名单、重复运行、到期解封和状态持久化。
- 事件查询、防火墙或状态保存失败时的保守处理与回滚。
- CLI 帮助、版本、未知参数和 dry-run 行为。

## 发布文件

- `rdpguard.exe` 大小：604,160 字节。
- `rdpguard.exe` SHA-256：`1DAC981B84F29708BF3C5CEBAFA4866807539A6FE3DC700E8A3F4556576DCA61`。
- Cargo 直接依赖已核对为 2026-08-04 的 crates.io 最新稳定版本。
- GitHub Actions 工作流已通过最新版 `actionlint` 和 Prettier 检查。

本次仓库整理没有替换或重启当前计算机上已运行的服务。使用 v0.2.0 的可配置检查间隔时，请按 README 的升级步骤重新运行安装器。
