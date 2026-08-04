# RdpGuard

[![CI](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/jwwsjlm/RdpGuard-Rust/actions/workflows/ci.yml)

RdpGuard 是一个面向 Windows 的低占用 Rust 服务。它持续读取系统 RDP 事件日志，在同一公网 IP 的失败次数达到阈值后，通过 Windows 防火墙临时阻止该地址。

默认策略：每 60 秒检查一次；同一公网 IP 在最近 10 分钟内失败达到 5 次，封禁 360 分钟。到期自动解封，重启后仍保留未到期的封禁状态。

## 主要特点

- 使用 Rust 编写，无垃圾回收停顿，常驻资源占用低。
- 直接调用 Windows Event Log 和 Firewall COM API，不在服务中启动 `wevtutil` 或 `netsh` 子进程。
- 只接受事件 XML 中名为 `IPString` 的合法公网单播 IPv4/IPv6 地址。
- 支持精确 IP 白名单、自动解封和原子化状态保存。
- 只管理 `RdpGuard AutoBlock <IP>` 规则，不修改现有手工防火墙规则。
- 查询事件、修改防火墙或保存状态失败时采用保守策略，不记录未实际生效的封禁。

## 系统要求

- Windows 10/11，或仍受支持的 Windows Server。
- 已启用远程桌面及对应的 RDP Operational 事件日志。
- 安装、修改服务和查看受保护日志时需要管理员权限。
- 直接使用发布包不需要安装 Rust；从源码构建才需要 Rust stable 和 MSVC Build Tools。

## 快速安装

下载并解压发布包后，以管理员身份打开 PowerShell，进入解压目录：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-RdpGuard.ps1
```

安装器会：

1. 将程序安装到 `C:\ProgramData\RdpGuard`。
2. 将目录 ACL 限制为 SYSTEM 和本机管理员。
3. 先执行一次不会修改系统的 `--dry-run`。
4. 创建 `LocalSystem` 服务并启用延迟自动启动。
5. 设置服务异常退出后的自动恢复。

重复运行安装器可以升级程序。已有的 `C:\ProgramData\RdpGuard\config.json` 会保留，不会被默认配置覆盖。

## 验证安装

```powershell
Get-Service RdpGuard
sc.exe qc RdpGuard
Get-Content C:\ProgramData\RdpGuard\rdpguard.log -Tail 20
```

正常情况下，服务状态为 `Running`，日志每个检查周期出现一条 `check complete`。

查看 RdpGuard 创建的临时防火墙规则：

```powershell
Get-NetFirewallRule -DisplayName 'RdpGuard AutoBlock *' |
    Get-NetFirewallAddressFilter
```

没有达到阈值的地址时查不到自动规则，这是正常情况。

## 配置

默认配置文件：

```json
{
  "check_interval_seconds": 60,
  "window_minutes": 10,
  "failure_threshold": 5,
  "block_minutes": 360,
  "whitelist": []
}
```

| 配置项 | 默认值 | 允许范围 | 作用 |
| --- | ---: | ---: | --- |
| `check_interval_seconds` | `60` | `10`–`3600` | 两次检查之间的等待秒数。设置过低会增加事件日志查询频率。 |
| `window_minutes` | `10` | `1`–`1440` | 统计同一 IP 失败次数的时间窗口。窗口越大，单次查询的数据可能越多。 |
| `failure_threshold` | `5` | `1`–`10000` | 时间窗口内触发封禁所需的失败次数。 |
| `block_minutes` | `360` | `1`–`525600` | 每次自动封禁持续的分钟数，最大一年。 |
| `whitelist` | `[]` | 精确 IP 数组 | 永不自动封禁的 IPv4/IPv6 地址；目前不支持 CIDR 网段。 |

所有数值必须是 JSON 正整数，不能带引号。超出安全范围或 JSON 格式错误时，本轮检查不会修改防火墙或状态文件，错误会写入日志，服务随后按 60 秒保守间隔重试。

### 修改已安装配置

以管理员身份编辑：

```powershell
notepad C:\ProgramData\RdpGuard\config.json
Restart-Service RdpGuard
Get-Content C:\ProgramData\RdpGuard\rdpguard.log -Tail 10
```

服务每轮都会重新读取配置；重启服务可以让新配置立即生效。

### 白名单示例

如果你有固定的办公出口 IP 或可信 IPv6 地址：

```json
{
  "check_interval_seconds": 60,
  "window_minutes": 10,
  "failure_threshold": 5,
  "block_minutes": 360,
  "whitelist": [
    "203.0.113.10",
    "2001:db8::10"
  ]
}
```

上面的地址仅用于演示，请替换成自己的真实公网地址。白名单按单个 IP 精确匹配，不要填写端口、主机名或 CIDR。

### 调整建议

- 日常使用建议先保持默认 `60 / 10 / 5 / 360`。
- 经常出现误封时，优先提高 `failure_threshold`，例如改为 `8`，而不是盲目缩短封禁时间。
- 攻击频繁时，可以将阈值降至 `3`，但应先把自己的固定出口 IP 加入白名单。
- `window_minutes` 越大，读取的历史事件越多；不建议为了长期统计而设成数小时或数天。

## 日志和状态

- 运行日志：`C:\ProgramData\RdpGuard\rdpguard.log`
- 封禁状态：`C:\ProgramData\RdpGuard\state.json`
- 配置文件：`C:\ProgramData\RdpGuard\config.json`

这些文件默认只能由 SYSTEM 和本机管理员读取。不要手工修改 `state.json`；需要清空自动封禁时，应先停止服务，再使用 Windows 防火墙管理工具处理对应的 `RdpGuard AutoBlock *` 规则。

## 手动试运行

发布包内可以执行：

```powershell
.\rdpguard.exe --dry-run `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

`--dry-run` 会读取真实事件和已有状态，但不会修改防火墙、状态文件或日志。输出中的 `dry-run:` 表示如果正式运行将执行的动作。

`--once` 会真实修改防火墙和状态，只应在管理员窗口中用于诊断：

```powershell
.\rdpguard.exe --once `
    --config .\config.json `
    --state .\state.json `
    --log .\rdpguard.log
```

其他命令：

```powershell
.\rdpguard.exe --help
.\rdpguard.exe --version
```

## 从源码构建

安装 Rust stable、Visual Studio Build Tools 的“使用 C++ 的桌面开发”组件，然后执行：

```powershell
rustup default stable
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
Copy-Item .\target\release\rdpguard.exe .\rdpguard.exe -Force
```

复制 release 程序到仓库根目录后，可以直接运行 `Install-RdpGuard.ps1`。

## 升级

1. 备份 `C:\ProgramData\RdpGuard\config.json`。
2. 下载并解压新版本。
3. 在管理员 PowerShell 中运行新版本的 `Install-RdpGuard.ps1`。
4. 检查服务状态和最新日志。

安装器默认保留现有配置、状态和日志。新版本增加配置字段时，缺失字段会使用程序默认值；建议同时参考新版 `config.json` 和本节配置表。

## 卸载

以管理员身份执行：

```powershell
.\Uninstall-RdpGuard.ps1
```

默认保留配置、状态和日志。彻底删除数据：

```powershell
.\Uninstall-RdpGuard.ps1 -RemoveData
```

卸载器只删除 `RdpGuard AutoBlock *` 规则，不修改手工黑名单或其他防火墙规则。

## 发布到 GitHub

仓库默认分支为 `main`。创建空的 GitHub 仓库后，在本地执行：

```powershell
git remote add origin https://github.com/你的用户名/rdpguard.git
git push -u origin main
```

发布版本时创建与 Cargo 版本一致的标签，Release 工作流会自动构建并上传附件：

```powershell
git tag -a v0.2.1 -m "RdpGuard v0.2.1"
git push origin v0.2.1
```

仓库包含以下自动化维护：

- GitHub Actions 在每次推送和 Pull Request 时运行格式检查、Clippy、测试和 Windows release 构建。
- 成功构建后上传 `rdpguard-windows-x64` 构件。
- 推送与 Cargo 版本一致的 `v*.*.*` 标签后，Release 工作流自动发布 Windows ZIP 和 SHA-256 校验文件。

## 安全说明

RdpGuard 用于降低密码爆破风险，不等同于完整的远程访问边界。公网直接开放 TCP 3389 仍有额外风险，建议同时启用 NLA、强密码和账户锁定；条件允许时优先通过 VPN、RD Gateway 或源地址白名单访问 RDP。

安全问题请使用 GitHub 的 Private vulnerability reporting，不要在公开 Issue 中披露可直接利用的细节。

## 许可证

[MIT](LICENSE)
