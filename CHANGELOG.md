# Changelog

## 0.2.0 - 2026-08-04

- 新增 `check_interval_seconds`，检查间隔可在 10–3600 秒内配置。
- 为统计窗口、失败阈值和封禁时长增加安全范围校验。
- 将 CLI 版本测试改为自动读取 Cargo 包版本。
- 补充完整中文安装、配置、升级、构建和 GitHub 发布教程。
- 增加 Git 仓库忽略规则、属性和 MIT 许可证。
- 将全部 Cargo 依赖更新并显式声明为 2026-08-04 的最新稳定版本。
- 新增 Windows GitHub Actions CI、release 构件上传和 Dependabot 自动更新。

## 0.1.0 - 2026-08-04

- 首个 Rust Windows 服务版本。
- 支持 RDP 失败事件聚合、临时防火墙封禁、自动解封、白名单和状态持久化。
- 提供 PowerShell 安装器、卸载器和只读 dry-run。
