# Changelog

## 0.2.2 - 2026-08-04

- 安装器在非管理员 PowerShell 中运行时自动请求 UAC 提权。
- 使用编码命令安全传递包含空格、中文或单引号的安装器路径。
- 等待提权进程结束并检查退出码，取消 UAC 或安装失败时返回明确错误。

## 0.2.1 - 2026-08-04

- 移除 Dependabot 每周依赖检查。
- 新增标签触发的 GitHub Release 工作流，自动发布 Windows ZIP 和 SHA-256 校验文件。

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
