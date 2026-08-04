# Security Policy

## Supported versions

安全修复只保证应用于最新发布版本。

## Reporting a vulnerability

请优先使用 GitHub 仓库的 **Private vulnerability reporting** 报告安全问题。不要在公开 Issue、讨论区或日志截图中披露可利用细节、真实凭据、内网地址或远程桌面账户信息。

报告中建议包含受影响版本、复现条件、预期影响和最小化的复现步骤。请勿在未获授权的计算机上测试。

## Release 验证

当前 Windows EXE 未使用 Authenticode 签名。正式 Release 为 x64、ARM64、x86 包提供 SHA-256、CycloneDX SBOM 和 GitHub build provenance。在线安装器只接受 HTTPS GitHub 地址，并在管理员专用暂存目录中校验压缩包后执行。

建议同时核对：Release 标签与程序 `--version` 一致、SHA-256 匹配 `SHA256SUMS.txt`，并使用 `gh attestation verify` 验证构建证明。
