[CmdletBinding()]
param([switch]$LibraryMode)

$ErrorActionPreference = 'Stop'
$Repository = 'jwwsjlm/RdpGuard-Rust'
$ReleaseTag = 'v0.3.3'

function Resolve-RdpGuardLanguage {
    param(
        [Parameter(Mandatory)][string]$Language,
        [Parameter(Mandatory)][string]$UiCulture
    )
    if ($Language -ne 'auto') { return $Language }
    if ($UiCulture.StartsWith('zh', [StringComparison]::OrdinalIgnoreCase)) { return 'zh-CN' }
    return 'en-US'
}

function Get-OnlineText {
    param(
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language,
        [Parameter(Mandatory)][string]$Key
    )
    $messages = @{
        Title = @('RdpGuard 在线工具', 'RdpGuard Online Tool')
        Install = @('[1] 安装或配置防护服务', '[1] Install or configure protection service')
        History = @('[2] 查看历史登录日志', '[2] View historical login logs')
        Language = @('[3] English', '[3] 中文')
        Exit = @('[0] 退出', '[0] Exit')
        Choice = @('请选择', 'Select an option')
        InvalidChoice = @('无效选项，请输入 0、1、2 或 3。', 'Invalid option. Enter 0, 1, 2 or 3.')
        Downloading = @('正在下载并校验最新正式版...', 'Downloading and verifying the latest stable release...')
        Ready = @('发布包校验通过。', 'Release package verification passed.')
        OperationFailed = @('操作失败', 'Operation failed')
        InstallFailed = @('安装器返回失败状态', 'Installer returned a failure status')
        MonitorFailed = @('历史日志监控器返回失败状态', 'History monitor returned a failure status')
    }
    if (-not $messages.ContainsKey($Key)) { throw "Unknown message key: $Key" }
    if ($Language -eq 'zh-CN') { return $messages[$Key][0] }
    return $messages[$Key][1]
}

function Get-ExpectedArchiveHash {
    param(
        [Parameter(Mandatory)][string]$ChecksumText,
        [Parameter(Mandatory)][string]$ArchiveName
    )
    $escapedName = [regex]::Escape($ArchiveName)
    $found = [regex]::Matches($ChecksumText, "(?im)^([0-9a-f]{64})[ `t]+\*?$escapedName[ `t]*$")
    if ($found.Count -ne 1) {
        throw "Checksum file must contain exactly one SHA-256 entry for $ArchiveName."
    }
    return $found[0].Groups[1].Value.ToLowerInvariant()
}

function Assert-ArchiveHash {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual
    )
    if (-not $Expected.Equals($Actual, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release archive SHA-256 mismatch. Expected $Expected but received $Actual."
    }
}

function Assert-SafeDownloadUri {
    param([Parameter(Mandatory)][string]$Value)
    $uri = [Uri]$Value
    $allowedHosts = @('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com')
    if ($uri.Scheme -ne 'https' -or $uri.Host -notin $allowedHosts) {
        throw "Unexpected GitHub release download URL: $Value"
    }
    return $uri.AbsoluteUri
}

function Remove-TemporaryBundle {
    param([AllowNull()][string]$TemporaryDirectory)
    if ([string]::IsNullOrWhiteSpace($TemporaryDirectory) -or -not (Test-Path -LiteralPath $TemporaryDirectory)) { return }

    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $candidate = [IO.Path]::GetFullPath($TemporaryDirectory)
    $leaf = Split-Path -Leaf $candidate
    if (-not $candidate.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or -not $leaf.StartsWith('RdpGuard-', [StringComparison]::Ordinal)) {
        throw "Refusing to remove unexpected temporary path: $candidate"
    }
    Remove-Item -LiteralPath $candidate -Recurse -Force
}

function Invoke-WithTemporaryCleanup {
    param(
        [Parameter(Mandatory)][string]$TemporaryDirectory,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    try { & $Action } finally { Remove-TemporaryBundle $TemporaryDirectory }
}

function Get-VerifiedReleaseBundle {
    $tempDirectory = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($ReleaseTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'The launcher contains an invalid release tag.' }
        $headers = @{ 'User-Agent' = 'RdpGuard-Online-Installer' }
        $archiveName = "RdpGuard-Rust-$ReleaseTag.zip"
        $releaseBase = "https://github.com/$Repository/releases/download/$ReleaseTag"
        $archiveUri = Assert-SafeDownloadUri "$releaseBase/$archiveName"
        $checksumUri = Assert-SafeDownloadUri "$releaseBase/SHA256SUMS.txt"
        $tempDirectory = Join-Path ([IO.Path]::GetTempPath()) "RdpGuard-$([Guid]::NewGuid().ToString('N'))"
        $archivePath = Join-Path $tempDirectory $archiveName
        $checksumPath = Join-Path $tempDirectory 'SHA256SUMS.txt'
        $extractPath = Join-Path $tempDirectory 'extracted'
        New-Item -ItemType Directory -Path $tempDirectory | Out-Null

        Invoke-WebRequest -Uri $archiveUri -Headers $headers -UseBasicParsing -OutFile $archivePath
        Invoke-WebRequest -Uri $checksumUri -Headers $headers -UseBasicParsing -OutFile $checksumPath
        $expected = Get-ExpectedArchiveHash (Get-Content -LiteralPath $checksumPath -Raw) $archiveName
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-ArchiveHash $expected $actual

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath
        $roots = @(Get-ChildItem -LiteralPath $extractPath -Directory)
        if ($roots.Count -ne 1) { throw 'Release archive must contain exactly one root directory.' }
        $root = $roots[0].FullName
        foreach ($required in @('Install-RdpGuard.ps1', 'Install-RdpGuard-Online.ps1', 'rdpguard.exe', 'rdpguard-monitor.exe', 'config.json')) {
            if (-not (Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) {
                throw "Verified release archive is missing $required."
            }
        }
        return [pscustomobject]@{ Root = $root; TempDirectory = $tempDirectory; Tag = $ReleaseTag }
    } catch {
        if ($tempDirectory) { Remove-TemporaryBundle $tempDirectory }
        throw
    }
}

function Invoke-RdpGuardMenuChoice {
    param(
        [Parameter(Mandatory)][string]$Choice,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language,
        [AllowNull()]$Bundle,
        [Parameter(Mandatory)][scriptblock]$BundleProvider,
        [Parameter(Mandatory)][scriptblock]$InstallAction,
        [Parameter(Mandatory)][scriptblock]$MonitorAction
    )

    $result = [ordered]@{ Exit = $false; Valid = $true; Language = $Language; Bundle = $Bundle }
    switch ($Choice.Trim()) {
        '0' { $result.Exit = $true }
        '3' { $result.Language = if ($Language -eq 'zh-CN') { 'en-US' } else { 'zh-CN' } }
        '1' {
            if ($null -eq $result.Bundle) {
                Write-Host (Get-OnlineText $Language Downloading) -ForegroundColor Cyan
                $result.Bundle = & $BundleProvider
                Write-Host (Get-OnlineText $Language Ready) -ForegroundColor Green
            }
            & $InstallAction $result.Bundle $result.Language | ForEach-Object { Write-Host $_ }
        }
        '2' {
            if ($null -eq $result.Bundle) {
                Write-Host (Get-OnlineText $Language Downloading) -ForegroundColor Cyan
                $result.Bundle = & $BundleProvider
                Write-Host (Get-OnlineText $Language Ready) -ForegroundColor Green
            }
            & $MonitorAction $result.Bundle $result.Language | ForEach-Object { Write-Host $_ }
        }
        default { $result.Valid = $false }
    }
    return [pscustomobject]$result
}

function Invoke-OnlineLauncher {
    $language = Resolve-RdpGuardLanguage -Language auto -UiCulture $PSUICulture
    $bundle = $null
    $bundleProvider = { Get-VerifiedReleaseBundle }
    $installAction = {
        param($VerifiedBundle, $SelectedLanguage)
        $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $installer = Join-Path $VerifiedBundle.Root 'Install-RdpGuard.ps1'
        & $windowsPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installer -Language $SelectedLanguage
        if ($LASTEXITCODE -ne 0) { throw "$(Get-OnlineText $SelectedLanguage InstallFailed): $LASTEXITCODE" }
    }
    $monitorAction = {
        param($VerifiedBundle, $SelectedLanguage)
        $monitor = Join-Path $VerifiedBundle.Root 'rdpguard-monitor.exe'
        & $monitor --language $SelectedLanguage
        if ($LASTEXITCODE -ne 0) { throw "$(Get-OnlineText $SelectedLanguage MonitorFailed): $LASTEXITCODE" }
    }

    try {
        while ($true) {
            Write-Host ''
            Write-Host (Get-OnlineText $language Title) -ForegroundColor Cyan
            Write-Host (Get-OnlineText $language Install)
            Write-Host (Get-OnlineText $language History)
            Write-Host (Get-OnlineText $language Language)
            Write-Host (Get-OnlineText $language Exit)
            $choice = Read-Host (Get-OnlineText $language Choice)
            try {
                $result = Invoke-RdpGuardMenuChoice $choice $language $bundle $bundleProvider $installAction $monitorAction
                $language = $result.Language
                $bundle = $result.Bundle
                if (-not $result.Valid) { Write-Host (Get-OnlineText $language InvalidChoice) -ForegroundColor Yellow }
                if ($result.Exit) { break }
            } catch {
                Write-Host "$(Get-OnlineText $language OperationFailed): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } finally {
        if ($null -ne $bundle) { Remove-TemporaryBundle $bundle.TempDirectory }
    }
}

if ($LibraryMode) { return }
Invoke-OnlineLauncher
