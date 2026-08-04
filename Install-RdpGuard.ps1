[CmdletBinding()]
param(
    [ValidateSet('auto', 'zh-CN', 'en-US')]
    [string]$Language = 'auto',
    [switch]$NonInteractive,
    [switch]$LibraryMode
)

$ErrorActionPreference = 'Stop'

function Resolve-RdpGuardLanguage {
    param(
        [Parameter(Mandatory)][string]$Language,
        [Parameter(Mandatory)][string]$UiCulture
    )

    if ($Language -ne 'auto') { return $Language }
    if ($UiCulture.StartsWith('zh', [StringComparison]::OrdinalIgnoreCase)) { return 'zh-CN' }
    return 'en-US'
}

function Resolve-InstallerLanguageChoice {
    param(
        [AllowEmptyString()][string]$Raw,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Current
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) { return $Current }
    if ($Raw -in @('l', 'L', '3')) {
        if ($Current -eq 'zh-CN') { return 'en-US' }
        return 'zh-CN'
    }
    throw 'Language choice must be Enter or L.'
}

function Get-RdpGuardText {
    param(
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language,
        [Parameter(Mandatory)][string]$Key
    )

    $messages = @{
        LanguagePrompt = @('当前语言：中文。按 Enter 继续，按 L 切换到 English', 'Current language: English. Press Enter to continue or L for 中文')
        InvalidLanguage = @('请输入 Enter 或 L。', 'Enter is the only other valid choice besides L.')
        ConfigTitle = @('RdpGuard 防护配置', 'RdpGuard protection configuration')
        Current = @('当前值', 'current')
        Range = @('允许范围', 'allowed range')
        Keep = @('直接按 Enter 保留当前值', 'press Enter to keep the current value')
        CheckInterval = @('检查间隔（秒）', 'Check interval (seconds)')
        WindowMinutes = @('失败统计窗口（分钟）', 'Failure window (minutes)')
        FailureThreshold = @('同一 IP 失败次数', 'Failures per IP')
        BlockMinutes = @('封禁时长（分钟）', 'Block duration (minutes)')
        MaxLogSize = @('单个日志文件上限（MB）', 'Maximum log file size (MB)')
        LogRetention = @('保留的历史日志文件数', 'Number of rotated log files to keep')
        Whitelist = @('IP 白名单（逗号分隔；输入 clear 或 清空可清空）', 'IP whitelist (comma-separated; enter clear to empty it)')
        InvalidValue = @('输入无效', 'Invalid value')
        ElevationCancelled = @('管理员权限请求已取消或失败', 'Administrator elevation was cancelled or failed')
        InstallSuccess = @('RdpGuard 已安装并正在运行', 'RdpGuard is installed and running')
        MonitorHint = @('打开历史日志监控器', 'Open the history monitor')
    }
    if (-not $messages.ContainsKey($Key)) { throw "Unknown message key: $Key" }
    if ($Language -eq 'zh-CN') { return $messages[$Key][0] }
    return $messages[$Key][1]
}

function Read-BoundedInteger {
    param(
        [AllowEmptyString()][string]$Raw,
        [Parameter(Mandatory)][long]$Current,
        [Parameter(Mandatory)][long]$Minimum,
        [Parameter(Mandatory)][long]$Maximum
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) { return $Current }
    $parsed = 0L
    if (-not [long]::TryParse($Raw.Trim(), [ref]$parsed)) {
        throw "Value must be an integer between $Minimum and $Maximum."
    }
    if ($parsed -lt $Minimum -or $parsed -gt $Maximum) {
        throw "Value must be between $Minimum and $Maximum."
    }
    return $parsed
}

function Read-Whitelist {
    param(
        [AllowEmptyString()][string]$Raw,
        [AllowEmptyCollection()][string[]]$Current
    )

    if ([string]::IsNullOrWhiteSpace($Raw)) { return @($Current) }
    if ($Raw.Trim() -in @('clear', '清空')) { return @() }

    $addresses = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Raw.Split(',')) {
        $value = $item.Trim()
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($value, [ref]$parsed)) {
            throw "Invalid IP address: $value"
        }
        $canonical = $parsed.IPAddressToString
        if ($seen.Add($canonical)) { $addresses.Add($canonical) }
    }
    return @($addresses)
}

function New-RdpGuardConfig {
    param(
        [Parameter(Mandatory)][long]$CheckIntervalSeconds,
        [Parameter(Mandatory)][long]$WindowMinutes,
        [Parameter(Mandatory)][long]$FailureThreshold,
        [Parameter(Mandatory)][long]$BlockMinutes,
        [Parameter(Mandatory)][long]$MaxLogSizeMb,
        [Parameter(Mandatory)][long]$LogRetentionFiles,
        [AllowEmptyCollection()][string[]]$Whitelist
    )

    return [ordered]@{
        check_interval_seconds = $CheckIntervalSeconds
        window_minutes = $WindowMinutes
        failure_threshold = $FailureThreshold
        block_minutes = $BlockMinutes
        max_log_size_mb = $MaxLogSizeMb
        log_retention_files = $LogRetentionFiles
        whitelist = @($Whitelist)
    }
}

function ConvertTo-ValidatedConfig {
    param([Parameter(Mandatory)]$InputObject)

    $interval = Read-BoundedInteger -Raw ([string]$InputObject.check_interval_seconds) -Current 60 -Minimum 10 -Maximum 3600
    $window = Read-BoundedInteger -Raw ([string]$InputObject.window_minutes) -Current 10 -Minimum 1 -Maximum 1440
    $threshold = Read-BoundedInteger -Raw ([string]$InputObject.failure_threshold) -Current 5 -Minimum 1 -Maximum 10000
    $duration = Read-BoundedInteger -Raw ([string]$InputObject.block_minutes) -Current 360 -Minimum 1 -Maximum 525600
    $maxLogSize = Read-BoundedInteger -Raw ([string]$InputObject.max_log_size_mb) -Current 10 -Minimum 1 -Maximum 1024
    $logRetention = Read-BoundedInteger -Raw ([string]$InputObject.log_retention_files) -Current 5 -Minimum 1 -Maximum 100
    $rawWhitelist = (@($InputObject.whitelist) -join ',')
    $whitelist = @(Read-Whitelist -Raw $rawWhitelist -Current @())
    return New-RdpGuardConfig $interval $window $threshold $duration $maxLogSize $logRetention $whitelist
}

function Read-IntegerPrompt {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][long]$Current,
        [Parameter(Mandatory)][long]$Minimum,
        [Parameter(Mandatory)][long]$Maximum,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language
    )

    while ($true) {
        $prompt = "$Label [$((Get-RdpGuardText $Language Current)): $Current; $((Get-RdpGuardText $Language Range)): $Minimum-$Maximum; $((Get-RdpGuardText $Language Keep))]"
        $raw = Read-Host $prompt
        try { return Read-BoundedInteger $raw $Current $Minimum $Maximum } catch {
            Write-Host "$((Get-RdpGuardText $Language InvalidValue)): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Get-InteractiveConfig {
    param(
        [Parameter(Mandatory)]$CurrentConfig,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language
    )

    Write-Host ''
    Write-Host (Get-RdpGuardText $Language ConfigTitle) -ForegroundColor Cyan
    $interval = Read-IntegerPrompt (Get-RdpGuardText $Language CheckInterval) $CurrentConfig.check_interval_seconds 10 3600 $Language
    $window = Read-IntegerPrompt (Get-RdpGuardText $Language WindowMinutes) $CurrentConfig.window_minutes 1 1440 $Language
    $threshold = Read-IntegerPrompt (Get-RdpGuardText $Language FailureThreshold) $CurrentConfig.failure_threshold 1 10000 $Language
    $duration = Read-IntegerPrompt (Get-RdpGuardText $Language BlockMinutes) $CurrentConfig.block_minutes 1 525600 $Language
    $maxLogSize = Read-IntegerPrompt (Get-RdpGuardText $Language MaxLogSize) $CurrentConfig.max_log_size_mb 1 1024 $Language
    $logRetention = Read-IntegerPrompt (Get-RdpGuardText $Language LogRetention) $CurrentConfig.log_retention_files 1 100 $Language

    while ($true) {
        $shown = if (@($CurrentConfig.whitelist).Count) { @($CurrentConfig.whitelist) -join ', ' } else { '-' }
        $raw = Read-Host "$((Get-RdpGuardText $Language Whitelist)) [$((Get-RdpGuardText $Language Current)): $shown; $((Get-RdpGuardText $Language Keep))]"
        try {
            $whitelist = @(Read-Whitelist $raw @($CurrentConfig.whitelist))
            break
        } catch {
            Write-Host "$((Get-RdpGuardText $Language InvalidValue)): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    return New-RdpGuardConfig $interval $window $threshold $duration $maxLogSize $logRetention $whitelist
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-ElevatedPowerShellArguments {
    param(
        [Parameter(Mandatory)][string]$EncodedCommand,
        [switch]$UseNonInteractive
    )

    $arguments = @('-NoLogo', '-NoProfile')
    if ($UseNonInteractive) { $arguments += '-NonInteractive' }
    $arguments += @('-ExecutionPolicy', 'Bypass', '-EncodedCommand', $EncodedCommand)
    return $arguments
}

function Invoke-SelfElevation {
    param(
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$ResolvedLanguage,
        [switch]$UseNonInteractive
    )

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Cannot determine the installer script path for elevation.'
    }
    $escapedPath = $PSCommandPath.Replace("'", "''")
    $invokeInstaller = "& '$escapedPath' -Language '$ResolvedLanguage'"
    if ($UseNonInteractive) { $invokeInstaller += ' -NonInteractive' }
    $errorPath = Join-Path ([IO.Path]::GetTempPath()) "RdpGuard-install-$([Guid]::NewGuid().ToString('N')).error.txt"
    $escapedErrorPath = $errorPath.Replace("'", "''")
    $command = @"
try {
    $invokeInstaller
} catch {
    `$detail = (`$_ | Out-String)
    [IO.File]::WriteAllText('$escapedErrorPath', `$detail, [Text.UTF8Encoding]::new(`$false))
    exit 1
}
"@
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $powerShellArguments = @(New-ElevatedPowerShellArguments -EncodedCommand $encodedCommand -UseNonInteractive:$UseNonInteractive)

    try {
        $process = Start-Process -FilePath $windowsPowerShell -Verb RunAs -ArgumentList $powerShellArguments -Wait -PassThru
    } catch {
        if (Test-Path -LiteralPath $errorPath) { Remove-Item -LiteralPath $errorPath -Force }
        throw "$(Get-RdpGuardText $ResolvedLanguage ElevationCancelled): $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) {
        $detail = if (Test-Path -LiteralPath $errorPath) { [IO.File]::ReadAllText($errorPath).Trim() } else { '' }
        if (Test-Path -LiteralPath $errorPath) { Remove-Item -LiteralPath $errorPath -Force }
        if ($detail) {
            throw "Elevated RdpGuard installation failed with exit code $($process.ExitCode): $detail"
        }
        throw "Elevated RdpGuard installation failed with exit code $($process.ExitCode)."
    }
    if (Test-Path -LiteralPath $errorPath) { Remove-Item -LiteralPath $errorPath -Force }
    Write-Output 'RdpGuard installation completed in an elevated PowerShell process.'
    exit 0
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'RdpGuard installation requires an elevated PowerShell window.'
    }
}

function Invoke-ServiceControl {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed ($LASTEXITCODE): $($output -join ' ')"
    }
}

function Restore-PreviousConfig {
    param(
        [Parameter(Mandatory)][string]$TargetConfig,
        [Parameter(Mandatory)][string]$BackupConfig,
        [Parameter(Mandatory)][bool]$HadPreviousConfig
    )

    if (Test-Path -LiteralPath $TargetConfig) { Remove-Item -LiteralPath $TargetConfig -Force }
    if ($HadPreviousConfig -and (Test-Path -LiteralPath $BackupConfig)) {
        Move-Item -LiteralPath $BackupConfig -Destination $TargetConfig
    }
}

if ($LibraryMode) { return }

$ResolvedLanguage = Resolve-RdpGuardLanguage -Language $Language -UiCulture $PSUICulture
if (-not $NonInteractive -and $Language -eq 'auto') {
    while ($true) {
        $choice = Read-Host (Get-RdpGuardText $ResolvedLanguage LanguagePrompt)
        try {
            $ResolvedLanguage = Resolve-InstallerLanguageChoice $choice $ResolvedLanguage
            break
        } catch {
            Write-Host (Get-RdpGuardText $ResolvedLanguage InvalidLanguage) -ForegroundColor Yellow
        }
    }
}

if (-not (Test-Administrator)) {
    Invoke-SelfElevation -ResolvedLanguage $ResolvedLanguage -UseNonInteractive:$NonInteractive
}
Assert-Administrator

$ServiceName = 'RdpGuard'
$InstallDirectory = Join-Path $env:ProgramData 'RdpGuard'
$TargetExecutable = Join-Path $InstallDirectory 'rdpguard.exe'
$TargetMonitor = Join-Path $InstallDirectory 'rdpguard-monitor.exe'
$TargetConfig = Join-Path $InstallDirectory 'config.json'
$TargetState = Join-Path $InstallDirectory 'state.json'
$TargetLog = Join-Path $InstallDirectory 'rdpguard.log'
$SourceExecutable = Join-Path $PSScriptRoot 'rdpguard.exe'
$SourceMonitor = Join-Path $PSScriptRoot 'rdpguard-monitor.exe'
$SourceConfig = Join-Path $PSScriptRoot 'config.json'
$suffix = "$PID.$([Guid]::NewGuid().ToString('N'))"
$PendingConfig = "$TargetConfig.pending.$suffix"
$BackupConfig = "$TargetConfig.backup.$suffix"

foreach ($required in @($SourceExecutable, $SourceMonitor, $SourceConfig)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing release file: $required" }
}

$configSource = if (Test-Path -LiteralPath $TargetConfig) { $TargetConfig } else { $SourceConfig }
$currentConfig = ConvertTo-ValidatedConfig (Get-Content -LiteralPath $configSource -Raw | ConvertFrom-Json)
$selectedConfig = if ($NonInteractive) { $currentConfig } else { Get-InteractiveConfig $currentConfig $ResolvedLanguage }
$selectedConfig = ConvertTo-ValidatedConfig $selectedConfig
$hadPreviousConfig = Test-Path -LiteralPath $TargetConfig
$configReplaced = $false

try {
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        Invoke-ServiceControl -Arguments @('delete', $ServiceName)
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 250
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
    Copy-Item -LiteralPath $SourceExecutable -Destination $TargetExecutable -Force
    Copy-Item -LiteralPath $SourceMonitor -Destination $TargetMonitor -Force

    $aclOutput = & "$env:SystemRoot\System32\icacls.exe" $InstallDirectory '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to secure install directory: $($aclOutput -join ' ')" }
    $monitorAclOutput = & "$env:SystemRoot\System32\icacls.exe" $TargetMonitor '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Failed to secure monitor executable: $($monitorAclOutput -join ' ')" }

    $json = $selectedConfig | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($PendingConfig, $json, [Text.UTF8Encoding]::new($false))
    & $TargetExecutable --dry-run --config $PendingConfig --state $TargetState --log $TargetLog
    if ($LASTEXITCODE -ne 0) { throw "RdpGuard dry-run failed with exit code $LASTEXITCODE" }

    if ($hadPreviousConfig) {
        Move-Item -LiteralPath $TargetConfig -Destination $BackupConfig
    }
    Move-Item -LiteralPath $PendingConfig -Destination $TargetConfig
    $configReplaced = $true

    $binaryPath = '"{0}" --service' -f $TargetExecutable
    Invoke-ServiceControl -Arguments @('create', $ServiceName, 'binPath=', $binaryPath, 'start=', 'delayed-auto', 'obj=', 'LocalSystem', 'DisplayName=', 'RdpGuard - RDP Brute Force Protection')
    Invoke-ServiceControl -Arguments @('description', $ServiceName, 'Temporarily blocks IPs with repeated failed RDP authentication attempts.')
    Invoke-ServiceControl -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000')
    Invoke-ServiceControl -Arguments @('failureflag', $ServiceName, '1')

    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    if (Test-Path -LiteralPath $BackupConfig) { Remove-Item -LiteralPath $BackupConfig -Force }
} catch {
    if ($configReplaced -or (Test-Path -LiteralPath $BackupConfig)) {
        Restore-PreviousConfig -TargetConfig $TargetConfig -BackupConfig $BackupConfig -HadPreviousConfig $hadPreviousConfig
    }
    throw
} finally {
    if (Test-Path -LiteralPath $PendingConfig) { Remove-Item -LiteralPath $PendingConfig -Force }
}

Write-Output "$(Get-RdpGuardText $ResolvedLanguage InstallSuccess): $InstallDirectory"
Write-Output "$(Get-RdpGuardText $ResolvedLanguage MonitorHint): $TargetMonitor"
