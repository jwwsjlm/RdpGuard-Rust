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
        AdvancedPrompt = @('是否配置高级选项？输入 y 继续，直接按 Enter 使用当前值', 'Configure advanced options? Enter y to continue, or press Enter to keep current values')
        BlockScope = @('拦截范围（1=全部入站，2=仅 RDP）', 'Block scope (1=all inbound, 2=RDP only)')
        RdpPort = @('RDP 端口（0=自动检测）', 'RDP port (0=auto-detect)')
        RepeatMultiplier = @('复犯封禁倍数', 'Repeat-block multiplier')
        MaxBlockMinutes = @('最长封禁时长（分钟）', 'Maximum block duration (minutes)')
        RepeatResetDays = @('无复犯后重置天数', 'Quiet days before repeat history resets')
        MaxActiveBlocks = @('最大活动封禁数', 'Maximum active blocks')
        HeartbeatMinutes = @('健康心跳间隔（分钟）', 'Health heartbeat interval (minutes)')
        CurrentPublicSessions = @('WTS 检测到已认证活动 RDP 会话报告的公网地址（请人工确认）', 'WTS found public addresses reported by authenticated active RDP sessions (verify manually)')
        TrustCurrentSessions = @('仅在确认地址属于你时输入 y 加入白名单；直接按 Enter 不添加', 'Enter y only if you recognize these addresses; press Enter to leave unchanged')
        SessionLookupWarning = @('CONN002：无法读取已认证活动 RDP 会话；已跳过白名单建议', 'CONN002: authenticated active RDP sessions could not be read; whitelist suggestion skipped')
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
        $parts = @($value.Split('/'))
        if ($parts.Count -gt 2) { throw "Invalid IP or CIDR: $value" }
        $parsed = $null
        if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$parsed)) { throw "Invalid IP or CIDR: $value" }
        $canonical = $parsed.IPAddressToString
        if ($parts.Count -eq 2) {
            $prefix = 0
            $maximum = if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt $maximum) {
                throw "Invalid CIDR prefix: $value"
            }
            $canonical = "$canonical/$prefix"
        }
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
        [AllowEmptyCollection()][string[]]$Whitelist,
        [ValidateSet('all_inbound', 'rdp_only')][string]$BlockScope = 'all_inbound',
        [AllowNull()][Nullable[int]]$RdpPort = $null,
        [long]$RepeatBlockMultiplier = 2,
        [long]$MaxBlockMinutes = 10080,
        [long]$RepeatResetDays = 30,
        [long]$MaxActiveBlocks = 5000,
        [long]$HeartbeatMinutes = 60
    )

    return [ordered]@{
        schema_version = 2
        check_interval_seconds = $CheckIntervalSeconds
        window_minutes = $WindowMinutes
        failure_threshold = $FailureThreshold
        block_minutes = $BlockMinutes
        max_log_size_mb = $MaxLogSizeMb
        log_retention_files = $LogRetentionFiles
        whitelist = @($Whitelist)
        block_scope = $BlockScope
        rdp_port = $RdpPort
        repeat_block_multiplier = $RepeatBlockMultiplier
        max_block_minutes = $MaxBlockMinutes
        repeat_reset_days = $RepeatResetDays
        max_active_blocks = $MaxActiveBlocks
        heartbeat_minutes = $HeartbeatMinutes
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
    $scope = [string]$InputObject.block_scope
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = 'all_inbound' }
    if ($scope -notin @('all_inbound', 'rdp_only')) { throw 'block_scope must be all_inbound or rdp_only.' }
    $port = $null
    if ($null -ne $InputObject.rdp_port -and -not [string]::IsNullOrWhiteSpace([string]$InputObject.rdp_port)) {
        $port = [int](Read-BoundedInteger ([string]$InputObject.rdp_port) 3389 1 65535)
    }
    $repeatMultiplier = Read-BoundedInteger ([string]$InputObject.repeat_block_multiplier) 2 1 16
    $defaultMaxBlock = [Math]::Max(10080, $duration)
    $maxBlock = Read-BoundedInteger ([string]$InputObject.max_block_minutes) $defaultMaxBlock $duration 525600
    $resetDays = Read-BoundedInteger ([string]$InputObject.repeat_reset_days) 30 1 3650
    $maxActive = Read-BoundedInteger ([string]$InputObject.max_active_blocks) 5000 1 100000
    $heartbeat = Read-BoundedInteger ([string]$InputObject.heartbeat_minutes) 60 1 1440
    return New-RdpGuardConfig $interval $window $threshold $duration $maxLogSize $logRetention $whitelist $scope $port $repeatMultiplier $maxBlock $resetDays $maxActive $heartbeat
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
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language,
        [Parameter(Mandatory)][string]$SessionSourceExecutable
    )

    Write-Host ''
    Write-Host (Get-RdpGuardText $Language ConfigTitle) -ForegroundColor Cyan
    $interval = Read-IntegerPrompt (Get-RdpGuardText $Language CheckInterval) $CurrentConfig.check_interval_seconds 10 3600 $Language
    $window = Read-IntegerPrompt (Get-RdpGuardText $Language WindowMinutes) $CurrentConfig.window_minutes 1 1440 $Language
    $threshold = Read-IntegerPrompt (Get-RdpGuardText $Language FailureThreshold) $CurrentConfig.failure_threshold 1 10000 $Language
    $duration = Read-IntegerPrompt (Get-RdpGuardText $Language BlockMinutes) $CurrentConfig.block_minutes 1 525600 $Language

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
    try {
        $currentPublic = @(Get-CurrentRdpPublicAddresses -Executable $SessionSourceExecutable)
    } catch {
        Write-Host "$((Get-RdpGuardText $Language SessionLookupWarning)): $($_.Exception.Message)" -ForegroundColor Yellow
        $currentPublic = @()
    }
    if ($currentPublic.Count -gt 0) {
        Write-Host "$((Get-RdpGuardText $Language CurrentPublicSessions)): $($currentPublic -join ', ')" -ForegroundColor Yellow
        $trust = Read-Host (Get-RdpGuardText $Language TrustCurrentSessions)
        if ($trust -in @('y', 'Y', 'yes', 'YES', '是')) {
            $whitelist = @(Read-Whitelist -Raw ((@($whitelist) + $currentPublic) -join ',') -Current @())
        }
    }
    $maxLogSize = $CurrentConfig.max_log_size_mb
    $logRetention = $CurrentConfig.log_retention_files
    $scope = $CurrentConfig.block_scope
    $port = $CurrentConfig.rdp_port
    $repeatMultiplier = $CurrentConfig.repeat_block_multiplier
    $maxBlock = $CurrentConfig.max_block_minutes
    $resetDays = $CurrentConfig.repeat_reset_days
    $maxActive = $CurrentConfig.max_active_blocks
    $heartbeat = $CurrentConfig.heartbeat_minutes
    $advanced = Read-Host (Get-RdpGuardText $Language AdvancedPrompt)
    if ($advanced -in @('y', 'Y', 'yes', 'YES', '是')) {
        while ($true) {
            $scopeRaw = Read-Host "$((Get-RdpGuardText $Language BlockScope)) [$((Get-RdpGuardText $Language Current)): $scope]"
            if ([string]::IsNullOrWhiteSpace($scopeRaw)) { break }
            if ($scopeRaw -eq '1') { $scope = 'all_inbound'; break }
            if ($scopeRaw -eq '2') { $scope = 'rdp_only'; break }
            Write-Host (Get-RdpGuardText $Language InvalidValue) -ForegroundColor Yellow
        }
        $currentPort = if ($null -eq $port) { 0 } else { [int]$port }
        $selectedPort = Read-IntegerPrompt (Get-RdpGuardText $Language RdpPort) $currentPort 0 65535 $Language
        $port = if ($selectedPort -eq 0) { $null } else { [int]$selectedPort }
        $repeatMultiplier = Read-IntegerPrompt (Get-RdpGuardText $Language RepeatMultiplier) $repeatMultiplier 1 16 $Language
        $maxBlock = Read-IntegerPrompt (Get-RdpGuardText $Language MaxBlockMinutes) $maxBlock $duration 525600 $Language
        $resetDays = Read-IntegerPrompt (Get-RdpGuardText $Language RepeatResetDays) $resetDays 1 3650 $Language
        $maxActive = Read-IntegerPrompt (Get-RdpGuardText $Language MaxActiveBlocks) $maxActive 1 100000 $Language
        $heartbeat = Read-IntegerPrompt (Get-RdpGuardText $Language HeartbeatMinutes) $heartbeat 1 1440 $Language
        $maxLogSize = Read-IntegerPrompt (Get-RdpGuardText $Language MaxLogSize) $maxLogSize 1 1024 $Language
        $logRetention = Read-IntegerPrompt (Get-RdpGuardText $Language LogRetention) $logRetention 1 100 $Language
    }
    return New-RdpGuardConfig $interval $window $threshold $duration $maxLogSize $logRetention $whitelist $scope $port $repeatMultiplier $maxBlock $resetDays $maxActive $heartbeat
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PublicRdpAddress {
    param([Parameter(Mandatory)][Net.IPAddress]$Address)
    if ([Net.IPAddress]::IsLoopback($Address) -or $Address.IsIPv6LinkLocal -or $Address.IsIPv6Multicast -or $Address.IsIPv6SiteLocal) { return $false }
    $bytes = $Address.GetAddressBytes()
    if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224) { return $false }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $false }
        return $true
    }
    if (($bytes[0] -band 0xFE) -eq 0xFC) { return $false }
    return $true
}

function Get-CurrentRdpPublicAddresses {
    param([Parameter(Mandatory)][string]$Executable)
    $output = @(& $Executable session-sources --json 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "session-sources exited with code $LASTEXITCODE`: $($output -join ' ')"
    }
    try {
        $addresses = @(($output -join [Environment]::NewLine) | ConvertFrom-Json)
    } catch {
        throw "session-sources returned invalid JSON: $($_.Exception.Message)"
    }
    $results = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($address in $addresses) {
        $parsed = $null
        if ([Net.IPAddress]::TryParse([string]$address, [ref]$parsed) -and (Test-PublicRdpAddress $parsed)) {
            [void]$results.Add($parsed.IPAddressToString)
        }
    }
    return @($results)
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

function Get-ServiceStartModeArgument {
    param(
        [Parameter(Mandatory)][string]$StartMode,
        [bool]$DelayedAutoStart
    )
    switch ($StartMode) {
        'Auto' { if ($DelayedAutoStart) { return 'delayed-auto' }; return 'auto' }
        'Manual' { return 'demand' }
        'Disabled' { return 'disabled' }
        default { throw "UPGRADE001: Unsupported existing service start mode: $StartMode" }
    }
}

function Add-RdpGuardErrorCode {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Message -match '^[A-Z][A-Z0-9_]*[0-9]{3}:') { return $Message }
    return "${Code}: $Message"
}

function Invoke-ExecutablePreflight {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedVersion,
        [Parameter(Mandatory)][string]$Component
    )

    $output = @()
    $exitCode = $null
    $startError = $null
    $previousExitCode = $global:LASTEXITCODE
    try {
        $global:LASTEXITCODE = $null
        try {
            $output = @(& $Path --version 2>&1)
            $exitCode = $global:LASTEXITCODE
        } catch {
            $startError = $_.Exception.Message
            $exitCode = $global:LASTEXITCODE
        }
    } finally {
        $global:LASTEXITCODE = $previousExitCode
    }

    $outputText = (($output | ForEach-Object { [string]$_ }) -join ' ').Trim()
    $exitCodeText = if ($null -eq $exitCode) { '<not-set>' } else { [string]$exitCode }
    $startErrorText = if ([string]::IsNullOrWhiteSpace($startError)) { '<none>' } else { $startError.Replace("`r", ' ').Replace("`n", ' ') }
    $shownOutput = if ([string]::IsNullOrWhiteSpace($outputText)) { '<empty>' } else { $outputText }
    if ($null -ne $startError -or $exitCode -ne 0 -or $outputText -ne $ExpectedVersion) {
        $message = "New $Component executable preflight failed: path=$Path; exit_code=$exitCodeText; start_error=$startErrorText; output=$shownOutput; expected=$ExpectedVersion"
        throw (Add-RdpGuardErrorCode -Code 'UPGRADE001' -Message $message)
    }
}

function Restore-ServiceConfiguration {
    param(
        [Parameter(Mandatory)]$OriginalService,
        [Parameter(Mandatory)][bool]$DelayedAutoStart
    )
    $startMode = Get-ServiceStartModeArgument $OriginalService.StartMode $DelayedAutoStart
    Invoke-ServiceControl -Arguments @(
        'config', $OriginalService.Name,
        'binPath=', $OriginalService.PathName,
        'start=', $startMode,
        'obj=', 'LocalSystem',
        'DisplayName=', $OriginalService.DisplayName
    )
}

function Set-ProtectedInstallDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "UPGRADE001: Refusing unsafe install directory: $Path"
        }
    } else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }

    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($administrators)
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($system, $fullControl, $inheritance, $propagation, $allow))
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($administrators, $fullControl, $inheritance, $propagation, $allow))
    Set-Acl -LiteralPath $Path -AclObject $security
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
    throw 'UPGRADE001: RdpGuard installation requires an elevated PowerShell window. Open PowerShell with Run as administrator and run this script again.'
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
$PendingExecutable = Join-Path $InstallDirectory "rdpguard.pending.$suffix.exe"
$PendingMonitor = Join-Path $InstallDirectory "rdpguard-monitor.pending.$suffix.exe"
$PreflightState = "$TargetState.preflight.$suffix"
$BackupExecutable = "$TargetExecutable.backup.$suffix"
$BackupMonitor = "$TargetMonitor.backup.$suffix"

foreach ($required in @($SourceExecutable, $SourceMonitor, $SourceConfig)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "UPGRADE001: Missing release file: $required" }
}

$configSource = if (Test-Path -LiteralPath $TargetConfig) { $TargetConfig } else { $SourceConfig }
try {
    $currentConfig = ConvertTo-ValidatedConfig (Get-Content -LiteralPath $configSource -Raw | ConvertFrom-Json)
} catch {
    throw "CFG001: Failed to load configuration $configSource. Repair the JSON or move it aside and rerun installation. $($_.Exception.Message)"
}
$selectedConfig = if ($NonInteractive) { $currentConfig } else { Get-InteractiveConfig $currentConfig $ResolvedLanguage $SourceExecutable }
$selectedConfig = ConvertTo-ValidatedConfig $selectedConfig
$hadPreviousConfig = Test-Path -LiteralPath $TargetConfig
$hadPreviousExecutable = Test-Path -LiteralPath $TargetExecutable
$hadPreviousMonitor = Test-Path -LiteralPath $TargetMonitor
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$hadService = $null -ne $existing
$serviceWasRunning = $hadService -and $existing.Status -ne 'Stopped'
$originalService = $null
$originalDelayedAutoStart = $false
if ($hadService) {
    $originalService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $originalService) { throw 'UPGRADE001: Failed to inspect the existing RdpGuard service.' }
    if ($originalService.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw "UPGRADE001: Existing RdpGuard service uses unexpected account $($originalService.StartName). Restore LocalSystem before upgrading."
    }
    $originalDelayedAutoStart = [bool](Get-ItemPropertyValue -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name DelayedAutoStart -ErrorAction SilentlyContinue)
}
$serviceCreated = $false
$replacementStarted = $false
$preserveBackups = $false

try {
    Set-ProtectedInstallDirectory $InstallDirectory

    Copy-Item -LiteralPath $SourceExecutable -Destination $PendingExecutable -Force
    Copy-Item -LiteralPath $SourceMonitor -Destination $PendingMonitor -Force
    Invoke-ExecutablePreflight -Path $PendingExecutable -ExpectedVersion 'rdpguard 0.4.2' -Component 'service'
    Invoke-ExecutablePreflight -Path $PendingMonitor -ExpectedVersion 'rdpguard-monitor 0.4.2' -Component 'monitor'

    $json = $selectedConfig | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($PendingConfig, $json, [Text.UTF8Encoding]::new($false))
    & $PendingExecutable --dry-run --config $PendingConfig --state $PreflightState --log $TargetLog
    if ($LASTEXITCODE -ne 0) { throw "UPGRADE001: RdpGuard dry-run failed with exit code $LASTEXITCODE" }

    if ($hadPreviousExecutable) { Copy-Item -LiteralPath $TargetExecutable -Destination $BackupExecutable -Force }
    if ($hadPreviousMonitor) { Copy-Item -LiteralPath $TargetMonitor -Destination $BackupMonitor -Force }
    if ($hadPreviousConfig) { Copy-Item -LiteralPath $TargetConfig -Destination $BackupConfig -Force }

    if ($serviceWasRunning) {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    $replacementStarted = $true
    Move-Item -LiteralPath $PendingExecutable -Destination $TargetExecutable -Force
    Move-Item -LiteralPath $PendingMonitor -Destination $TargetMonitor -Force
    Move-Item -LiteralPath $PendingConfig -Destination $TargetConfig -Force

    $monitorAclOutput = & "$env:SystemRoot\System32\icacls.exe" $TargetMonitor '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "UPGRADE001: Failed to secure monitor executable: $($monitorAclOutput -join ' ')" }

    $binaryPath = '"{0}" --service' -f $TargetExecutable
    if ($hadService) {
        Invoke-ServiceControl -Arguments @('config', $ServiceName, 'binPath=', $binaryPath, 'start=', 'delayed-auto', 'obj=', 'LocalSystem', 'DisplayName=', 'RdpGuard - RDP Brute Force Protection')
    } else {
        Invoke-ServiceControl -Arguments @('create', $ServiceName, 'binPath=', $binaryPath, 'start=', 'delayed-auto', 'obj=', 'LocalSystem', 'DisplayName=', 'RdpGuard - RDP Brute Force Protection')
        $serviceCreated = $true
    }
    Invoke-ServiceControl -Arguments @('description', $ServiceName, 'Temporarily blocks IPs with repeated failed RDP authentication attempts.')
    Invoke-ServiceControl -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000')
    Invoke-ServiceControl -Arguments @('failureflag', $ServiceName, '1')

    Start-Service -Name $ServiceName
    $service = Get-Service -Name $ServiceName
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    if ($service.Status -ne 'Running') { throw 'UPGRADE001: Service did not report a healthy Running state.' }
    foreach ($backup in @($BackupExecutable, $BackupMonitor, $BackupConfig)) {
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    }
} catch {
    $failure = $_
    try {
        $currentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($currentService -and $currentService.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            $currentService.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        if ($replacementStarted) {
            foreach ($target in @($TargetExecutable, $TargetMonitor, $TargetConfig)) {
                if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
            }
            if ($hadPreviousExecutable -and (Test-Path -LiteralPath $BackupExecutable)) { Move-Item -LiteralPath $BackupExecutable -Destination $TargetExecutable -Force }
            if ($hadPreviousMonitor -and (Test-Path -LiteralPath $BackupMonitor)) { Move-Item -LiteralPath $BackupMonitor -Destination $TargetMonitor -Force }
            if ($hadPreviousConfig -and (Test-Path -LiteralPath $BackupConfig)) { Move-Item -LiteralPath $BackupConfig -Destination $TargetConfig -Force }
        }
        if ($serviceCreated) { Invoke-ServiceControl -Arguments @('delete', $ServiceName) }
        elseif ($serviceWasRunning) {
            Restore-ServiceConfiguration $originalService $originalDelayedAutoStart
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        } elseif ($hadService) {
            Restore-ServiceConfiguration $originalService $originalDelayedAutoStart
        }
    } catch {
        $preserveBackups = $true
        $rollbackFailure = "$($failure.Exception.Message) Rollback also failed: $($_.Exception.Message)"
        throw (Add-RdpGuardErrorCode -Code 'UPGRADE001' -Message $rollbackFailure)
    }
    $restoredFailure = "$($failure.Exception.Message) Previous installation was restored."
    throw (Add-RdpGuardErrorCode -Code 'UPGRADE001' -Message $restoredFailure)
} finally {
    foreach ($pending in @($PendingExecutable, $PendingMonitor, $PendingConfig, $PreflightState)) {
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
    }
    if (-not $preserveBackups) {
        foreach ($backup in @($BackupExecutable, $BackupMonitor, $BackupConfig)) {
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        }
    }
}

Write-Output "$(Get-RdpGuardText $ResolvedLanguage InstallSuccess): $InstallDirectory"
Write-Output "$(Get-RdpGuardText $ResolvedLanguage MonitorHint): $TargetMonitor"
