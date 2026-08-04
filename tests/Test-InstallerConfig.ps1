$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param($Actual, $Expected, [string]$Message = 'values differ')
    if ($Actual -ne $Expected) {
        throw "$Message`: expected '$Expected', got '$Actual'"
    }
}

function Assert-Throws {
    param([scriptblock]$Action)
    try {
        & $Action
    } catch {
        return
    }
    throw 'expected action to throw'
}

function Assert-True {
    param([bool]$Value, [string]$Message)
    if (-not $Value) { throw $Message }
}

. "$PSScriptRoot\..\Install-RdpGuard.ps1" -LibraryMode

Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'zh-CN') 'zh-CN'
Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'en-US') 'en-US'
Assert-Equal (Resolve-InstallerLanguageChoice -Raw 'l' -Current 'zh-CN') 'en-US'
Assert-Equal (Resolve-InstallerLanguageChoice -Raw '' -Current 'zh-CN') 'zh-CN'

Assert-Equal (Read-BoundedInteger -Raw '' -Current 60 -Minimum 10 -Maximum 3600) 60
Assert-Equal (Read-BoundedInteger -Raw '120' -Current 60 -Minimum 10 -Maximum 3600) 120
Assert-Throws { Read-BoundedInteger -Raw '9' -Current 60 -Minimum 10 -Maximum 3600 }
Assert-Throws { Read-BoundedInteger -Raw 'abc' -Current 60 -Minimum 10 -Maximum 3600 }

Assert-Equal ((Read-Whitelist -Raw '' -Current @('203.0.113.1')) -join ',') '203.0.113.1'
Assert-Equal ((Read-Whitelist -Raw 'clear' -Current @('203.0.113.1')).Count) 0
Assert-Equal ((Read-Whitelist -Raw '203.0.113.1, 2001:db8::1, 203.0.113.1' -Current @()) -join ',') '203.0.113.1,2001:db8::1'
Assert-Equal ((Read-Whitelist -Raw '198.51.100.0/24,2001:db8::/32' -Current @()) -join ',') '198.51.100.0/24,2001:db8::/32'
Assert-Throws { Read-Whitelist -Raw 'not-an-ip' -Current @() }
Assert-Throws { Read-Whitelist -Raw '198.51.100.0/99' -Current @() }

$config = New-RdpGuardConfig -CheckIntervalSeconds 60 -WindowMinutes 10 -FailureThreshold 5 -BlockMinutes 360 -MaxLogSizeMb 10 -LogRetentionFiles 5 -Whitelist @('203.0.113.1')
$json = $config | ConvertTo-Json -Depth 3 | ConvertFrom-Json
Assert-Equal $json.check_interval_seconds 60
Assert-Equal $json.window_minutes 10
Assert-Equal $json.failure_threshold 5
Assert-Equal $json.block_minutes 360
Assert-Equal $json.max_log_size_mb 10
Assert-Equal $json.log_retention_files 5
Assert-Equal $json.whitelist[0] '203.0.113.1'
Assert-Equal $json.schema_version 2
Assert-Equal $json.block_scope 'all_inbound'
Assert-Equal $json.repeat_block_multiplier 2
Assert-Equal $json.max_block_minutes 10080
Assert-Equal $json.repeat_reset_days 30
Assert-Equal $json.max_active_blocks 5000
Assert-Equal $json.heartbeat_minutes 60

$legacyConfig = [pscustomobject]@{
    check_interval_seconds = 60
    window_minutes = 10
    failure_threshold = 5
    block_minutes = 360
    whitelist = @()
}
$upgradedConfig = ConvertTo-ValidatedConfig $legacyConfig
Assert-Equal $upgradedConfig.max_log_size_mb 10
Assert-Equal $upgradedConfig.log_retention_files 5
Assert-Equal $upgradedConfig.schema_version 2
Assert-Equal $upgradedConfig.block_scope 'all_inbound'

Assert-Equal (Get-ServiceStartModeArgument -StartMode Auto -DelayedAutoStart $true) 'delayed-auto'
Assert-Equal (Get-ServiceStartModeArgument -StartMode Auto -DelayedAutoStart $false) 'auto'
Assert-Equal (Get-ServiceStartModeArgument -StartMode Manual -DelayedAutoStart $false) 'demand'
Assert-Equal (Get-ServiceStartModeArgument -StartMode Disabled -DelayedAutoStart $false) 'disabled'
Assert-Throws { Get-ServiceStartModeArgument -StartMode Unknown -DelayedAutoStart $false }

Write-Output 'Installer configuration tests passed.'
