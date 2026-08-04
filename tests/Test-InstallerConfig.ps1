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

$interactiveElevation = @(New-ElevatedPowerShellArguments -EncodedCommand 'test-command')
$nonInteractiveElevation = @(New-ElevatedPowerShellArguments -EncodedCommand 'test-command' -UseNonInteractive)
Assert-True (-not ($interactiveElevation -contains '-NonInteractive')) 'interactive UAC process must allow Read-Host'
Assert-True ($nonInteractiveElevation -contains '-NonInteractive') 'unattended UAC process must remain non-interactive'

Assert-Equal (Read-BoundedInteger -Raw '' -Current 60 -Minimum 10 -Maximum 3600) 60
Assert-Equal (Read-BoundedInteger -Raw '120' -Current 60 -Minimum 10 -Maximum 3600) 120
Assert-Throws { Read-BoundedInteger -Raw '9' -Current 60 -Minimum 10 -Maximum 3600 }
Assert-Throws { Read-BoundedInteger -Raw 'abc' -Current 60 -Minimum 10 -Maximum 3600 }

Assert-Equal ((Read-Whitelist -Raw '' -Current @('203.0.113.1')) -join ',') '203.0.113.1'
Assert-Equal ((Read-Whitelist -Raw 'clear' -Current @('203.0.113.1')).Count) 0
Assert-Equal ((Read-Whitelist -Raw '203.0.113.1, 2001:db8::1, 203.0.113.1' -Current @()) -join ',') '203.0.113.1,2001:db8::1'
Assert-Throws { Read-Whitelist -Raw 'not-an-ip' -Current @() }

$config = New-RdpGuardConfig -CheckIntervalSeconds 60 -WindowMinutes 10 -FailureThreshold 5 -BlockMinutes 360 -MaxLogSizeMb 10 -LogRetentionFiles 5 -Whitelist @('203.0.113.1')
$json = $config | ConvertTo-Json -Depth 3 | ConvertFrom-Json
Assert-Equal $json.check_interval_seconds 60
Assert-Equal $json.window_minutes 10
Assert-Equal $json.failure_threshold 5
Assert-Equal $json.block_minutes 360
Assert-Equal $json.max_log_size_mb 10
Assert-Equal $json.log_retention_files 5
Assert-Equal $json.whitelist[0] '203.0.113.1'

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

Write-Output 'Installer configuration tests passed.'
