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
Assert-Throws { Read-Whitelist -Raw 'not-an-ip' -Current @() }

$config = New-RdpGuardConfig -CheckIntervalSeconds 60 -WindowMinutes 10 -FailureThreshold 5 -BlockMinutes 360 -Whitelist @('203.0.113.1')
$json = $config | ConvertTo-Json -Depth 3 | ConvertFrom-Json
Assert-Equal $json.check_interval_seconds 60
Assert-Equal $json.window_minutes 10
Assert-Equal $json.failure_threshold 5
Assert-Equal $json.block_minutes 360
Assert-Equal $json.whitelist[0] '203.0.113.1'

Write-Output 'Installer configuration tests passed.'
