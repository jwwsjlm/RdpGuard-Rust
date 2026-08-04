[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ServiceName = 'RdpGuard'
$InstallDirectory = Join-Path $env:ProgramData 'RdpGuard'
$TargetExecutable = Join-Path $InstallDirectory 'rdpguard.exe'
$TargetConfig = Join-Path $InstallDirectory 'config.json'
$TargetState = Join-Path $InstallDirectory 'state.json'
$TargetLog = Join-Path $InstallDirectory 'rdpguard.log'
$SourceExecutable = Join-Path $PSScriptRoot 'rdpguard.exe'
$SourceConfig = Join-Path $PSScriptRoot 'config.json'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
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

Assert-Administrator
if (-not (Test-Path -LiteralPath $SourceExecutable)) {
    throw "Missing release executable: $SourceExecutable"
}
if (-not (Test-Path -LiteralPath $SourceConfig)) {
    throw "Missing default configuration: $SourceConfig"
}

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
if (-not (Test-Path -LiteralPath $TargetConfig)) {
    Copy-Item -LiteralPath $SourceConfig -Destination $TargetConfig
}

$aclOutput = & "$env:SystemRoot\System32\icacls.exe" $InstallDirectory '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to secure install directory: $($aclOutput -join ' ')"
}

& $TargetExecutable --dry-run --config $TargetConfig --state $TargetState --log $TargetLog
if ($LASTEXITCODE -ne 0) {
    throw "RdpGuard dry-run failed with exit code $LASTEXITCODE"
}

$binaryPath = '"{0}" --service' -f $TargetExecutable
Invoke-ServiceControl -Arguments @(
    'create', $ServiceName,
    'binPath=', $binaryPath,
    'start=', 'delayed-auto',
    'obj=', 'LocalSystem',
    'DisplayName=', 'RdpGuard - RDP Brute Force Protection'
)
Invoke-ServiceControl -Arguments @('description', $ServiceName, 'Temporarily blocks IPs with repeated failed RDP authentication attempts.')
Invoke-ServiceControl -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/60000')
Invoke-ServiceControl -Arguments @('failureflag', $ServiceName, '1')

Start-Service -Name $ServiceName
$service = Get-Service -Name $ServiceName
$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Output "RdpGuard installed and running from $InstallDirectory"
