[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
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

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'RdpGuard installation requires an elevated PowerShell window.'
    }
}

function Invoke-SelfElevation {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Cannot determine the installer script path for elevation.'
    }

    $escapedPath = $PSCommandPath.Replace("'", "''")
    $command = "& '$escapedPath'"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

    try {
        $process = Start-Process -FilePath $windowsPowerShell -Verb RunAs -ArgumentList @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', $encodedCommand
        ) -Wait -PassThru
    } catch {
        throw "RdpGuard elevation was cancelled or failed: $($_.Exception.Message)"
    }

    if ($process.ExitCode -ne 0) {
        throw "Elevated RdpGuard installation failed with exit code $($process.ExitCode)."
    }

    Write-Output 'RdpGuard installation completed in an elevated PowerShell process.'
    exit 0
}

function Invoke-ServiceControl {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed ($LASTEXITCODE): $($output -join ' ')"
    }
}

if (-not (Test-Administrator)) {
    Invoke-SelfElevation
}
Assert-Administrator
if (-not (Test-Path -LiteralPath $SourceExecutable)) {
    throw "Missing release executable: $SourceExecutable"
}
if (-not (Test-Path -LiteralPath $SourceMonitor)) {
    throw "Missing release monitor: $SourceMonitor"
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
Copy-Item -LiteralPath $SourceMonitor -Destination $TargetMonitor -Force
if (-not (Test-Path -LiteralPath $TargetConfig)) {
    Copy-Item -LiteralPath $SourceConfig -Destination $TargetConfig
}

$aclOutput = & "$env:SystemRoot\System32\icacls.exe" $InstallDirectory '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to secure install directory: $($aclOutput -join ' ')"
}

# The data directory remains administrator-only. Grant standard users access to
# the monitor executable itself so it can launch and request UAC before reading
# protected logs or state.
$monitorAclOutput = & "$env:SystemRoot\System32\icacls.exe" $TargetMonitor '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to secure monitor executable: $($monitorAclOutput -join ' ')"
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
Write-Output "Open the monitor with: $TargetMonitor"
