[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'RdpGuard'
$InstallDirectory = Join-Path $env:ProgramData 'RdpGuard'
$TargetExecutable = Join-Path $InstallDirectory 'rdpguard.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'RdpGuard removal requires an elevated PowerShell window.'
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $output = & "$env:SystemRoot\System32\sc.exe" delete $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete service: $($output -join ' ')"
    }
}

Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like 'RdpGuard AutoBlock *' } |
    Remove-NetFirewallRule

if ($RemoveData) {
    if (Test-Path -LiteralPath $InstallDirectory) {
        $resolved = (Resolve-Path -LiteralPath $InstallDirectory).Path
        $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'RdpGuard'))
        if ($resolved -ne $expected) { throw "Refusing to remove unexpected path: $resolved" }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
} elseif (Test-Path -LiteralPath $TargetExecutable) {
    Remove-Item -LiteralPath $TargetExecutable -Force
}

Write-Output 'RdpGuard service and automatic firewall rules were removed.'
