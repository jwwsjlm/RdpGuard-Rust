[CmdletBinding()]
param(
    [switch]$LibraryMode,
    [ValidateSet('', 'install', 'monitor', 'doctor')][string]$ElevatedAction = '',
    [ValidateSet('auto', 'zh-CN', 'en-US')][string]$Language = 'auto'
)

$ErrorActionPreference = 'Stop'
$Repository = 'jwwsjlm/RdpGuard-Rust'
$ReleaseTag = 'v0.4.4'

function ConvertFrom-OnlineUtf8Base64 {
    param([Parameter(Mandatory)][string]$Value)
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

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
        Title = @((ConvertFrom-OnlineUtf8Base64 'UmRwR3VhcmQg5Zyo57q/5bel5YW3'), 'RdpGuard Online Tool')
        Install = @((ConvertFrom-OnlineUtf8Base64 'WzFdIOWuieijheaIlumFjee9rumYsuaKpOacjeWKoQ=='), '[1] Install or configure protection service')
        History = @((ConvertFrom-OnlineUtf8Base64 'WzJdIOafpeeci+WOhuWPsueZu+W9leaXpeW/lw=='), '[2] View historical login logs')
        Language = @('[3] English', (ConvertFrom-OnlineUtf8Base64 'WzNdIOS4reaWhw=='))
        Doctor = @((ConvertFrom-OnlineUtf8Base64 'WzRdIOi/kOihjOiviuaWrQ=='), '[4] Run diagnostics')
        Exit = @((ConvertFrom-OnlineUtf8Base64 'WzBdIOmAgOWHug=='), '[0] Exit')
        Choice = @((ConvertFrom-OnlineUtf8Base64 '6K+36YCJ5oup'), 'Select an option')
        InvalidChoice = @((ConvertFrom-OnlineUtf8Base64 '5peg5pWI6YCJ6aG577yM6K+36L6T5YWlIDDjgIEK44CBMuOAgTPmiJYgNOOAgg=='), 'Invalid option. Enter 0, 1, 2, 3 or 4.')
        Downloading = @((ConvertFrom-OnlineUtf8Base64 '5q2j5Zyo5LiL6L295bm25qCh6aqM5pyA5paw5q2j5byP54mILi4u'), 'Downloading and verifying the latest stable release...')
        Ready = @((ConvertFrom-OnlineUtf8Base64 '5Y+R5biD5YyF5qCh6aqM6YCa6L+H44CC'), 'Release package verification passed.')
        OperationFailed = @((ConvertFrom-OnlineUtf8Base64 '5pON5L2c5aSx6LSl'), 'Operation failed')
        InstallFailed = @((ConvertFrom-OnlineUtf8Base64 '5a6J6KOF5Zmo6L+U5Zue5aSx6LSl54q25oCB'), 'Installer returned a failure status')
        MonitorFailed = @((ConvertFrom-OnlineUtf8Base64 '5Y6G5Y+y5pel5b+X55uR5o6n5Zmo6L+U5Zue5aSx6LSl54q25oCB'), 'History monitor returned a failure status')
        DoctorFailed = @((ConvertFrom-OnlineUtf8Base64 '6K+K5pat5Y+R546w6ZyA6KaB5aSE55CG55qE'), 'Diagnostics found items that need attention')
        ElevationFailed = @((ConvertFrom-OnlineUtf8Base64 '566h55CG5ZGY5p2D6ZmQ6K+35rGC5aSx6LSl5oiW5Y+W5raI'), 'Administrator elevation failed or was cancelled')
        InstallComplete = @((ConvertFrom-OnlineUtf8Base64 '6YWN572u5a6M5oiQ77yMUmRwR3VhcmQg6Ziy5oqk5pyN5Yqh5q2j5Zyo6L+Q6KGM44CC'), 'Configuration complete. The RdpGuard protection service is running.')
        MonitorOpening = @((ConvertFrom-OnlineUtf8Base64 '5q2j5Zyo5omT5byA5Y6G5Y+y55m75b2V5pel5b+X56qX5Y+jLi4u'), 'Opening the historical login log window...')
        MonitorClosed = @((ConvertFrom-OnlineUtf8Base64 '5Y6G5Y+y5pel5b+X56qX5Y+j5bey5YWz6Zet44CC'), 'The historical login log window has closed.')
        DoctorComplete = @((ConvertFrom-OnlineUtf8Base64 '6K+K5pat5bey5a6M5oiQ44CC'), 'Diagnostics complete.')
    }
    if (-not $messages.ContainsKey($Key)) { throw "Unknown message key: $Key" }
    if ($Language -eq 'zh-CN') { return $messages[$Key][0] }
    return $messages[$Key][1]
}

function Get-NativeRdpGuardArchitecture {
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($architecture.ToUpperInvariant()) {
        'AMD64' { return 'x64' }
        'ARM64' { return 'arm64' }
        'X86' { return 'x86' }
        default { throw "Unsupported native Windows architecture: $architecture" }
    }
}

function Get-ExpectedArchiveHash {
    param(
        [Parameter(Mandatory)][string]$ChecksumText,
        [Parameter(Mandatory)][string]$ArchiveName
    )
    $escapedName = [regex]::Escape($ArchiveName)
    $found = [regex]::Matches($ChecksumText, "(?im)^([0-9a-f]{64})[ `t]+\*?(?:\./)?$escapedName[ `t]*`r?$")
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
    $protectedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'RdpGuard\Staging')).TrimEnd('\') + '\'
    $candidate = [IO.Path]::GetFullPath($TemporaryDirectory)
    $leaf = Split-Path -Leaf $candidate
    $allowedRoot = $candidate.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or $candidate.StartsWith($protectedRoot, [StringComparison]::OrdinalIgnoreCase)
    if (-not $allowedRoot -or -not $leaf.StartsWith('RdpGuard-', [StringComparison]::Ordinal)) {
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
    param([AllowNull()][string]$BaseDirectory)
    $tempDirectory = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($ReleaseTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'The launcher contains an invalid release tag.' }
        $headers = @{ 'User-Agent' = 'RdpGuard-Online-Installer' }
        $architecture = Get-NativeRdpGuardArchitecture
        $archiveName = "RdpGuard-Rust-$ReleaseTag-windows-$architecture.zip"
        $releaseBase = "https://github.com/$Repository/releases/download/$ReleaseTag"
        $archiveUri = Assert-SafeDownloadUri "$releaseBase/$archiveName"
        $checksumUri = Assert-SafeDownloadUri "$releaseBase/SHA256SUMS.txt"
        $rootDirectory = if ([string]::IsNullOrWhiteSpace($BaseDirectory)) { [IO.Path]::GetTempPath() } else { $BaseDirectory }
        $tempDirectory = Join-Path $rootDirectory "RdpGuard-$([Guid]::NewGuid().ToString('N'))"
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

function Test-OnlineAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-ProtectedOnlineDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "UPGRADE001: Refusing unsafe protected directory: $Path"
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

function Invoke-ProtectedOnlineAction {
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'monitor', 'doctor')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$SelectedLanguage
    )
    if (-not (Test-OnlineAdministrator)) { throw 'Protected online action requires administrator rights.' }
    $installRoot = Join-Path $env:ProgramData 'RdpGuard'
    $stagingRoot = Join-Path $installRoot 'Staging'
    Set-ProtectedOnlineDirectory $installRoot
    Set-ProtectedOnlineDirectory $stagingRoot
    $bundle = $null
    try {
        Write-Host (Get-OnlineText $SelectedLanguage Downloading) -ForegroundColor Cyan
        $bundle = Get-VerifiedReleaseBundle -BaseDirectory $stagingRoot
        Write-Host (Get-OnlineText $SelectedLanguage Ready) -ForegroundColor Green
        switch ($Action) {
            'install' {
                & (Join-Path $bundle.Root 'Install-RdpGuard.ps1') -Language $SelectedLanguage
                if ($LASTEXITCODE -ne 0) { throw "$(Get-OnlineText $SelectedLanguage InstallFailed): $LASTEXITCODE" }
            }
            'monitor' {
                $monitor = Join-Path $bundle.Root 'rdpguard-monitor.exe'
                $monitorProcess = Start-Process -FilePath $monitor -ArgumentList @('--language', $SelectedLanguage) -WorkingDirectory $bundle.Root -Wait -PassThru
                if ($monitorProcess.ExitCode -ne 0) { throw "$(Get-OnlineText $SelectedLanguage MonitorFailed): $($monitorProcess.ExitCode)" }
            }
            'doctor' {
                $diagnostic = Join-Path $env:ProgramData 'RdpGuard\rdpguard.exe'
                if (-not (Test-Path -LiteralPath $diagnostic)) { $diagnostic = Join-Path $bundle.Root 'rdpguard.exe' }
                & $diagnostic doctor --language $SelectedLanguage
                if ($LASTEXITCODE -eq 2) { throw "$(Get-OnlineText $SelectedLanguage DoctorFailed): invalid arguments" }
            }
        }
    } finally {
        if ($null -ne $bundle -and (Test-Path -LiteralPath $bundle.TempDirectory)) {
            Remove-TemporaryBundle $bundle.TempDirectory
        }
    }
}

function Invoke-ElevatedOnlineAction {
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'monitor', 'doctor')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$SelectedLanguage
    )
    if ($Action -eq 'monitor') {
        Write-Host (Get-OnlineText $SelectedLanguage MonitorOpening) -ForegroundColor Cyan
    }
    if (Test-OnlineAdministrator) {
        Invoke-ProtectedOnlineAction $Action $SelectedLanguage
        Write-OnlineActionComplete $Action $SelectedLanguage
        return
    }
    $launcherUri = "https://raw.githubusercontent.com/$Repository/$ReleaseTag/Install-RdpGuard-Online.ps1"
    $command = @"
`$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
`$source = Invoke-RestMethod -UseBasicParsing -Uri '$launcherUri' -Headers @{ 'User-Agent' = 'RdpGuard-Online-Installer' }
& ([ScriptBlock]::Create([string]`$source)) -ElevatedAction '$Action' -Language '$SelectedLanguage'
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $process = Start-Process -FilePath $powerShell -Verb RunAs -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Wait -PassThru
    } catch {
        throw "$(Get-OnlineText $SelectedLanguage ElevationFailed): $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) { throw "$(Get-OnlineText $SelectedLanguage OperationFailed): exit code $($process.ExitCode)" }
    Write-OnlineActionComplete $Action $SelectedLanguage
}

function Write-OnlineActionComplete {
    param(
        [Parameter(Mandatory)][ValidateSet('install', 'monitor', 'doctor')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$SelectedLanguage
    )
    $key = switch ($Action) {
        'install' { 'InstallComplete' }
        'monitor' { 'MonitorClosed' }
        'doctor' { 'DoctorComplete' }
    }
    Write-Host (Get-OnlineText $SelectedLanguage $key) -ForegroundColor Green
}

function Invoke-RdpGuardMenuChoice {
    param(
        [Parameter(Mandatory)][string]$Choice,
        [Parameter(Mandatory)][ValidateSet('zh-CN', 'en-US')][string]$Language,
        [Parameter(Mandatory)][scriptblock]$ActionInvoker
    )
    $result = [ordered]@{ Exit = $false; Valid = $true; Language = $Language }
    switch ($Choice.Trim()) {
        '0' { $result.Exit = $true }
        '1' { & $ActionInvoker 'install' $Language }
        '2' { & $ActionInvoker 'monitor' $Language }
        '3' { $result.Language = if ($Language -eq 'zh-CN') { 'en-US' } else { 'zh-CN' } }
        '4' { & $ActionInvoker 'doctor' $Language }
        default { $result.Valid = $false }
    }
    return [pscustomobject]$result
}

function Invoke-OnlineLauncher {
    $language = Resolve-RdpGuardLanguage -Language $Language -UiCulture $PSUICulture
    $actionInvoker = { param($Action, $SelectedLanguage) Invoke-ElevatedOnlineAction $Action $SelectedLanguage }
    while ($true) {
        Write-Host ''
        Write-Host (Get-OnlineText $language Title) -ForegroundColor Cyan
        Write-Host (Get-OnlineText $language Install)
        Write-Host (Get-OnlineText $language History)
        Write-Host (Get-OnlineText $language Language)
        Write-Host (Get-OnlineText $language Doctor)
        Write-Host (Get-OnlineText $language Exit)
        $choice = Read-Host (Get-OnlineText $language Choice)
        try {
            $result = Invoke-RdpGuardMenuChoice $choice $language $actionInvoker
            $language = $result.Language
            if (-not $result.Valid) { Write-Host (Get-OnlineText $language InvalidChoice) -ForegroundColor Yellow }
            if ($result.Exit) { break }
        } catch {
            Write-Host "$(Get-OnlineText $language OperationFailed): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

if ($LibraryMode) { return }
$resolved = Resolve-RdpGuardLanguage -Language $Language -UiCulture $PSUICulture
if ($ElevatedAction) {
    Invoke-ProtectedOnlineAction $ElevatedAction $resolved
    return
}
Invoke-OnlineLauncher
