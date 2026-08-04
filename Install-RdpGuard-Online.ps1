[CmdletBinding()]
param([switch]$LibraryMode)

$ErrorActionPreference = 'Stop'
$Repository = 'jwwsjlm/RdpGuard-Rust'
$ReleaseTag = 'v0.3.6'

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
        Exit = @((ConvertFrom-OnlineUtf8Base64 'WzBdIOmAgOWHug=='), '[0] Exit')
        Choice = @((ConvertFrom-OnlineUtf8Base64 '6K+36YCJ5oup'), 'Select an option')
        InvalidChoice = @((ConvertFrom-OnlineUtf8Base64 '5peg5pWI6YCJ6aG577yM6K+36L6T5YWlIDDjgIEx44CBMiDmiJYgM+OAgg=='), 'Invalid option. Enter 0, 1, 2 or 3.')
        Downloading = @((ConvertFrom-OnlineUtf8Base64 '5q2j5Zyo5LiL6L295bm25qCh6aqM5pyA5paw5q2j5byP54mILi4u'), 'Downloading and verifying the latest stable release...')
        Ready = @((ConvertFrom-OnlineUtf8Base64 '5Y+R5biD5YyF5qCh6aqM6YCa6L+H44CC'), 'Release package verification passed.')
        OperationFailed = @((ConvertFrom-OnlineUtf8Base64 '5pON5L2c5aSx6LSl'), 'Operation failed')
        InstallFailed = @((ConvertFrom-OnlineUtf8Base64 '5a6J6KOF5Zmo6L+U5Zue5aSx6LSl54q25oCB'), 'Installer returned a failure status')
        MonitorFailed = @((ConvertFrom-OnlineUtf8Base64 '5Y6G5Y+y5pel5b+X55uR5o6n5Zmo6L+U5Zue5aSx6LSl54q25oCB'), 'History monitor returned a failure status')
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
    $found = [regex]::Matches($ChecksumText, "(?im)^([0-9a-f]{64})[ `t]+\*?$escapedName[ `t]*`r?$")
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
