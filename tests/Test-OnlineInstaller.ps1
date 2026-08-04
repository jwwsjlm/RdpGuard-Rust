$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param($Actual, $Expected, [string]$Message = 'values differ')
    if ($Actual -ne $Expected) { throw "$Message`: expected '$Expected', got '$Actual'" }
}

function Assert-True {
    param([bool]$Value, [string]$Message)
    if (-not $Value) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Action)
    try { & $Action } catch { return }
    throw 'expected action to throw'
}

. "$PSScriptRoot\..\Install-RdpGuard-Online.ps1" -LibraryMode

Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'zh-CN') 'zh-CN'
Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'en-US') 'en-US'
$archiveName = 'RdpGuard-Rust-v0.3.2.zip'
$hash = 'a' * 64
Assert-Equal (Get-ExpectedArchiveHash -ChecksumText "$hash  $archiveName`n" -ArchiveName $archiveName) $hash
Assert-Throws { Get-ExpectedArchiveHash -ChecksumText 'invalid' -ArchiveName $archiveName }
Assert-Throws { Get-ExpectedArchiveHash -ChecksumText "$hash  $archiveName`n$hash  $archiveName" -ArchiveName $archiveName }
Assert-Throws { Assert-ArchiveHash -Expected ('0' * 64) -Actual ('1' * 64) }
Assert-ArchiveHash -Expected ('A' * 64) -Actual ('a' * 64)

$script:downloads = 0
$script:installedLanguage = $null
$script:monitorLanguage = $null
$provider = {
    $script:downloads++
    [pscustomobject]@{ Root = 'C:\verified'; TempDirectory = 'C:\temporary' }
}
$install = { param($Bundle, $Language) $script:installedLanguage = $Language }
$monitor = { param($Bundle, $Language) $script:monitorLanguage = $Language }

$result = Invoke-RdpGuardMenuChoice -Choice '0' -Language 'zh-CN' -Bundle $null -BundleProvider $provider -InstallAction $install -MonitorAction $monitor
Assert-True $result.Exit 'choice 0 must exit'
Assert-Equal $script:downloads 0 'choice 0 must not download'

$result = Invoke-RdpGuardMenuChoice -Choice '3' -Language 'zh-CN' -Bundle $null -BundleProvider $provider -InstallAction $install -MonitorAction $monitor
Assert-Equal $result.Language 'en-US'
Assert-Equal $script:downloads 0 'language toggle must not download'

$result = Invoke-RdpGuardMenuChoice -Choice '1' -Language 'en-US' -Bundle $null -BundleProvider $provider -InstallAction $install -MonitorAction $monitor
Assert-Equal $script:downloads 1
Assert-Equal $script:installedLanguage 'en-US'
Assert-True ($null -ne $result.Bundle) 'install choice must cache the bundle'

$result = Invoke-RdpGuardMenuChoice -Choice '2' -Language 'zh-CN' -Bundle $result.Bundle -BundleProvider $provider -InstallAction $install -MonitorAction $monitor
Assert-Equal $script:downloads 1 'cached bundle must be reused'
Assert-Equal $script:monitorLanguage 'zh-CN'

$temporary = Join-Path ([IO.Path]::GetTempPath()) "RdpGuard-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporary | Out-Null
Assert-Throws { Invoke-WithTemporaryCleanup -TemporaryDirectory $temporary -Action { throw 'test failure' } }
Assert-True (-not (Test-Path -LiteralPath $temporary)) 'temporary directory must be removed after errors'

Write-Output 'Online installer tests passed.'
