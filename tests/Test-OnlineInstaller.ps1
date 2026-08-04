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

$onlineInstaller = Join-Path $PSScriptRoot '..\Install-RdpGuard-Online.ps1'
$onlineInstallerBytes = [IO.File]::ReadAllBytes($onlineInstaller)
Assert-True ($onlineInstallerBytes.Length -ge 3) 'online installer must not be empty'
$hasUtf8Bom = $onlineInstallerBytes[0] -eq 0xEF -and $onlineInstallerBytes[1] -eq 0xBB -and $onlineInstallerBytes[2] -eq 0xBF
Assert-True (-not $hasUtf8Bom) 'online installer must be UTF-8 without BOM so irm can parse it'
Assert-True (($onlineInstallerBytes | Where-Object { $_ -gt 0x7F }).Count -eq 0) 'online installer source must be ASCII so Windows PowerShell 5.1 can parse it without BOM'
[void][scriptblock]::Create([IO.File]::ReadAllText($onlineInstaller, [Text.UTF8Encoding]::new($false)))
$onlineSource = [IO.File]::ReadAllText($onlineInstaller, [Text.UTF8Encoding]::new($false))
Assert-True $onlineSource.Contains("-Verb RunAs") 'online actions must request UAC before protected work'
Assert-True $onlineSource.Contains("RdpGuard\Staging") 'online actions must use protected ProgramData staging'
Assert-True $onlineSource.Contains("Get-NativeRdpGuardArchitecture") 'online actions must select the native architecture'
Assert-True $onlineSource.Contains("Invoke-ProtectedOnlineAction") 'downloads must run inside the elevated action'
Assert-True $onlineSource.Contains("Set-ProtectedOnlineDirectory") 'protected staging must replace its ACL'
Assert-True $onlineSource.Contains("ReparsePoint") 'protected staging must reject reparse points'

. $onlineInstaller -LibraryMode

Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'zh-CN') 'zh-CN'
Assert-Equal (Resolve-RdpGuardLanguage -Language auto -UiCulture 'en-US') 'en-US'
Assert-Equal ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-OnlineText -Language 'zh-CN' -Key Title)))) 'UmRwR3VhcmQg5Zyo57q/5bel5YW3'
Assert-True ((Get-OnlineText -Language 'zh-CN' -Key InvalidChoice).Length -gt 0) 'Chinese invalid-choice text must exist'
$archiveName = "RdpGuard-Rust-$ReleaseTag-windows-$(Get-NativeRdpGuardArchitecture).zip"
$hash = 'a' * 64
Assert-Equal (Get-ExpectedArchiveHash -ChecksumText "$hash  $archiveName`n" -ArchiveName $archiveName) $hash
Assert-Equal (Get-ExpectedArchiveHash -ChecksumText "$hash  $archiveName`r`n" -ArchiveName $archiveName) $hash
Assert-Throws { Get-ExpectedArchiveHash -ChecksumText 'invalid' -ArchiveName $archiveName }
Assert-Throws { Get-ExpectedArchiveHash -ChecksumText "$hash  $archiveName`n$hash  $archiveName" -ArchiveName $archiveName }
Assert-Throws { Assert-ArchiveHash -Expected ('0' * 64) -Actual ('1' * 64) }
Assert-ArchiveHash -Expected ('A' * 64) -Actual ('a' * 64)

$script:actions = [Collections.Generic.List[string]]::new()
$invoker = { param($Action, $Language) $script:actions.Add("$Action|$Language") }

$result = Invoke-RdpGuardMenuChoice -Choice '0' -Language 'zh-CN' -ActionInvoker $invoker
Assert-True $result.Exit 'choice 0 must exit'
Assert-Equal $script:actions.Count 0 'choice 0 must not invoke an action'

$result = Invoke-RdpGuardMenuChoice -Choice '3' -Language 'zh-CN' -ActionInvoker $invoker
Assert-Equal $result.Language 'en-US'
Assert-Equal $script:actions.Count 0 'language toggle must not invoke an action'

$result = Invoke-RdpGuardMenuChoice -Choice '1' -Language 'en-US' -ActionInvoker $invoker
Assert-Equal $script:actions[0] 'install|en-US'

$result = Invoke-RdpGuardMenuChoice -Choice '2' -Language 'zh-CN' -ActionInvoker $invoker
Assert-Equal $script:actions[1] 'monitor|zh-CN'
$result = Invoke-RdpGuardMenuChoice -Choice '4' -Language 'zh-CN' -ActionInvoker $invoker
Assert-Equal $script:actions[2] 'doctor|zh-CN'

$temporary = Join-Path ([IO.Path]::GetTempPath()) "RdpGuard-test-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporary | Out-Null
Assert-Throws { Invoke-WithTemporaryCleanup -TemporaryDirectory $temporary -Action { throw 'test failure' } }
Assert-True (-not (Test-Path -LiteralPath $temporary)) 'temporary directory must be removed after errors'

Write-Output 'Online installer tests passed.'
