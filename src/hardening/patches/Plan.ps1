# Read-only inventory and conditional plan. Never imports or invokes activation code.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'Plan view requires Windows PowerShell 5.1.' }
$method = $env:MAS_PLAN_METHOD
if ([string]::IsNullOrWhiteSpace($method)) {
    $method = switch ([IO.Path]::GetFileName($env:MAS_SAFE_SELF)) {
        'HWID_Activation.cmd' { 'HWID' }
        'Ohook_Activation_AIO.cmd' { 'Ohook' }
        'TSforge_Activation.cmd' { 'TSforge' }
        'Online_KMS_Activation.cmd' { 'KMS' }
        default { 'All' }
    }
}
if ($method -notin @('All','HWID','Ohook','TSforge','KMS')) { throw 'Use /Plan with All, HWID, Ohook, TSforge or KMS. No activation was requested.' }
$source = $env:MAS_SAFE_SELF
if (-not [IO.File]::Exists($source)) { throw 'The source script could not be read.' }
$sourceText = [IO.File]::ReadAllText($source)
function Show([string]$line) { Write-Output $line }
function Read-Registry([string]$path, [string[]]$names) {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null; $key = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
            $key = $base.OpenSubKey($path,$false)
            if ($key) {
                foreach ($name in $names) {
                    $value = $key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ($null -ne $value) {
                        # Registry strings are data, never commands; remove control characters from display.
                        Show ('  {0} {1}: {2}' -f $view,$name,([regex]::Replace([string]$value,'[\x00-\x1f\x7f]',' ')))
                    }
                }
            }
        } catch { Show ('  {0}: unavailable ({1})' -f $view,$_.Exception.GetType().Name) }
        finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
    }
}
function Show-Flag([string]$name) {
    $matches = [regex]::Matches($sourceText,'(?im)^set\s+"?'+[regex]::Escape($name)+'=([01])"?\s*$')
    if ($matches.Count -eq 1) { Show ('  {0}={1}' -f $name,$matches[0].Groups[1].Value) }
    else { Show ('  {0}: source-dependent or unavailable; inspect the chosen module' -f $name) }
}
Show 'MAS safer r3 - PLAN ONLY'
Show ('Source: '+[IO.Path]::GetFileName($source))
Show ('Selected scope: '+$method)
Show 'No activation, elevation, service control, registry writes, downloads or journal creation is performed by this mode.'
Show 'This is a conditional plan, not a successful preflight or a guarantee of activation.'
Show ''
Show 'Windows inventory (read-only):'
Read-Registry 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' @('ProductName','EditionID','CurrentBuildNumber','DisplayVersion','UBR')
Show ('Process architecture: '+$env:PROCESSOR_ARCHITECTURE)
try {
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($env:windir))
    Show ('Free space on Windows volume: {0:N2} GiB (no write probe)' -f ($drive.AvailableFreeSpace/1GB))
} catch { Show 'Free space: unavailable; not treated as sufficient.' }
Show ''
Show 'Source defaults (runtime options and product discovery may change the actual path):'
foreach ($flag in 'MAS_SAFER_ALLOW_PUBLIC_KMS','MAS_SAFER_ALLOW_LICENSE_CLEANUP','MAS_SAFER_ALLOW_REPAIRS','_NoEditionChange','_norentsk') { Show-Flag $flag }
Show ''
if ($method -in @('All','HWID')) {
    Show 'HWID - possible actions when explicitly activated later:'
    Show '  Inspect Windows edition and existing license; start required services.'
    Show '  Install a product key, prepare/import a ticket and contact activation services.'
    Show '  Automatic edition/region changes are disabled by safer defaults.'
    Show '  Key/ticket/service changes are not covered by automatic file rollback.'
}
if ($method -in @('All','Ohook','TSforge','KMS')) {
    Show ''
    Show 'Office inventory (C2R registry only; an absent entry does NOT exclude MSI/UWP Office):'
    Read-Registry 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration' @('InstallationPath','Platform','VersionToReport','ProductReleaseIds')
    Show 'Office MSI/UWP products and exact hook targets: not resolved in plan-only mode.'
}
if ($method -in @('All','Ohook')) {
    Show ''
    Show 'Ohook - possible actions when explicitly installed/uninstalled later:'
    Show '  Resolve C2R/MSI/OSPP paths; check existing DLLs, links and Microsoft signatures.'
    Show '  Install license/key data; back up recognized DLLs and link metadata.'
    Show '  Stage verified DLL bytes; replace DLLs/create links; attempt file rollback on failure.'
    Show '  Uninstall removes recognized forwarding links and restores recognized OSPPC files.'
    Show '  Conditional targets: Office sppc.dll/sppcs.dll and shared OfficeSoftwareProtectionPlatform\OSPPC.DLL.'
    Show '  Prior key/registry changes are not undone by DLL rollback.'
}
if ($method -in @('All','TSforge')) {
    Show ''
    Show 'TSforge - possible actions when explicitly activated later:'
    Show '  Resolve the licensing store/version and selected product IDs; stop/restart SPP as needed.'
    Show '  For PKEY2005, validate physical/token stores before removing keys; reopen after licensing API changes.'
    Show '  Prepare backups and encrypted store outputs; replace stores; attempt per-file recovery on failure.'
    Show '  Write associated registry data and invalidate cache; perform the selected activation method.'
    Show '  Candidate store locations (not opened, parsed, hashed or locked by plan mode):'
    foreach ($relative in 'System32\spp\store','System32\spp\store\2.0','System32\spp\store_test\2.0','ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform') {
        Show ('    '+[IO.Path]::Combine($env:windir,$relative))
    }
    Show '  A registry-configured TokenStore or legacy Vista store may be used instead.'
    Show '  Store schema, decryptability, API availability and full-state rollback: NOT verified here.'
}
if ($method -in @('All','KMS')) {
    Show ''
    Show 'KMS - possible actions when explicitly activated later:'
    Show '  Install appropriate keys, configure the selected host/port and contact that host.'
    Show '  With safer defaults and no explicit trusted host, activation is refused.'
    Show '  Optional renewal-task creation requires different settings; task cleanup may still run.'
    Show '  Key, host, registry and scheduler changes do not have automatic full rollback.'
}
Show ''
Show 'Journal and recovery limits:'
Show ('  Future mutation journals: '+[IO.Path]::Combine($env:windir,'MAS-Safer-Recovery'))
Show ('  Ohook backup manifests/journals: '+[IO.Path]::Combine($env:windir,'MAS-Safer-Backups'))
Show '  Store .bak/.tmp/.restore files are beside the affected store; journals list exact paths.'
Show '  No terminal event means interrupted or unknown, never success.'
Show '  File rollback does not roll back product keys, the registry, service state or remote activation.'
Show ''
Show 'Not checked: effective write/delete permissions, backup creation, DLL trust/network certificate checks,'
Show 'store compatibility, licensing service health, network reachability, activation or recovery behavior.'
Show 'Plan view ends here. It never continues into activation.'
