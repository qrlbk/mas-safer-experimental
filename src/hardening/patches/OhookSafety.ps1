$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'This local safer build requires Windows PowerShell 5.1.' }
$journalBlock = [IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferjournal:\r?$'
if ($journalBlock.Count -ne 3) { throw 'Invalid recovery journal helper block.' }
. ([scriptblock]::Create($journalBlock[1])) # Definitions only; plan/preflight creates no journal.
$hashes = @{
    'sppc32.dll' = '09865ea5993215965e8f27a74b8a41d15fd0f60f5f404cb7a8b3c7757acdab02'
    'sppc64.dll' = '393a1fa26deb3663854e41f2b687c188a9eacd87b23f17ea09422c4715cb5a9f'
}
$plans = New-Object Collections.Generic.List[object]
$snapshots = New-Object Collections.Generic.List[object]
function Assert-Directory([string]$path) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not [IO.Directory]::Exists($path)) { throw "Missing/non-absolute directory: $path" }
    for ($d = Get-Item -LiteralPath $path -Force; $null -ne $d; $d = $d.Parent) {
        if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Redirected directory refused: $($d.FullName)" }
    }
}
function Item([string]$path) {
    try { Get-Item -LiteralPath $path -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
}
function Is-Hook([string]$path) {
    $item = Item $path
    if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    return $hashes.Values -contains (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-MicrosoftFile([string]$path) {
    $item = Item $path
    if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Expected an ordinary Microsoft DLL: $path" }
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw "Microsoft signature could not be verified: $path" }
}
function Assert-Link([string]$path, [string]$target) {
    $item = Item $path
    if ($item -and ($item.LinkType -ne 'SymbolicLink' -or $item.Target.Count -ne 1 -or [IO.Path]::GetFullPath($item.Target[0]) -ine [IO.Path]::GetFullPath($target))) {
        throw "Unknown file/link left untouched: $path"
    }
}
function Add-Plan([string]$path, [string]$kind, $data) {
    Assert-Directory (Split-Path -Parent $path)
    if (@($plans | Where-Object Path -eq $path).Count) { throw "Duplicate mutation target: $path" }
    $plans.Add([pscustomobject]@{Path=$path; Kind=$kind; Data=$data})
}
function Hook-Bytes([string]$name) {
    if (-not $hashes.ContainsKey($name)) { throw "Unknown hook architecture: $name" }
    $parts = [IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split (':' + [regex]::Escape($name) + ':.*')
    if ($parts.Count -ne 3) { throw 'Expected exactly one embedded DLL block.' }
    $bytes = [Convert]::FromBase64String($parts[1])
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($actual -ne $hashes[$name]) { throw "Embedded DLL hash mismatch: $name" }
    return ,$bytes
}
function Plan-C2R([string]$directory, [string]$original, [string]$hook, [bool]$remove) {
    Assert-Directory $directory
    $dll = Join-Path $directory 'sppc.dll'; $link = Join-Path $directory 'sppcs.dll'
    if ((Item $dll) -and -not (Is-Hook $dll)) { throw "Unknown DLL left untouched: $dll" }
    Assert-MicrosoftFile $original
    Assert-Link $link $original
    if ($remove) {
        if (Is-Hook $dll) {
            Add-Plan $dll 'delete' $null
            if (Item $link) { Add-Plan $link 'delete' $null }
        }
    } else {
        Add-Plan $dll 'file' (Hook-Bytes $hook)
        if (-not (Item $link)) { Add-Plan $link 'link' $original }
    }
}
function Plan-OSPP([string]$directory, [string]$hook, [bool]$remove) {
    Assert-Directory $directory
    $dll = Join-Path $directory 'OSPPC.DLL'; $original = Join-Path $directory 'sppcs.dll'
    if (Is-Hook $dll) {
        Assert-MicrosoftFile $original
        if ($remove) {
            Add-Plan $dll 'file' ([IO.File]::ReadAllBytes($original))
            Add-Plan $original 'delete' $null
        } else { Add-Plan $dll 'file' (Hook-Bytes $hook) }
    } elseif (-not $remove) {
        Assert-MicrosoftFile $dll
        if (Item $original) { throw "Existing backup DLL left untouched: $original" }
        Add-Plan $original 'file' ([IO.File]::ReadAllBytes($dll))
        Add-Plan $dll 'file' (Hook-Bytes $hook)
    } elseif (Item $dll) {
        Assert-MicrosoftFile $dll
    }
}
switch ($env:MAS_SAFE_ACTION) {
    { $_ -in @('install','validate') } { Plan-C2R $env:_hookPath $env:_sppcPath $env:_hook $false }
    { $_ -in @('install-ospp','validate-ospp') } {
        if ($env:_osppPath68) { Plan-OSPP $env:_osppPath68 $env:_hook68 $false }
        if ($env:_osppPath86) { Plan-OSPP $env:_osppPath86 $env:_hook86 $false }
        $target = if ($env:_osppPath86) { Join-Path $env:_osppPath86 'sppcs.dll' } else { Join-Path $env:_osppPath68 'sppcs.dll' }
        $link = Join-Path $env:_hookPath 'sppcs.dll'
        Assert-Link $link $target
        if (-not (Item $link)) { Add-Plan $link 'link' $target }
    }
    'uninstall' {
        $dirs = @()
        foreach ($key in '_16CHook','_15CHook') {
            $base = [Environment]::GetEnvironmentVariable($key)
            if ($base) { $dirs += Join-Path $base 'System'; $dirs += Join-Path $base 'SystemX86' }
        }
        foreach ($key in '_16MHook','_15MHook','_14MHook') {
            $base = [Environment]::GetEnvironmentVariable($key)
            if ($base) { $dirs += $base }
        }
        foreach ($base in @($env:ProgramFiles,$env:ProgramW6432,${env:ProgramFiles(x86)}) | Select-Object -Unique) {
            if (-not $base) { continue }
            foreach ($v in '14','15','16') { $dirs += Join-Path $base "Microsoft Office\Office$v" }
            foreach ($v in 'Office','Office 15') { foreach ($arch in 'System','SystemX86') { $dirs += Join-Path $base "Microsoft $v\root\vfs\$arch" } }
        }
        $osppDirs = @()
        foreach ($base in @($env:CommonProgramFiles,$env:CommonProgramW6432,${env:CommonProgramFiles(x86)}) | Select-Object -Unique) {
            if ($base) { $osppDirs += Join-Path $base 'Microsoft Shared\OfficeSoftwareProtectionPlatform' }
        }
        # Registry paths may end in a slash while conventional paths do not.
        # Normalize before deduplication so one Office directory is planned once.
        $dirs = @($dirs | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) } | Sort-Object -Unique)
        $osppDirs = @($osppDirs | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) } | Sort-Object -Unique)
        $osppTargets = @($osppDirs | ForEach-Object { Join-Path $_ 'sppcs.dll' })
        foreach ($dir in $dirs) {
            $link = Item (Join-Path $dir 'sppcs.dll')
            # OSPP installs only a forwarding link here, not an Office-local sppc.dll.
            if ($link -and $link.LinkType -eq 'SymbolicLink' -and $link.Target.Count -eq 1 -and
                $osppTargets -icontains [IO.Path]::GetFullPath([string]$link.Target[0])) {
                Assert-Directory $dir
                Assert-Link $link.FullName ([IO.Path]::GetFullPath([string]$link.Target[0]))
                $shared = Split-Path -Parent ([string]$link.Target[0])
                if (-not (Is-Hook (Join-Path $shared 'OSPPC.DLL'))) { throw "Unrecognized OSPP installation: $shared" }
                Assert-MicrosoftFile ([string]$link.Target[0])
                Add-Plan $link.FullName 'delete' $null
                continue
            }
            if (-not (Test-Path -LiteralPath (Join-Path $dir 'sppc.dll'))) { continue }
            if (-not $link -or $link.Target.Count -ne 1) { throw "Missing/unrecognized forwarding link: $dir" }
            $expected = @((Join-Path $env:windir 'System32\sppc.dll'), (Join-Path $env:windir 'SysWOW64\sppc.dll'))
            if ($expected -inotcontains [string]$link.Target[0]) { throw "Unexpected forwarding target: $dir" }
            Plan-C2R $dir $link.Target[0] '' $true
        }
        foreach ($dir in $osppDirs | Select-Object -Unique) {
            if (Test-Path -LiteralPath $dir) { Plan-OSPP $dir '' $true }
        }
    }
    default { throw 'Unknown safer Ohook operation.' }
}
if ($env:MAS_SAFE_ACTION -like 'validate*') { Write-Host 'Ohook preflight passed; no files changed.'; exit 0 }
if ($plans.Count -eq 0) { Write-Host 'No recognized safer-build hook to change.'; exit 0 }

# Back up ALL affected files before the first mutation. Backups live in an admin-only directory.
$backupRoot = Join-Path $env:windir 'MAS-Safer-Backups'
if (-not (Test-Path -LiteralPath $backupRoot)) { [void][IO.Directory]::CreateDirectory($backupRoot) }
Assert-Directory $backupRoot
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
Set-Acl -LiteralPath $backupRoot -AclObject $acl
$backup = Join-Path $backupRoot ([guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($backup)
Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'operation-started' -Result $env:MAS_SAFE_ACTION -Required $true
$attempted = New-Object Collections.Generic.List[int]
$staged = @{}
$complete = $false
try {
foreach ($plan in $plans) {
    $item = Item $plan.Path
    $saved = [pscustomobject]@{Path=$plan.Path; Existed=[bool]$item; Link=$null; Backup=$null; Hash=$null; Acl=$null}
    if ($item) {
        $saved.Acl = (Get-Acl -LiteralPath $plan.Path).Sddl
        if ($item.LinkType -eq 'SymbolicLink') { $saved.Link = [string]$item.Target[0] }
        else {
            $saved.Backup = Join-Path $backup ($snapshots.Count.ToString()+'.bin')
            [IO.File]::Copy($plan.Path,$saved.Backup,$false)
            $saved.Hash = (Get-FileHash -LiteralPath $saved.Backup).Hash
            if ($saved.Hash -ne (Get-FileHash -LiteralPath $plan.Path).Hash) { throw 'Backup verification failed.' }
        }
    }
    $snapshots.Add($saved)
    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'backup-recorded' -Item $saved.Path -Backup $saved.Backup -Auxiliary $saved.Link -Sha256 $saved.Hash -Result ('existed='+$saved.Existed) -Required $true
}
$snapshots | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8
    # Prepare every replacement before touching any destination.
    for ($i=0; $i -lt $plans.Count; $i++) {
        $plan = $plans[$i]
        if ($plan.Kind -eq 'file') {
            $tmp = $plan.Path + '.mas-safer-' + [guid]::NewGuid().ToString('N') + '.tmp'
            $staged[$i] = $tmp
            $stream = New-Object IO.FileStream($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
            try { $stream.Write($plan.Data,0,$plan.Data.Length); $stream.Flush() } finally { $stream.Dispose() }
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $expected = ([BitConverter]::ToString($sha.ComputeHash([byte[]]$plan.Data))).Replace('-','') } finally { $sha.Dispose() }
            if ((Get-FileHash -LiteralPath $tmp).Hash -ne $expected) { throw 'Staged DLL verification failed.' }
            Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'output-staged' -Item $plan.Path -Auxiliary $tmp -Sha256 $expected -Required $true
        }
    }
    for ($i=0; $i -lt $plans.Count; $i++) {
        $plan = $plans[$i]; $saved = $snapshots[$i]
        Assert-Directory (Split-Path -Parent $plan.Path)
        $current = Item $plan.Path
        if ($saved.Existed) {
            if ($saved.Link) { Assert-Link $plan.Path $saved.Link; if (-not $current) { throw 'Link disappeared after backup.' } }
            elseif (-not $current -or $current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                    (Get-FileHash -LiteralPath $plan.Path).Hash -ne $saved.Hash) { throw 'File changed after backup.' }
        } elseif ($current) { throw 'Destination appeared after preflight.' }
        Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'mutation-intent' -Item $plan.Path -Backup $saved.Backup -Auxiliary ([string]$staged[$i]) -Result $plan.Kind -Required $true
        $attempted.Add($i) # Only now may a native operation partially change its destination.
        if ($plan.Kind -eq 'file') {
            if ($current) { [IO.File]::Replace($staged[$i],$plan.Path,$staged[$i]+'.displaced') }
            else { [IO.File]::Move($staged[$i],$plan.Path) }
        } elseif ($plan.Kind -eq 'link') {
            [void](New-Item -ItemType SymbolicLink -Path $plan.Path -Target $plan.Data)
        } else { Remove-Item -LiteralPath $plan.Path -Force }
        Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'mutation-returned' -Item $plan.Path -Result 'file-operation-only'
    }
    'complete' | Set-Content -LiteralPath (Join-Path $backup 'status.txt')
    $complete = $true
    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'files-committed' -Result 'activation-not-verified'
    Write-Host "Verified Ohook files updated. Backups: $backup"
} catch {
    $failure = $_
    $rollbackErrors = @()
    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'operation-failed' -Result $failure.Exception.GetType().FullName
    for ($a=$attempted.Count-1; $a -ge 0; $a--) {
        $i=$attempted[$a]; $saved=$snapshots[$i]; $plan=$plans[$i]
        try {
            Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'rollback-intent' -Item $saved.Path -Backup $saved.Backup -Result 'recovery-pending'
            Assert-Directory (Split-Path -Parent $saved.Path)
            $current = Item $saved.Path
            if ($saved.Existed) {
                if ($saved.Link) {
                    if ($current) { Assert-Link $saved.Path $saved.Link }
                    else { [void](New-Item -ItemType SymbolicLink -Path $saved.Path -Target $saved.Link) }
                }
                else {
                    if ($current -and ($current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint))) { throw 'Unexpected rollback destination; preserving it.' }
                    if ($current -and (Get-FileHash -LiteralPath $saved.Path).Hash -eq $saved.Hash) {
                        Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'rollback-item' -Item $saved.Path -Sha256 $saved.Hash -Result 'unchanged'
                        continue
                    }
                    # Never delete the current DLL before preparing its complete replacement.
                    $restore = $saved.Path + '.mas-restore-' + [guid]::NewGuid().ToString('N')
                    if ((Get-FileHash -LiteralPath $saved.Backup).Hash -ne $saved.Hash) { throw 'Recovery backup hash mismatch.' }
                    [IO.File]::Copy($saved.Backup,$restore,$false)
                    if ((Get-FileHash -LiteralPath $restore).Hash -ne $saved.Hash) { throw 'Recovery staging hash mismatch.' }
                    $fileAcl=New-Object Security.AccessControl.FileSecurity
                    $fileAcl.SetSecurityDescriptorSddlForm($saved.Acl,[Security.AccessControl.AccessControlSections]::Access)
                    Set-Acl -LiteralPath $restore -AclObject $fileAcl
                    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'recovery-staged' -Item $saved.Path -Backup $saved.Backup -Auxiliary $restore -Sha256 $saved.Hash
                    if ($current) { [IO.File]::Replace($restore,$saved.Path,$restore+'.displaced') }
                    else { [IO.File]::Move($restore,$saved.Path) }
                }
            } elseif ($current) {
                # Remove only the file/link created by this operation, never an unknown object.
                if ($plan.Kind -eq 'link') { Assert-Link $saved.Path ([string]$plan.Data) }
                elseif ($plan.Kind -eq 'file') {
                    if ($current.PSIsContainer -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected new rollback destination.' }
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try { $expected = ([BitConverter]::ToString($sha.ComputeHash([byte[]]$plan.Data))).Replace('-','') } finally { $sha.Dispose() }
                    if ((Get-FileHash -LiteralPath $saved.Path).Hash -ne $expected) { throw 'New file changed; preserving it.' }
                } else { throw 'Unexpected rollback operation.' }
                Remove-Item -LiteralPath $saved.Path -Force
            }
            Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'rollback-item' -Item $saved.Path -Backup $saved.Backup -Result 'restored-or-removed-new-object'
        } catch {
            $rollbackErrors += $_.Exception.Message
            Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'rollback-item' -Item $saved.Path -Backup $saved.Backup -Result ('manual-recovery:'+$_.Exception.GetType().FullName)
        }
    }
    $rollbackResult = if ($rollbackErrors.Count) { 'manual-recovery-required' } else { 'restored-or-unchanged; licensing-state-not-restored' }
    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'file-rollback-ended' -Result $rollbackResult
    throw "Ohook operation failed: $($failure.Exception.Message). Backups: $backup. File rollback errors: $($rollbackErrors -join '; '). Licensing API/registry changes are not rolled back."
} finally {
    if ($complete) {
        foreach ($tmp in $staged.Values) {
            foreach ($path in @($tmp,($tmp+'.displaced'))) {
                try { if (Item $path) { Remove-Item -LiteralPath $path -Force } } catch {
                    Write-RecoveryRecord -Directory $backup -Scope 'Ohook-files' -Event 'cleanup-retained' -Item $path -Result $_.Exception.GetType().FullName
                    Write-Warning "Retained staging file: $path"
                }
            }
        }
    }
}
