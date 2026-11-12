# Definitions only. Loading this block does not create files.
function Assert-RecoveryDirectory([string]$path) {
    if (-not [IO.Path]::IsPathRooted($path) -or -not [IO.Directory]::Exists($path)) { throw 'Invalid recovery directory.' }
    for ($d = Get-Item -LiteralPath $path -Force; $null -ne $d; $d = $d.Parent) {
        if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected recovery directory refused.' }
    }
}
function New-RecoveryFolder {
    $root = Join-Path $env:windir 'MAS-Safer-Recovery'
    Assert-RecoveryDirectory $env:windir
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    if (-not [IO.Directory]::Exists($root)) { [void][IO.Directory]::CreateDirectory($root,$acl) }
    Assert-RecoveryDirectory $root
    Set-Acl -LiteralPath $root -AclObject $acl
    $directory = Join-Path $root ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory,$acl)
    return $directory
}
function Write-RecoveryRecord {
    param([string]$Directory,[string]$Scope,[string]$Event,[string]$Item='',
          [string]$Backup='',[string]$Auxiliary='',[string]$Sha256='',
          [string]$Result='',[bool]$Required=$false)
    try {
        Assert-RecoveryDirectory $Directory
        $path = Join-Path $Directory 'events.jsonl'
        if ([IO.File]::Exists($path) -and (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Redirected journal refused.' }
        $parent = $env:MAS_RECOVERY_RUN_ID
        if ($parent -notmatch '^[a-fA-F0-9]{32}$') { $parent = '' }
        if ($parent -eq [IO.Path]::GetFileName($Directory)) { $parent = '' }
        $record = [ordered]@{schema=1;utc=[DateTime]::UtcNow.ToString('o');operation=[IO.Path]::GetFileName($Directory);
            parent=$parent;scope=$Scope;event=$Event;item=$Item;backup=$Backup;auxiliary=$Auxiliary;sha256=$Sha256;result=$Result}
        $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress -Depth 3)+[Environment]::NewLine)
        $stream = New-Object IO.FileStream($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
    } catch {
        if ($Required) { throw 'Recovery journal could not be written; the next mutation was not started.' }
        try { Write-Warning ('Recovery journal incomplete: '+$Directory+'. Inspect backups; no recovery outcome is implied.') -WarningAction Continue }
        catch { # A closed output stream must not interrupt rollback either.
        }
    }
}
function Invoke-BatchJournal {
    $ErrorActionPreference = 'Stop'
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'Recovery journal requires Windows PowerShell 5.1.' }
    $scope = $env:MAS_RECOVERY_SCOPE
    if ($scope -notin @('HWID','Ohook','TSforge','KMS','Ohook-Uninstall','KMS-Uninstall')) { throw 'Unknown journal scope.' }
    if ($env:MAS_RECOVERY_ACTION -eq 'begin') {
        $directory = New-RecoveryFolder
        Write-RecoveryRecord -Directory $directory -Scope $scope -Event 'operation-started' -Result 'activation-not-verified' -Required $true
        # Only this token is returned to CMD. No key, argument string or exception text is logged.
        Write-Output ([IO.Path]::GetFileName($directory))
        return
    }
    if ($env:MAS_RECOVERY_RUN_ID -notmatch '^[a-fA-F0-9]{32}$') { throw 'Invalid recovery operation ID.' }
    $directory = Join-Path (Join-Path $env:windir 'MAS-Safer-Recovery') $env:MAS_RECOVERY_RUN_ID
    if ($env:MAS_RECOVERY_ACTION -eq 'end') {
        $result = 'control-returned-activation-not-verified'
        if ($env:error -or $env:error_ -or $env:MAS_RECOVERY_LOG_FAILED) { $result = 'control-returned-with-errors-or-incomplete-log' }
        Write-RecoveryRecord -Directory $directory -Scope $scope -Event 'control-returned' -Result $result -Required $true
    } elseif ($env:MAS_RECOVERY_ACTION -eq 'phase') {
        if ($env:MAS_RECOVERY_EVENT -notin @('diagnostics','key-install-may-run','hwid-ticket-may-run','ohook-files-may-change','tsforge-processing','kms-processing')) { throw 'Unknown journal event.' }
        Write-RecoveryRecord -Directory $directory -Scope $scope -Event $env:MAS_RECOVERY_EVENT -Result 'intent-not-outcome' -Required $true
    } else { throw 'Unknown journal action.' }
}
