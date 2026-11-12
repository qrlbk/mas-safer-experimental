param([string]$Root)
$ErrorActionPreference='Stop'
$count=0
foreach($file in Get-ChildItem -LiteralPath $Root -Filter '*.cmd' -Recurse) {
    $s=[IO.File]::ReadAllText($file.FullName)
    $labels=[regex]::Matches($s,'(?m)^:([^:\r\n]+):\r?$') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
    foreach($label in $labels) {
        $parts=[regex]::Split($s,'(?m)^:'+ [regex]::Escape($label)+':\r?$')
        if($parts.Count -ne 3){throw "Unexpected delimiters: $label in $file"}
        if($label -in @('sppc32.dll','sppc64.dll','_extracttask','renewal','run_once','renewal_vista','run_once_vista')) {continue}
        if($parts[1].TrimStart().StartsWith('@echo off')) {continue}
        $tokens=$null; $errors=$null
        [void][Management.Automation.Language.Parser]::ParseInput($parts[1],[ref]$tokens,[ref]$errors)
        if($errors.Count){throw "$($file.Name) : $label : $($errors | Out-String)"}
        $count++
    }
}
Write-Output "PASS: $count embedded PowerShell blocks parse without errors (PowerShell $($PSVersionTable.PSVersion))."

# Load ONLY function definitions from the helper, stopping before dispatch/mutation.
$aio=Join-Path $Root 'MAS/All-In-One-Version-KL/MAS_AIO.cmd'
$env:MAS_SAFE_SELF=$aio
$helper=([IO.File]::ReadAllText($aio) -split '(?m)^:saferohook:\r?$')[1]
$functions=$helper.Substring(0,$helper.IndexOf('switch ($env:MAS_SAFE_ACTION)'))
. ([scriptblock]::Create($functions))
foreach($name in 'sppc32.dll','sppc64.dll') {
    $bytes=Hook-Bytes $name
    if($bytes.Length -ne 9216){throw 'Decoded DLL length mismatch'}
}
Write-Output 'PASS: both embedded DLLs decode to 9216 bytes and match the enforced SHA-256.'
$temp=Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Root).Path) ('mas-safer-test-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $corrupt=Join-Path $temp 'corrupt.cmd'
    $source=[IO.File]::ReadAllText($aio)
    $source=[regex]::Replace($source,'(?m)(^:sppc32.dll:\r?\n)T','$1U')
    [IO.File]::WriteAllText($corrupt,$source)
    $env:MAS_SAFE_SELF=$corrupt
    $rejected=$false;try{$null=Hook-Bytes 'sppc32.dll'}catch{$rejected=$true}
    if(-not $rejected){throw 'Corrupted embedded DLL was accepted'}
    Write-Output 'PASS: one-byte embedded DLL corruption is rejected before planning a write.'
    $unknown=Join-Path $temp 'sppc.dll';[IO.File]::WriteAllText($unknown,'unrecognized file')
    $rejected=$false;try{Plan-C2R $temp 'unused' 'sppc32.dll' $false}catch{$rejected=$_.Exception.Message -like 'Unknown DLL left untouched:*'}
    if(-not $rejected -or [IO.File]::ReadAllText($unknown) -ne 'unrecognized file' -or $plans.Count -ne 0){throw 'Unknown file was not preserved'}
    Write-Output 'PASS: unknown existing DLL is preserved and no write is planned.'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }

# Windows-only signature, registry, ACL and scheduler behavior is intentionally NOT simulated as verified.
