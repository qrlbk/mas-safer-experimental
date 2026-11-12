$ErrorActionPreference='Stop'
$dest=Join-Path $env:ProgramFiles 'MAS-Safer-Renewal'
function Assert-NoRedirect([string]$path) {
    $item=Get-Item -LiteralPath $path -Force
    for ($d=$item; $null -ne $d; $d=$d.Parent) {
        if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Redirected path refused: $($d.FullName)" }
    }
}
$files=@()
if (Test-Path -LiteralPath $dest) {
    Assert-NoRedirect $dest
    $files=@(Get-ChildItem -LiteralPath $dest -Force)
    foreach ($file in $files) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notin @('Activation_task.cmd','Info.txt','Logs.txt','mas-safer-task.sha256')) {
            throw "Unexpected renewal-directory content left untouched: $($file.FullName)"
        }
    }
    if ($files.Count) {
        $expected=(Get-Content -LiteralPath (Join-Path $dest 'mas-safer-task.sha256') -Raw).Trim()
        $actual=(Get-FileHash -LiteralPath (Join-Path $dest 'Activation_task.cmd') -Algorithm SHA256).Hash
        if ($expected -notmatch '^[0-9A-Fa-f]{64}$' -or $expected -ine $actual) { throw 'Renewal payload ownership/integrity check failed.' }
    }
}
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
$folder=$scheduler.GetFolder('\')
$tasks=@($folder.GetTasks(0) | Where-Object { $_.Name -in @('MAS-Safer-Renewal','MAS-Safer-RunOnce') })
foreach ($task in $tasks) {
    [xml]$xml=$task.Xml
    $command=[Environment]::ExpandEnvironmentVariables([string]$xml.Task.Actions.Exec.Command)
    if ($xml.Task.RegistrationInfo.Source -ne 'MAS local safer build - unofficial' -or $command -ine (Join-Path $dest 'Activation_task.cmd')) {
        throw "Task is not owned by this safer build: $($task.Name)"
    }
}
# No legacy tasks, registry menu entries or legacy directories are removed.
foreach ($task in $tasks) { $folder.DeleteTask($task.Name,0) }
foreach ($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
if (Test-Path -LiteralPath $dest) { [IO.Directory]::Delete($dest,$false) }
