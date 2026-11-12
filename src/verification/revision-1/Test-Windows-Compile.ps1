param([string]$PackageRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -or $PSVersionTable.PSVersion -lt [version]'5.1') {
    throw 'Use Windows PowerShell 5.1 for this .NET Framework compile-only check.'
}
$file=Join-Path $PackageRoot 'MAS\All-In-One-Version-KL\MAS_AIO.cmd'
$text=[IO.File]::ReadAllText($file)
$code=($text -split [regex]::Escape('$src = @'''),2)[1]
$code=($code -split "(?m)^'@\r?$",2)[0]
$references=[string[]]@('System.dll','System.Core.dll','System.ServiceProcess.dll','System.Xml.dll','System.Xml.Linq.dll')
$cp=[CodeDom.Compiler.CompilerParameters]$references
$cp.GenerateInMemory=$true
$cp.CompilerOptions='/unsafe'
$provider=New-Object Microsoft.CSharp.CSharpCodeProvider
try {
    $result=$provider.CompileAssemblyFromSource($cp,[string[]]@($code))
    if ($result.Errors.HasErrors) { throw ($result.Errors | Out-String) }
    Write-Output 'PASS: complete embedded C# compiles under this Windows .NET Framework.'
    Write-Output 'No activation or license-store method was invoked. This does NOT verify activation.'
} finally { $provider.Dispose(); $cp.TempFiles.Delete() }
