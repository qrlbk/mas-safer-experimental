"""Source transformations only. Importing this module never runs MAS or tests."""
from pathlib import Path

HERE = Path(__file__).resolve().parent

def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source layout: ' + old[:100])
    return text.replace(old, new, 1)


def revise_cs(src):
    return src + '\n\n' + (HERE / 'patches/RecoveryJournal.cs').read_text()


def revise_batch(s, path):
    names = {'MAS_AIO.cmd':'All', 'HWID_Activation.cmd':'HWID', 'Ohook_Activation_AIO.cmd':'Ohook',
             'TSforge_Activation.cmd':'TSforge', 'Online_KMS_Activation.cmd':'KMS'}
    if path.name not in names: return s
    # Dispatch before MAS settings, relaunch, UAC, QuickEdit, temp files or menu.
    if '@echo off\n' not in s[:1500]: raise ValueError('Missing script entry header')
    s = s.replace('@echo off\n', '@echo off\n@setlocal EnableExtensions DisableDelayedExpansion\n@for %%P in (%*) do @if /i "%%~P"=="/Plan" goto :mas_safer_plan\n', 1)
    marker = 'set "MAS_SAFE_SELF=%~f0"\n'
    if marker not in s: raise ValueError('Missing initial configuration')
    s = s.replace(marker, marker+'set "MAS_RECOVERY_RUN_ID="\nset "MAS_RECOVERY_LOG_FAILED="\n', 1)
    scopes = ['HWID','Ohook','TSforge','KMS'] if path.name == 'MAS_AIO.cmd' else [names[path.name]]
    if s.count('call :dk_errorcheck\n') != len(scopes): raise ValueError('Unexpected diagnostics sites')
    chunks = s.split('call :dk_errorcheck\n')
    assembled = chunks[0]
    for scope, chunk in zip(scopes, chunks[1:]):
        assembled += ('call :mas_safer_journal_begin '+scope+'\nif errorlevel 1 (set error=1&goto :dk_done)\n'
                      'call :mas_safer_journal_event diagnostics\ncall :dk_errorcheck\n') + chunk
    s = assembled
    for label, scope in [('oh_uninstall','Ohook-Uninstall'),('ks_uninstall','KMS-Uninstall')]:
        if '\n:'+label+'\n' in s:
            s = once(s, '\n:'+label+'\n', '\n:'+label+'\ncall :mas_safer_journal_begin '+scope+'\nif errorlevel 1 (set error=1&goto :dk_done)\n')
    s = once(s, '\n:dk_done\n', '\n:dk_done\ncall :mas_safer_journal_end\n')
    for label, phase in [('dk_inskey','key-install-may-run'),('oh_hookinstall','ohook-files-may-change'),
                         ('oh_hookinstall_ospp','ohook-files-may-change'),('ts_act','tsforge-processing'),('ks_activate','kms-processing')]:
        if '\n:'+label+'\n' in s:
            s = once(s, '\n:'+label+'\n', '\n:'+label+'\ncall :mas_safer_journal_event '+phase+'\n')
    if 'call :hwiddata ticket\n' in s:
        s = once(s, 'call :hwiddata ticket\n', 'call :mas_safer_journal_event hwid-ticket-may-run\ncall :hwiddata ticket\n')
    if "$src = @'\n" in s:
        # This wrapper starts after compilation and before any licensing detection/API call.
        start = '[void][LibTSforge.Utils]::Wow64EnableWow64FsRedirection($false)'
        s = once(s, start, '''$masJournal = $null
$masJournalOutcome = 'interrupted-or-unknown'
$errcode = 0
try {
    $masJournal = New-Object LibTSforge.RecoveryJournal('TSforge-processing')
    $masJournal.Required('licensing-actions-may-run','','','','','keys-registry-services-not-transactional')
'''+start)
        end = 'Exit $errcode\n:tsforge:'
        s = once(s, end, '''$masJournalOutcome = if ($errcode -eq 3) { 'worker-returned-with-errors' } else { 'worker-returned; activation-not-independently-verified' }
} catch {
    $errcode = 3
    $masJournalOutcome = 'worker-exception; licensing-state-unknown'
    if ($masJournal) { $masJournal.Note('worker-failed','','','','',$_.Exception.GetType().FullName) }
    Write-Host 'TSforge processing failed. Inspect the recovery journal and existing error output.' -ForegroundColor Red
} finally {
    if ($masJournal) { $masJournal.Note('worker-ended','','','','',$masJournalOutcome) }
}
Exit $errcode
:tsforge:''')
    s += r'''
exit /b
:mas_safer_plan
setlocal EnableExtensions DisableDelayedExpansion
if /i not "%~1"=="/Plan" (
echo /Plan must be the first argument. Mixed activation arguments were refused.
exit /b 2
)
if not "%~3"=="" (
echo Plan accepts only one optional scope: All, HWID, Ohook, TSforge or KMS.
exit /b 2
)
set "MAS_SAFE_SELF=%~f0"
set "MAS_PLAN_METHOD=%~2"
set "MAS_PLAN_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "MAS_PLAN_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%MAS_PLAN_PS%" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { $b=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferplan:\r?$'; if ($b.Count -ne 3) { throw 'Invalid plan block' }; & ([scriptblock]::Create($b[1])); exit 0 } catch { Write-Error ('Plan unavailable: '+$_.Exception.Message); exit 2 }"
exit /b %errorlevel%

:mas_safer_journal_begin
set "MAS_RECOVERY_SCOPE=%~1"
set "MAS_RECOVERY_RUN_ID="
set "MAS_RECOVERY_LOG_FAILED="
set "MAS_RECOVERY_ACTION=begin"
for /f "delims=" %%J in ('%psc% "$ErrorActionPreference='Stop'; try { $b=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferjournal:\r?$'; if ($b.Count -ne 3) { throw 'Invalid journal block' }; . ([scriptblock]::Create($b[1])); Invoke-BatchJournal } catch { [Console]::Error.WriteLine('Recovery journal could not be initialized. No activation phase was started.'); exit 1 }"') do set "MAS_RECOVERY_RUN_ID=%%J"
if not defined MAS_RECOVERY_RUN_ID exit /b 1
echo Recovery journal: %windir%\MAS-Safer-Recovery\%MAS_RECOVERY_RUN_ID%
exit /b 0

:mas_safer_journal_event
set "MAS_RECOVERY_SAVED_RC=%errorlevel%"
if not defined MAS_RECOVERY_RUN_ID exit /b %MAS_RECOVERY_SAVED_RC%
set "MAS_RECOVERY_ACTION=phase"
set "MAS_RECOVERY_EVENT=%~1"
call :mas_safer_journal_write
exit /b %MAS_RECOVERY_SAVED_RC%

:mas_safer_journal_end
if not defined MAS_RECOVERY_RUN_ID exit /b
set "MAS_RECOVERY_ACTION=end"
call :mas_safer_journal_write
set "MAS_RECOVERY_RUN_ID="
exit /b

:mas_safer_journal_write
%psc% "$ErrorActionPreference='Stop'; try { $b=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferjournal:\r?$'; if ($b.Count -ne 3) { throw 'Invalid journal block' }; . ([scriptblock]::Create($b[1])); Invoke-BatchJournal; exit 0 } catch { [Console]::Error.WriteLine('Recovery journal incomplete. Inspect backups; activation/recovery outcome is not implied.'); exit 1 }"
if errorlevel 1 set "MAS_RECOVERY_LOG_FAILED=1"
exit /b

:saferplan:
''' + (HERE/'patches/Plan.ps1').read_text() + '\n:saferplan:\n:saferjournal:\n' + (HERE/'patches/RecoveryJournal.ps1').read_text() + '\n:saferjournal:\n'
    return s
