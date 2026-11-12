"""Source-only revision 2 transformations. No tests, compilation or MAS execution."""

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source layout: ' + old[:90])
    return text.replace(old, new, 1)


def revise_cs(src):
    # PKEY2009 keeps its upstream operation order. PKEY2005 validates stores first.
    src = replace_once(src, '''            Guid instPkeyId = SLApi.GetInstalledPkeyID(actId);
            if (instPkeyId != Guid.Empty) SLApi.UninstallProductKey(instPkeyId);

            if (pkey.Algorithm == PKeyAlgorithm.PKEY2009)
            {
''', '''            if (pkey.Algorithm == PKeyAlgorithm.PKEY2009)
            {
                Guid instPkeyId = SLApi.GetInstalledPkeyID(actId);
                if (instPkeyId != Guid.Empty) SLApi.UninstallProductKey(instPkeyId);
''')
    src = replace_once(src, '''            string currEdition = SLApi.GetMetaStr(actId, "Family");

            if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
''', '''            string currEdition = SLApi.GetMetaStr(actId, "Family");

            // All newly strict format checks run before ANY product key is removed.
            // Dispose is read-only. These objects are discarded, never committed.
            // Service recovery is still required if preflight itself fails.
            try
            {
                SPPUtils.KillSPP(version);
                using (IPhysicalStore preflightPhysical = SPPUtils.GetStore(version, production))
                using (ITokenStore preflightTokens = SPPUtils.GetTokenStore(version))
                {
                    string preflightSuffix = (version == PSVersion.Win8 || version == PSVersion.WinBlue || version == PSVersion.WinModern) ? "_--_met" : "_met";
                    preflightTokens.GetMetaEntry("msft:spp/token/PKeyIdUriMapper" + preflightSuffix);
                    preflightTokens.GetMetaEntry(actId + preflightSuffix);
                    if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
                        preflightTokens.GetMetaEntry("msft:spp/token/windows/productkeyid/" + currEdition);
                }
            }
            finally { SPPUtils.RestartSPP(version); }

            // Reopen stores after the licensing API updates them; never write stale preflight data.
            Guid previousPkeyId = SLApi.GetInstalledPkeyID(actId);
            if (previousPkeyId != Guid.Empty) SLApi.UninstallProductKey(previousPkeyId);

            if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
''')
    src = replace_once(src, '                        WritePkey2005RegistryValues(version, pkey);',
                       '                        // Registry values are written only after the file batch commits.')
    src = replace_once(src, '''                    string cachePath = SPPUtils.GetTokensPath(version).Replace("tokens.dat", @"cache\cache.dat");
                    if (File.Exists(cachePath)) File.Delete(cachePath);
''', '')
    src = replace_once(src, '''                batch.Commit();
            }

            SLApi.RefreshTrustedTime(actId);''', '''                batch.Commit();
            }

            // Still stopped: invalidate the cache before asking the licensing service to reload.
            string cachePath = SPPUtils.GetTokensPath(version).Replace("tokens.dat", @"cache\cache.dat");
            if (File.Exists(cachePath)) File.Delete(cachePath);
            if (appId == SLApi.WINDOWS_APP_ID && !isAddon)
                WritePkey2005RegistryValues(version, pkey);

            SLApi.RefreshTrustedTime(actId);''')
    return src


def revise_batch(s):
    if '\n:oh_hookinstall\n' in s:
        s = replace_once(s, '\n:oh_menu2\n', '\n:oh_menu2\nset mas_safer_ohook_failed=\n')
        s = replace_once(s, 'if errorlevel 1 (set error=1&set ierror=Preflight&exit /b 1)',
                         'if errorlevel 1 (set error=1&set ierror=Preflight&set mas_safer_ohook_failed=1&exit /b 1)')
        lo = s.index('\n:oh_hookinstall_error\n'); hi = s.index('\n:oh_setspp\n', lo)
        block = s[lo:hi]
        block = replace_once(block, '\nexit /b\n', '\nif defined ierror (set mas_safer_ohook_failed=1&exit /b 1)\nexit /b 0\n')
        s = s[:lo] + block + s[hi:]
        install = '''if defined isOspp (
call :oh_hookinstall_ospp
) else (
call :oh_hookinstall
)
'''
        lo = s.index('\n:oh_processmsi\n'); hi = s.index('\n:oh_clearblock\n', lo)
        block = s[lo:hi]
        block = replace_once(block, 'if errorlevel 1 goto :dk_done', 'if errorlevel 1 exit /b 1')
        block = replace_once(block, install, install + 'if defined mas_safer_ohook_failed exit /b 1\n')
        prefix = s[:lo]
        if prefix.count(install) != 2: raise ValueError('Unexpected C2R call sites')
        prefix = prefix.replace(install, install + 'if defined mas_safer_ohook_failed goto :dk_done\n')
        for call in ('if defined o14msi call :oh_processmsi 14 %o14msi_reg%',
                     'if defined o15msi call :oh_processmsi 15 %o15msi_reg%',
                     'if defined o16msi call :oh_processmsi 16 %o16msi_reg%'):
            prefix = replace_once(prefix, call, call + '\nif defined mas_safer_ohook_failed goto :dk_done')
        s = prefix + block + s[hi:]
    if '\n:dk_errorcheck\n' in s:
        lo = s.index('::  Change disabled services startup type to default')
        hi = s.index('::  Check if the services are able to run or not', lo)
        block = s[lo:hi]
        # Do not enclose the status output in a new CMD block: percent-expanded
        # service lists must be read AFTER the repair loop, as in upstream.
        block = replace_once(block, 'if defined serv_ste (', '''if not "%MAS_SAFER_ALLOW_REPAIRS%"=="1" if defined serv_ste (
echo Enabling Disabled Services              [Skipped: automatic repairs disabled] [%serv_ste%]
set error=1
)
if "%MAS_SAFER_ALLOW_REPAIRS%"=="1" if defined serv_ste (''')
        block = block.replace('echo A registry fix has been applied to enable the disabled service.',
                              'echo Automatic service repair failed. Inspect the service configuration before retrying.')
        s = s[:lo] + block + s[hi:]
        s = replace_once(s, 'if not defined _vis if !errorlevel! NEQ 0 set rlicfailed=1',
                         'if "%MAS_SAFER_ALLOW_REPAIRS%"=="1" if not defined _vis if !errorlevel! NEQ 0 set rlicfailed=1')
        old = 'if %winbuild% GEQ 7600 if not defined toerr if not exist "%tokenstore%\\" ('
        s = replace_once(s, old, '''if not "%MAS_SAFER_ALLOW_REPAIRS%"=="1" if %winbuild% GEQ 7600 if not defined toerr if not exist "%tokenstore%\\" (
echo Checking SPP Token Folder               [Missing; automatic creation skipped]
set error=1
)
if "%MAS_SAFER_ALLOW_REPAIRS%"=="1" ''' + old)
        old = '''reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "SkipRearm" /t REG_DWORD /d "0" /f %nul%
)
call :dk_color %Gray% "Checking SkipRearm                      [Default 0 Value Not Found. Changing To 0]"
%psc% "Start-Job { Stop-Service sppsvc -force } | Wait-Job -Timeout 20 | Out-Null"
'''
        new = '''reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "SkipRearm" /t REG_DWORD /d "0" /f %nul%
if !errorlevel!==0 (
call :dk_color %Gray% "Checking SkipRearm                      [Changed To 0]"
%psc% "Start-Job { Stop-Service sppsvc -force } | Wait-Job -Timeout 20 | Out-Null"
) else (
set error=1
call :dk_color %Red% "Checking SkipRearm                      [Failed To Change]"
)
) else (
echo Checking SkipRearm                      [Non-default; automatic repair skipped]
)
'''
        s = replace_once(s, old, new)
    return s
