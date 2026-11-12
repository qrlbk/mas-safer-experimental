"""Deterministic local hardening patches; never executes the downloaded scripts."""
from pathlib import Path
import re, shutil, hashlib, json, difflib
from revision2 import revise_cs, revise_batch
from revision3 import revise_cs as revise_cs3, revise_batch as revise_batch3

HERE = Path(__file__).resolve().parent
ORIGINAL = HERE.parent / 'mas-review/Microsoft-Activation-Scripts-master'
TARGET = HERE / 'Microsoft-Activation-Scripts-safer'
PATCHES = HERE / 'patches'

def replace(s, old, new, count=1):
    assert s.count(old) == count, (old[:100], s.count(old), count)
    return s.replace(old, new)

def closing(s, pos):
    # C# lexical brace matcher; braces in strings/comments do not delimit scopes.
    token = re.compile(r'@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|[{}]')
    depth = 0
    for m in token.finditer(s, pos):
        if m.group() == '{': depth += 1
        elif m.group() == '}':
            depth -= 1
            if depth == 0: return m.start()
    raise AssertionError('Unclosed scope')

def method(s, signature, body):
    start = s.index(signature)
    end = closing(s, s.index('{', start)) + 1
    return s[:start] + body + s[end:]

def harden_cs(src):
    src = replace(src, 'asyncResult.AsyncWaitHandle.WaitOne();', '''if (!asyncResult.AsyncWaitHandle.WaitOne(60000, false)) {
                    webRequest.Abort();
                    throw new TimeoutException("Activation service timed out after 60 seconds.");
                }''')
    # Add explicit commits at the successful END of each existing using body.
    edits=[]
    for m in re.finditer(r'using \((IPhysicalStore|ITokenStore) (\w+) = [^\n]+\)\s*\{', src):
        end = closing(src, src.index('{', m.start()))
        if 'store.WriteRaw(' in src[m.end():end]: continue # WriteRaw is already an explicit write.
        indent = re.search(r'\n( *)[^\n]*$', src[:m.start()]).group(1)
        edits.append((end, '    ' + m.group(2) + '.Commit();\n' + indent))
    assert len(edits) == 11, len(edits)
    for at, value in sorted(edits, reverse=True): src = src[:at] + value + src[at:]
    # Group the generated-key token and physical stores into one rollback-capable file batch.
    marker='            using (IPhysicalStore ps = SPPUtils.GetStore(version, production))'
    start=src.index(marker); end=closing(src, src.index('{', start))+1
    block=src[start:end]
    src=src[:start]+'''            using (StoreWriteBatch batch = new StoreWriteBatch())
            {
'''+block+'''
                batch.Commit();
            }'''+src[end:]

    src=replace(src,'void Deserialize();\n        void Serialize();','void Deserialize();\n        void Serialize();\n        void Commit();')
    src=replace(src,'byte[] ReadRaw();\n        void WriteRaw(byte[] data);','byte[] ReadRaw();\n        void WriteRaw(byte[] data);\n        void Commit();')
    lo=src.index('    public class TokenStoreModern'); hi=src.index('// LibTSforge/PhysicalStore/Common.cs',lo)
    chunk=src[lo:hi]
    chunk=method(chunk,'        public void Deserialize()', (PATCHES/'TokenDeserialize.cs').read_text().rstrip())
    chunk=replace(chunk,'((Entries.Count / ENTRIES_PER_BLOCK) + 1) * ENTRIES_PER_BLOCK','Math.Max(1, (Entries.Count + ENTRIES_PER_BLOCK - 1) / ENTRIES_PER_BLOCK) * ENTRIES_PER_BLOCK')
    chunk=replace(chunk,'if (eIndex < Entries.Count)\n                        {','if (eIndex + 1 < Entries.Count)\n                        {')
    start=chunk.index('            tokens = new MemoryStream(tokensData);')
    end=chunk.index('\n        public void AddEntry',start)
    chunk=chunk[:start]+'''            Array.Copy(tokensHash, 0, tokensData, 4, tokensHash.Length);
            StoreWriteBatch.Write(new FileStream[] { TokensFile }, new byte[][] { tokensData });
        }

        public void Commit() { Serialize(); }
'''+chunk[end:]
    chunk=replace(chunk,'TokensFile = File.Open(tokensPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);\n            Deserialize();','''TokensFile = File.Open(tokensPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            try { Deserialize(); }
            catch { TokensFile.Close(); throw; }''')
    chunk=replace(chunk,'            Serialize();\n            TokensFile.Close();','            TokensFile.Close();')
    src=src[:lo]+chunk+src[hi:]

    for classname, version in [('PhysicalStoreModern','Version'),('PhysicalStoreVista','PSVersion.Vista'),('PhysicalStoreWin7','PSVersion.Win7')]:
        lo=src.index('    public sealed class '+classname); hi=closing(src,src.index('{',lo))+1
        chunk=src[lo:hi]
        files='new FileStream[] { TSFile }' if classname=='PhysicalStoreModern' else 'new FileStream[] { TSPrimary, TSSecondary }'
        values='new byte[][] { data }' if classname=='PhysicalStoreModern' else 'new byte[][] { data, data }'
        close='TSFile.Close();' if classname=='PhysicalStoreModern' else 'TSPrimary.Close(); TSSecondary.Close();'
        chunk=method(chunk,'        public void Dispose()',f'''        public void Dispose() {{ {close} }}

        public void Commit()
        {{
            byte[] data = PhysStoreCrypto.EncryptPhysicalStore(Serialize(), Production, {version});
            StoreWriteBatch.Write({files}, {values});
        }}''')
        chunk=method(chunk,'        public void WriteRaw(byte[] data)',f'''        public void WriteRaw(byte[] data)
        {{
            data = PhysStoreCrypto.EncryptPhysicalStore(data, Production, {version});
            StoreWriteBatch.Write({files}, {values});
        }}''')
        chunk=chunk.replace('FileMode.OpenOrCreate','FileMode.Open')
        # Close a partially opened constructor on corrupt files, including failure opening the second file.
        sig='        public '+classname+'('
        at=chunk.index(sig); brace=chunk.index('{',at); end=closing(chunk,brace)
        old=chunk[brace+1:end]
        if classname=='PhysicalStoreModern':
            first,rest=old.split('\n',2)[1:]
            new='\n'+first+'\n            try\n            {\n'+rest+'\n            }\n            catch { TSFile.Close(); throw; }\n        '
        else:
            first,rest=old.split('\n',2)[1:]
            new='\n'+first+'\n            try\n            {\n'+rest+'\n            }\n            catch { TSPrimary.Close(); if (TSSecondary != null) TSSecondary.Close(); throw; }\n        '
        chunk=chunk[:brace+1]+new+chunk[end:]
        src=src[:lo]+chunk+src[hi:]
    # All binary parsing must fail on a short/negative/oversized read, not return partial data.
    src=src.replace('.ReadBytes(','.ReadExactBytes(')
    src=replace(src,'public static class BinaryReaderExt\n    {','''public static class BinaryReaderExt
    {
        public static byte[] ReadExactBytes(this BinaryReader reader, int count)
        {
            if (count < 0 || count > 128 * 1024 * 1024 ||
                count > reader.BaseStream.Length - reader.BaseStream.Position)
                throw new FormatException("Binary field length outside store bounds.");
            byte[] value = reader.ReadBytes(count);
            if (value.Length != count) throw new EndOfStreamException("Incomplete binary field.");
            return value;
        }
''')
    src=replace(src,'reader.BaseStream.Seek(-pos & (to - 1), SeekOrigin.Current);','''int padding = -pos & (to - 1);
            if (reader.BaseStream.Position + padding > reader.BaseStream.Length)
                throw new FormatException("Binary alignment exceeds stream bounds.");
            reader.BaseStream.Seek(padding, SeekOrigin.Current);''')
    src=replace(src,'return br.ReadExactBytes((int)fs.Length);','''if (fs.Length > 128 * 1024 * 1024) throw new FormatException("Store exceeds 128 MiB limit.");
            return br.ReadExactBytes((int)(fs.Length - fs.Position));''')
    return src+'\n\n'+(PATCHES/'StoreWriteBatch.cs').read_text()

def main():
    if TARGET.is_symlink(): raise SystemExit('Refusing a symlink output directory.')
    if TARGET.exists():
        marker=TARGET/'.mas-safer-generated'
        if not marker.is_file() or marker.read_text()!='MAS safer generated output\n':
            raise SystemExit('Output directory exists without the generation marker; refusing to remove it.')
        shutil.rmtree(TARGET)
    shutil.copytree(ORIGINAL,TARGET)
    (TARGET/'.mas-safer-generated').write_text('MAS safer generated output\n')
    aio=ORIGINAL/'MAS/All-In-One-Version-KL/MAS_AIO.cmd'
    text=aio.read_text()
    cs=text.split("$src = @'\n",1)[1].split("\n'@",1)[0]
    safe_cs=revise_cs3(revise_cs(harden_cs(cs)))
    (HERE/'PatchedFull.cs').write_text(safe_cs)
    log=[]
    for path in sorted(TARGET.rglob('*.cmd')):
        orig=path.read_text(); s=orig
        if "$src = @'\n" in s:
            embedded=s.split("$src = @'\n",1)[1].split("\n'@",1)[0]
            assert embedded==cs,path
            s=replace(s,cs,safe_cs)
            # Even a failed store operation must reach the upstream service recovery routine.
            s=replace(s,'''            Write-Host "[$prodName] activation has failed." -ForegroundColor White -BackgroundColor DarkRed
        }
    }
}''','''            Write-Host "[$prodName] activation has failed." -ForegroundColor White -BackgroundColor DarkRed
        }
        finally {
            try { [LibTSforge.SPP.SPPUtils]::RestartSPP($ver) }
            catch { $errcode = 3; Write-Host "Service recovery failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
}''')
            s=replace(s,'''        Write-Host "$($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    }
}

Exit $errcode''','''        Write-Host "$($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    }
    finally {
        try { [LibTSforge.SPP.SPPUtils]::RestartSPP($ver) }
        catch { $errcode = 3; Write-Host "Service recovery failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
}

Exit $errcode''')
        # All scripts retain CRLF: the self-extraction patterns explicitly require it.
        s=revise_batch3(revise_batch(harden_batch(s,path)),path)
        path.write_bytes(s.replace('\n','\r\n').encode('utf-8'))
        log.append({'file':str(path.relative_to(TARGET)),'changed':orig!=s,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    (HERE/'changes.diff').write_text(''.join(''.join(difflib.unified_diff((ORIGINAL/p.relative_to(TARGET)).read_text().splitlines(True),p.read_text().splitlines(True),fromfile='original/'+str(p.relative_to(TARGET)),tofile='safer/'+str(p.relative_to(TARGET)))) for p in sorted(TARGET.rglob('*.cmd'))))
    (HERE/'build-manifest.json').write_text(json.dumps(log,indent=2))
    print('Patched',sum(x['changed'] for x in log),'scripts; embedded C#:',len(safe_cs.splitlines()),'lines')

def harden_batch(s,path):
    if '\n:oh_hookinstall\n' in s:
        s=s.replace('call :oh_ppcpath\n','''call :oh_ppcpath
call :mas_safer_preflight
if errorlevel 1 goto :dk_done
''')
        for label,action in [('oh_hookinstall','install'),('oh_hookinstall_ospp','install-ospp')]:
            start=s.index('\n:'+label+'\n')
            nextlabel='oh_hookinstall_ospp' if action=='install' else 'oh_hookinstall_error'
            end=s.index('\n:'+nextlabel+'\n',start)
            s=s[:start]+f'''
:{label}
set ierror=
set hasherror=
set "MAS_SAFE_SELF=%~f0"
set "MAS_SAFE_ACTION={action}"
call :mas_safer_ohook
if errorlevel 1 set "ierror=verified Ohook file operation - see error above"
goto :oh_hookinstall_error
'''+s[end:]
        # Keep upstream discovery but replace every wildcard/size-based uninstall and profile cleanup.
        start=s.index('if defined _16CHook (if exist',s.index('\n:oh_uninstall\n'))
        end=s.index('\n:oh_reset\n',start)
        s=s[:start]+'''
set "MAS_SAFE_SELF=%~f0"
set "MAS_SAFE_ACTION=uninstall"
call :mas_safer_ohook
if errorlevel 1 set error=1
echo Registry and user subscription licenses are preserved by safer uninstall.
goto :dk_done
'''+s[end:]
        start=s.index('\n:oh_extractdll\n'); end=s.index('\n:sppc32.dll:',start)
        s=s[:start]+'''
:: Original DLL bytes below are standard base64; SHA-256 is enforced by mas_safer_ohook.
'''+s[end:]
        for name in ['sppc32.dll','sppc64.dll']:
            pattern=r'(:'+re.escape(name)+r':\n)([\s\S]*?)(\n:'+re.escape(name)+r':)'
            s,n=re.subn(pattern,lambda m:m[1]+m[2].replace('-','A').replace('_','a')+m[3],s)
            assert n==1,(path,name,n)
        s=s.replace('Modifying Hash of Custom sppcs.dll','Verifying SHA256 of Custom sppc.dll')
        s+='''
:: Embedded helper is called explicitly; never fall through into PowerShell text.
exit /b
:mas_safer_preflight
set "MAS_SAFE_SELF=%~f0"
set "MAS_SAFE_ACTION=validate"
if defined isOspp set "MAS_SAFE_ACTION=validate-ospp"
call :mas_safer_ohook
if errorlevel 1 (set error=1&set ierror=Preflight&exit /b 1)
exit /b 0
:mas_safer_ohook
%psc% "$ErrorActionPreference='Stop'; try { $f=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferohook:\\r?$'; if ($f.Count -ne 3) { throw 'Invalid helper block' }; & ([scriptblock]::Create($f[1])); exit 0 } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }"
exit /b %errorlevel%
:saferohook:
'''+(PATCHES/'OhookSafety.ps1').read_text()+':saferohook:\n'
    # Make risk choices explicit in source, defaulting to preservation.
    config='''
:: MAS 3.14 LOCAL SAFER BUILD - experimental; see README-SAFER.txt.
:: Set a specific switch to 1 only after reading its documented effects.
set "MAS_SAFER_ALLOW_PUBLIC_KMS=0"
set "MAS_SAFER_ALLOW_LICENSE_CLEANUP=0"
set "MAS_SAFER_ALLOW_REPAIRS=0"
set "MAS_SAFE_SELF=%~f0"
'''
    s=s.replace('@echo off\n','@echo off\n'+config,1)
    s=re.sub(r'^set _NoEditionChange=0$', 'set _NoEditionChange=1',s,flags=re.M)
    s=s.replace('set _norentsk=0','set _norentsk=1',1)
    s=s.replace('<Source>Microsoft Corporation</Source>','<Source>MAS local safer build - unofficial</Source>')
    s=s.replace('<Hidden>true</Hidden>','<Hidden>false</Hidden>')
    s=s.replace('%nil%','')
    for empty in ['blank','w','-']:
        s=s.replace('%'+empty+'%','')
    s=s.replace("'@::RANDOM-' + [Guid]::NewGuid().Guid + [Environment]::NewLine + $f",'$f')
    s=s.replace("'@::%randguid%' + [Environment]::NewLine + $f[1].Trim()","$f[1].Trim()")
    s=s.replace(':: Add random data on top to create unique file which helps in avoiding AV\'s detections',':: Copy the reviewed source without randomized changes.')
    # No unsolicited upstream version probes. This is a separately maintained local variant.
    if '::  Check for updates\n' in s:
        start=s.index('::  Check for updates\n')
        end=s.index('::================================================================',start)
        s=s[:start]+':: Upstream update probe disabled for this pinned local build.\n\n'+s[end:]
    # No generated setup script may erase the shared Windows Setup Scripts directory.
    s=re.sub(r'^.*\(goto\^?\).*rd /s /q.*~dp0.*$', ':: Safer build retains setup files; no shared-directory deletion.',s,flags=re.M)
    if '\n:Extract$OEM$3\n' in s:
        s=s.replace('\n:Extract$OEM$3\n','''
:Extract$OEM$3
if exist "!desktop!\\$OEM$\\" (
echo Existing desktop $OEM$ folder is preserved. Move it before extracting again.
goto :Extract$OEM$2
)
''',1)
        s=s.replace('if exist "!desktop!\\$OEM$\\.*" rmdir /s /q "!desktop!\\$OEM$\\" %nul%','echo Partial OEM output was retained for inspection.')
    if path.name=='Extract_OEM_Folder.cmd':
        s=s.replace('md "!desktop!\\$OEM$\\$$\\Setup\\Scripts"','''if exist "!desktop!\\$OEM$\\" (
echo Existing desktop $OEM$ folder is preserved. Move it before extracting again.
goto :done2
)
md "!desktop!\\$OEM$\\$$\\Setup\\Scripts"''')
    s=s.replace('http://officecdn.microsoft.com','https://officecdn.microsoft.com')
    s='\n'.join(line for line in s.split('\n') if not (re.search(r'reg delete .*\\Policies\\Microsoft\\(?:cloud\\)?office\\16\.0\\common\\officeupdate',line,re.I)))
    if '\n:oemenu\n' in s:
        s=s.replace('\n:oemenu\n','''
:oemenu
%psc% "$ErrorActionPreference='Stop'; try { foreach ($h in 'HKLM:','HKCU:') { foreach ($root in 'SOFTWARE','SOFTWARE\\WOW6432Node') { foreach ($product in 'office','cloud\\office') { if (Test-Path ($h+'\\'+$root+'\\Policies\\Microsoft\\'+$product+'\\16.0\\Common\\officeupdate')) { throw 'Managed Office update policy found. Change refused; contact its administrator.' } } } }; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 goto :dk_done
''',1)
    if '\n:oh_clearblock\n' in s:
        s=s.replace('\n:oh_clearblock\n','''
:oh_clearblock
if not "%MAS_SAFER_ALLOW_LICENSE_CLEANUP%"=="1" (
echo Safer build: preserving existing Office user licenses and licensing policies.
exit /b
)
echo EXPLICIT OPT-IN: legacy all-profile license cleanup is enabled.
''',1)
    # Eliminate the destructive WMI rebuild code, including its separate helper.
    if '\n:fixwmi\n' in s:
        start=s.index('\n:fixwmi\n'); end=s.index('\n:checkwmi\n',start)
        s=s[:start]+'''
:fixwmi
echo Safer build: checking WMI without stopping services or rebuilding its repository.
call :checkwmi
if defined error echo WMI check failed. Use supported Windows repair procedures.
if not defined error echo WMI check passed.
goto :at_back
'''+s[end:]
    if '::  Change Windows region to USA' in s:
        start=s.index('::  Change Windows region to USA');end=s.index('::================================================================',start)
        s=s[:start]+''':: Safer build does not change the user's region automatically.
set regionchange=
echo Safer build: Windows region is preserved.

'''+s[end:]
    # Protection being enabled is a stop condition, not a reason to disable it.
    s=s.replace('call :dk_color %Blue% "It is recommended that you disable it from the Windows Defender settings."','echo Safer build: leaving Smart App Control enabled and aborting Ohook.\ngoto :dk_done')
    if '\n:dk_chkmal\n' in s:
        start=s.index('::  Remove the scheduled task of R@1n-KMS'); end=s.index('\nexit /b',start)
        s=s[:start]+':: Safer build preserves tasks created by other software.\n'+s[end:]
    # Keep diagnostics but gate automatic repairs. Service START remains needed by activation.
    if '\n:dk_errorcheck\n' in s:
        start=s.index('\n:dk_errorcheck\n');end=s.index('\n:wpatest:',start)
        block=s[start:end]
        lines=[]
        for line in block.splitlines():
            if not line.lstrip().startswith('::') and (re.search(r'(?i)\b(?:reg (?:add|delete)|sc config|mkdir |cscript .*?/rilc)',line) or 'Set-Acl -Path' in line or re.match(r'\s*%psc%.*(?:ReinstallLicenses|InstallLicense)',line)):
                line='if "%MAS_SAFER_ALLOW_REPAIRS%"=="1" (\n'+line+'\n)'
            lines.append(line)
        s=s[:start]+'\n'.join(lines)+'\n'+s[end:]
    # Avoid activation-related mutations in the status-only command.
    s=s.replace('$null = PrintDigitalLicenseStatus', 'CONOUT "Digital-license acquisition skipped by read-only status mode."')
    s=s.replace('try {sasv $winsvc -EA 1}', 'try {if ((gsv $winsvc -EA 1).Status -ne "Running") {throw "Service is stopped; read-only mode will not start it."}}')
    s=s.replace('try {sasv $offsvc -EA 1}', 'try {if ((gsv $offsvc -EA 1).Status -ne "Running") {throw "Service is stopped; read-only mode will not start it."}}')
    s=s.replace("'ACID' $tokenParts[0]","'ACID' '[redacted]'")
    s=s.replace("'User' $tokenParts[3]","'User' '[redacted]'")
    s=s.replace("'Acid' $decodedLicense.Acid","'Acid' '[redacted]'")
    s=s.replace("'DeviceId' $decodedLicense.Metadata.DeviceId","'DeviceId' '[redacted]'")
    s=s.replace("'TenantId' (\"N/A\", $decodedLicense.Metadata.TenantId)[!($null -eq $decodedLicense.Metadata.TenantId)]","'TenantId' '[redacted]'")
    s=s.replace('Client Machine ID (CMID): $ClientMachineID','Client Machine ID (CMID): [redacted]')
    if '\n:ks_start\n' in s:
        # Use distinct names so cleanup cannot erase an upstream/third-party installation.
        s=s.replace('Activation-Renewal','MAS-Safer-Renewal').replace('Activation-Run_Once','MAS-Safer-RunOnce')
        start=s.index('\n:ks_clearstuff\n');end=s.index('\n:_extracttask:',start)
        s=s[:start]+'''
:ks_clearstuff
set "MAS_SAFE_SELF=%~f0"
%psc% "$ErrorActionPreference='Stop'; try { $f=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:saferkms:\\r?$'; if ($f.Count -ne 3) { throw 'Invalid helper block' }; & ([scriptblock]::Create($f[1])); exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 set error_=1
exit /b
'''+s[end:]
        s+='\nexit /b\n:saferkms:\n'+(PATCHES/'KmsCleanup.ps1').read_text()+':saferkms:\n'
        s=s.replace('<RegistrationInfo>\n    <Date>', '<RegistrationInfo>\n    <Source>MAS local safer build - unofficial</Source>\n    <Date>')
        s=s.replace('\n:ks_start\n','''
:ks_start
%psc% "$s=$env:_server; $p=$env:_port; if ($s -and ($s.Length -gt 253 -or $s -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$')) { Write-Host 'Invalid KMS hostname or IPv4 address'; exit 1 }; if ($p -and ($p -notmatch '^[0-9]{1,5}$' -or [int]$p -lt 1 -or [int]$p -gt 65535)) { Write-Host 'Invalid KMS port'; exit 1 }; exit 0"
if errorlevel 1 exit /b
if not defined _server if not "%MAS_SAFER_ALLOW_PUBLIC_KMS%"=="1" (
echo Public third-party KMS servers are disabled by default in this local build.
echo Select a trusted KMS server in the menu, or explicitly change MAS_SAFER_ALLOW_PUBLIC_KMS.
if not %_unattended%==1 pause
exit /b
)
''',1)
        # Validate pasted input through environment variables, before cmd interpolates it.
        s=s.replace('set "_server=%_server: =%"','''%psc% "if ($env:_server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]$' -and $env:_server -notmatch '^[A-Za-z0-9]$') { exit 1 }"
if errorlevel 1 (set _server=&echo Invalid server name.&goto :ks_menu)''')
        s=s.replace('set "_port=%_port: =%"','''%psc% "if ($env:_port -notmatch '^[0-9]{1,5}$' -or [int]$env:_port -lt 1 -or [int]$env:_port -gt 65535) { exit 1 }"
if errorlevel 1 (set _port=&echo Invalid port.&goto :ks_menu)''')
        # Create payload and restrict its directory BEFORE registering a SYSTEM task.
        marker='if not exist "%_dest%\\" md "%_dest%\\" %nul%'
        if marker in s:
            secured='''
%psc% "$ErrorActionPreference='Stop'; try { $p=$env:_dest; for ($d=Get-Item -LiteralPath $p; $null -ne $d; $d=$d.Parent) { if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected task directory refused' } }; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (set error=1&exit /b)
%psc% "$ErrorActionPreference='Stop'; try { $a=New-Object Security.AccessControl.DirectorySecurity; $a.SetAccessRuleProtection($true,$false); foreach ($s in 'S-1-5-18','S-1-5-32-544') { $id=New-Object Security.Principal.SecurityIdentifier($s); $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }; Set-Acl -LiteralPath $env:_dest -AclObject $a; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (set error=1&exit /b)
'''
            s=s.replace(marker,marker+secured,1)
        start=s.index('\n:ks_renewal\n');end=s.index('\n:ks_RenExport\n',start)
        block=s[start:end]
        match=re.search(r'call :ks_createInfo\.txt\n%psc% [^\n]+\n',block)
        assert match,path
        payload='''call :ks_createInfo.txt
%psc% "$ErrorActionPreference='Stop'; try { $f=[IO.File]::ReadAllText($env:MAS_SAFE_SELF) -split '(?m)^:_extracttask:\\r?$'; if ($f.Count -ne 3) { throw 'Invalid embedded task' }; $p=Join-Path $env:_dest 'Activation_task.cmd'; [IO.File]::WriteAllText($p,$f[1].Trim(),[Text.Encoding]::ASCII); $hash=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash; [IO.File]::WriteAllText((Join-Path $env:_dest 'mas-safer-task.sha256'),$hash); exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (set error=1&exit /b)
'''
        block=block[:match.start()]+block[match.end():]
        index=block.index('schtasks /create')
        block=block[:index]+payload+'if not exist "%_dest%\\Activation_task.cmd" (set error=1&exit /b)\n'+block[index:]
        s=s[:start]+block+s[end:]
    return s

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original',type=Path,help='Extracted upstream source root (contains MAS and LICENSE).')
    args=parser.parse_args()
    if args.original: ORIGINAL=args.original.resolve()
    main()
