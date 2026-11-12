"""Offline invariants for the safer source package; does not run activation."""
import base64, hashlib, re, sys, xml.etree.ElementTree as ET
from pathlib import Path

root=Path(sys.argv[1])
aio=root/'MAS/All-In-One-Version-KL/MAS_AIO.cmd'
s=aio.read_text()
cmds=list(root.rglob('*.cmd'))
assert len(cmds)==10,len(cmds)
for p in cmds:
    b=p.read_bytes(); text=b.decode('utf-8')
    assert b'\n' not in b.replace(b'\r\n',b''),(p,'non-CRLF newline')
    assert 'MapFileAndCheckSum' not in text,p
    assert 'rd /s /q "%%~dp0"' not in text,p
    assert not re.search(r'winmgmt /resetrepository|rmdir /s /q .*wbem\\repository',text,re.I),p
    assert '<Hidden>true</Hidden>' not in text,p
    assert '<Source>Microsoft Corporation</Source>' not in text,p
    assert 'http://officecdn.microsoft.com' not in text,p
    assert not re.search(r'(?:\bdel\b|Remove-Item).*sppc\*dll',text,re.I),p
    assert 'sasv $winsvc' not in text and 'sasv $offsvc' not in text,p
    assert '$null = PrintDigitalLicenseStatus' not in text,p
    assert '%nil%' not in text and '%blank%' not in text,p
    if ':oh_clearblock' in text: assert 'set "MAS_SAFER_ALLOW_LICENSE_CLEANUP=0"' in text,p
    if ':ks_start' in text:
        assert re.search(r'^set _norentsk=1\r?$',text,re.M),p
        assert 'set "MAS_SAFER_ALLOW_PUBLIC_KMS=0"' in text,p
        assert text.index('[IO.File]::WriteAllText($p,$f[1].Trim()') < text.index('schtasks /create /tn "MAS-Safer-Renewal"'),p
    for m in re.finditer(r'(?m)^:(renewal|run_once|renewal_vista|run_once_vista):\r?$',text):
        parts=re.split(r'(?m)^:'+re.escape(m[1])+r':\r?$',text)
        assert len(parts)==3
        xml=ET.fromstring(parts[1].strip())
        ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        assert xml.find('t:RegistrationInfo/t:Source',ns).text=='MAS local safer build - unofficial'
        assert xml.find('t:Settings/t:Hidden',ns).text=='false'
        assert 'MAS-Safer-Renewal' in xml.find('t:Actions/t:Exec/t:Command',ns).text
print('PASS: source safety defaults, task XML, write-before-schedule order, 10 CRLF scripts.')

for name,expected in [('sppc32.dll','09865ea5993215965e8f27a74b8a41d15fd0f60f5f404cb7a8b3c7757acdab02'),('sppc64.dll','393a1fa26deb3663854e41f2b687c188a9eacd87b23f17ea09422c4715cb5a9f')]:
    for p in [aio,root/'MAS/Separate-Files-Version/Activators/Ohook_Activation_AIO.cmd']:
        blob=re.split(r'(?m)^:'+re.escape(name)+r':$',p.read_text())[1]
        data=base64.b64decode(''.join(blob.split()),validate=True)
        assert hashlib.sha256(data).hexdigest()==expected
print('PASS: both DLLs remain byte-identical to the audited upstream DLLs in both distributions.')

def cs(text): return text.split("$src = @'\n",1)[1].split("\n'@",1)[0]
compiled=root/'verification/PatchedFull.cs'
expected=cs(s)
assert cs((root/'MAS/Separate-Files-Version/Activators/TSforge_Activation.cmd').read_text())==expected
if compiled.exists(): assert compiled.read_text()==expected
for label in ['saferohook','saferkms','_extracttask']:
    assert len(re.split(r'(?m)^:'+label+r':$',s))==3,label
assert 'public void Dispose() { TSFile.Close(); }' in expected
assert 'public void Dispose() { TSPrimary.Close(); TSSecondary.Close(); }' in expected
assert len(re.findall(r'\b(?:store|ps|tks)\.Commit\(\)',expected))==11
assert 'batch.Commit();' in expected
assert 'TokensFile.SetLength(' not in expected and 'TSFile.SetLength(' not in expected
print('PASS: identical embedded C#, explicit commits, no direct truncation of license stores, helper extraction boundaries.')
