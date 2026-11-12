"""Run only synthetic file tests. No Windows licensing API is invoked."""
from pathlib import Path
import os, shutil, subprocess

here=Path(__file__).resolve().parent
run=here/'test-run'
run.mkdir(exist_ok=True)
(run/'fixtures').mkdir(exist_ok=True)
for p in (here/'fixtures').glob('*.dat'): shutil.copy2(p,run/'fixtures'/p.name)
env=dict(os.environ)
env.update(DOTNET_CLI_HOME=str(run/'dotnet-home'),DOTNET_CLI_TELEMETRY_OPTOUT='1',
           DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_GENERATE_ASPNET_CERTIFICATE='false',DOTNET_NOLOGO='1')
source=(here/'PatchedFull.cs').read_text()
needle='File.Replace(temporary[i], names[i], backups[i]);'
assert source.count(needle)==1
# The fault exists only in the generated test copy, never in the distributed CMD files.
(here/'TestFull.cs').write_text(source.replace(needle,
    'if (TestFaults.FailAt == i) throw new IOException("Injected second replace failure");\n                    '+needle))
for project,name in [('StorageTests.csproj','production-results.txt'),('FaultTests.csproj','fault-results.txt')]:
    result=subprocess.run(['dotnet','run','--project',str(here/project),'--',str(run)],
                          env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
    (run/name).write_text(result.stdout)
    print(result.stdout,end='')
    result.check_returncode()
    expected=33 if project=='StorageTests.csproj' else 34
    assert 'TOTAL PASSED: '+str(expected)+'\n' in result.stdout, 'Wrong test variant/result count; inspect build isolation.'
