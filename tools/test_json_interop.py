"""Actual serde_json::Value interoperability; Rust is a test-only dependency."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

base=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(base))
import p2s_harden as p

with tempfile.TemporaryDirectory(prefix='p2s-json-interop-') as temporary:
    root=Path(temporary)
    project=root/'parser'
    shutil.copytree(base/'tools/json-interop',project)
    report=p.Report()
    path='/srv/invalid_'+chr(0xdcff)+chr(0xdcfe)+'.php'
    row=report.add('OPEN','PHP '+path,path,rule_id='P2S-WS001',resource=dict(path=path,indicator='request-execution'))
    row['sha256']='a'*64
    report.discovery=dict(webshell_scan=True,webshell_coverage=[dict(root=path,paths=[dict(path=path,reason='window',sha256='a'*64)])])
    output=io.StringIO()
    with contextlib.redirect_stdout(output):report.show(True)
    content=output.getvalue().encode('ascii')
    value=json.loads(content)
    resource=value['findings'][0]['resource']
    assert bytes.fromhex(resource['path_bytes_hex'])==path.encode('utf-8','surrogateescape')
    assert resource['path']=='/srv/invalid_\ufffd\ufffd.php'
    (root/'report.json').write_bytes(content)
    draft=p.webshell_baseline_draft(report)
    assert all(entry['reviewed'] is False for entry in draft['files']+draft['reviewed_files'])
    (root/'draft.json').write_bytes(json.dumps(draft,ensure_ascii=True).encode('ascii'))
    (root/'former.json').write_bytes(b'{"path":"\\udcff"}')
    for name in ('report','draft','former'):
        command=['cargo','run','--quiet','--locked','--manifest-path',str(project/'Cargo.toml'),'--',str(root/(name+'.json'))]
        if name=='former':command.append('--reject')
        subprocess.run(command,check=True,timeout=180)
    print('serde_json 1.0.154: report and unreviewed draft accepted; former lone surrogate rejected; exact path bytes preserved')
