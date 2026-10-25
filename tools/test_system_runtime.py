#!/usr/bin/env python3
"""Real distro discovery -> preview -> confirmed fix -> rollback.

DESTRUCTIVE TEST FOR DISPOSABLE VMS ONLY. Requires Linux root, systemd,
distribution php-fpm/nginx packages and the exact explicit CI marker below.
Never run this against a production server. No discovery/service mocks are used.
The normal p2s-harden command does not invoke this developer test.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


MARKER=Path('/etc/p2s-disposable-ci')
MARKER_TEXT='p2s-harden disposable system test\n'


def run(argv):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=120)
    if result.returncode:
        raise RuntimeError('{} failed (exit {})'.format(argv[0],result.returncode))
    return result.stdout


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--expect-php',required=True,choices=('8.1','8.2','8.3','8.4'))
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args(argv)
    evidence=dict(schema_version=1,scope='disposable distro VM; actual /proc, nginx, FPM and systemd',
                  cases=[],exit_code=2)
    try:
        if sys.platform!='linux' or os.geteuid()!=0 or os.environ.get('P2S_DISPOSABLE_SYSTEM_TEST')!='1':
            raise RuntimeError('Requires an explicitly authorized disposable Linux root VM')
        if not MARKER.is_file() or MARKER.is_symlink() or MARKER.read_text()!=MARKER_TEXT or MARKER.stat().st_uid!=0 or MARKER.stat().st_mode & 0o022:
            raise RuntimeError('Missing exact root-owned disposable-VM marker; refusing all changes')
        if not Path('/run/systemd/system').is_dir():
            raise RuntimeError('A real booted systemd VM is required; service mocks are not accepted')
        base=Path(__file__).resolve().parents[1]
        engine_path=base/'p2s_harden.py'
        spec=importlib.util.spec_from_file_location('system_test_engine',engine_path)
        engine=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        evidence['audit_engine_sha256']=hashlib.sha256(engine_path.read_bytes()).hexdigest()
        evidence['os_release']=Path('/etc/os-release').read_text()
        evidence['packages']=run(['dpkg-query','-W','-f=${Package} ${Version}\n','php'+args.expect_php+'-fpm','nginx'])
        version=args.expect_php
        service='php'+version+'-fpm.service'
        ini=Path('/etc/php')/version/'fpm/php.ini'
        if not ini.is_file(): raise RuntimeError('Expected distro FPM layout is absent')
        root=Path('/srv/p2s-system-fixture')
        root.mkdir(mode=0o755)
        (root/'probe.php').write_text('<?php header("Content-Type: application/json"); echo json_encode(["sapi"=>PHP_SAPI,"version"=>PHP_VERSION,"system"=>function_exists("system"),"include"=>ini_get("allow_url_include")]);')
        (root/'.env').write_text('P2S_DISPOSABLE_FIXTURE_ONLY=1\n')
        os.chown(root,33,33)
        os.chmod(root,0o755)
        ini.write_text(engine.set_ini(ini.read_text(),dict(disable_functions='exec',allow_url_include='On')))
        nginx=Path('/etc/nginx/sites-enabled/p2s-system-test')
        nginx_text=('server { listen 127.0.0.1:18080; server_name p2s-ci.test; root '+str(root)+'; '
                         'location ~ /\\.(env|git) { deny all; } '
                         'location ~ \\.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php'+version+'-fpm.sock; } }\n')
        nginx.write_text(nginx_text)
        run(['systemctl','restart',service])
        run(['nginx','-t'])
        run(['systemctl','restart','nginx'])
        baseline=ini.read_bytes()
        before=ini.stat()
        evidence['baseline_sha256']=hashlib.sha256(baseline).hexdigest()
        def observed():
            last=None
            for _ in range(60):
                connection=http.client.HTTPConnection('127.0.0.1',18080,timeout=2)
                try:
                    connection.request('GET','/probe.php',headers={'Host':'p2s-ci.test'})
                    response=connection.getresponse()
                    data=json.loads(response.read(16384))
                    if response.status==200 and data.get('sapi')=='fpm-fcgi': return data
                except (OSError,ValueError,http.client.HTTPException) as exc: last=type(exc).__name__
                finally: connection.close()
                time.sleep(0.1)
            raise RuntimeError('Actual nginx/FPM request unavailable: '+str(last))
        initial=observed()
        assert initial['system'] is True and initial['include'].lower() in ('1','on'),initial
        evidence['php_version']=initial['version']
        assert initial['version'].startswith(version+'.')
        instances,issues=engine.discover()
        matching=[i for i in instances if i.get('service')==service]
        assert len(matching)==1,(len(matching),issues)
        assert str(ini) in matching[0]['inis'] and matching[0]['pools']
        evidence['cases'].append(dict(name='real-proc-distro-service-discovery',status='PASS'))
        def cli(*options):
            result=subprocess.run(['/bin/bash',str(base/'p2s-harden.sh'),'--root',str(root),
                '--backup-root','/root/p2s-system-test-backups','--protect-dir',str(root),'--json',*options],
                capture_output=True,text=True,timeout=120)
            report=json.loads(result.stdout)
            assert engine.INI_UPGRADE_NOTICE not in result.stdout
            assert engine.localize(engine.INI_UPGRADE_NOTICE,'de') not in result.stdout
            assert result.returncode==report['exit_code'] and result.returncode in (0,1,2)
            return report
        discovered=cli('--discover')
        assert any('p2s-ci.test:18080' in s for s in discovered['discovery']['selected_sites'])
        evidence['cases'].append(dict(name='real-nginx-automatic-mapping',status='PASS'))
        checked=cli('--check')
        assert any(row['rule_id']=='P2S-PHP001' and row['status']=='OPEN' for row in checked['findings'])
        assert any(row['rule_id']=='P2S-FS002' and row['status']=='OPEN' for row in checked['findings'])
        pool_rows=[row for row in checked['findings'] if row['rule_id'] in ('P2S-FPM002','P2S-FPM003','P2S-FPM004')]
        assert {row['rule_id'] for row in pool_rows}=={'P2S-FPM002','P2S-FPM003','P2S-FPM004'}
        assert all(row['status'] in ('OK','INFO') for row in pool_rows),pool_rows
        assert ini.read_bytes()==baseline
        evidence['cases'].append(dict(name='actual-audit-settings-and-php-user-permissions',status='PASS'))
        shared=cli('--check','--redact')
        assert shared['redacted'] and shared['exit_code']==checked['exit_code']
        assert shared['counts']==checked['counts']
        assert all(row['resource'] is None for row in shared['findings'])
        assert str(root) not in json.dumps(shared) and 'p2s-ci.test' not in json.dumps(shared)
        assert ini.read_bytes()==baseline
        evidence['cases'].append(dict(name='shareable-report-preserves-results-without-host-details',status='PASS'))
        posture=next(row for row in checked['findings'] if row['rule_id']=='P2S-SYS002' and row['resource']['service']==service)
        expected=dict(line.split('=',1) for line in run(['systemctl','show','--property=NoNewPrivileges,ProtectSystem,PrivateTmp','--',service]).splitlines())
        assert posture['status']=='INFO' and posture['evidence']['assessment']=='manager_policy',posture
        assert [posture['evidence'][key] for key in ('no_new_privileges','protect_system','private_tmp')]==[expected[key] for key in ('NoNewPrivileges','ProtectSystem','PrivateTmp')]
        assert posture['evidence']['worker_attestation'] is False
        evidence['cases'].append(dict(name='actual-systemd-manager-policy-observation',status='PASS',properties=expected,worker_attestation=False))
        uploads=root/'uploads';uploads.mkdir(mode=0o755)
        (uploads/'p2s-upload.php').write_text('<?php echo "P2S_UPLOAD_FIXTURE";')
        (uploads/'p2s-line\nbreak.php').write_text('<?php echo "P2S_UPLOAD_FIXTURE";')
        (uploads/'image.svg').write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
        def upload_response(expected_status=200, path='/uploads/p2s-upload.php'):
            for _ in range(60):
                connection=http.client.HTTPConnection('127.0.0.1',18080,timeout=2)
                try:
                    connection.request('GET',path,headers={'Host':'p2s-ci.test'})
                    response=connection.getresponse()
                    result=response.status,response.read(65536)
                    if result[0]==expected_status:return result
                except (OSError,http.client.HTTPException):pass
                finally:connection.close()
                time.sleep(0.1)
            raise RuntimeError('Upload fixture did not reach expected HTTP status '+str(expected_status))
        def upload_row():
            original_nginx=nginx.read_bytes()
            result=cli('--check','--runtime-dir',str(uploads))
            assert nginx.read_bytes()==original_nginx and ini.read_bytes()==baseline and root.stat().st_uid==33
            return next(row for row in result['findings'] if row['rule_id']=='P2S-NGX001' and isinstance(row['resource'],dict) and row['resource'].get('path')==str(uploads))
        assert upload_row()['status']=='OPEN'
        assert upload_response()==(200,b'P2S_UPLOAD_FIXTURE')
        assert nginx.read_text()==nginx_text and ini.read_bytes()==baseline
        evidence['cases'].append(dict(name='actual-upload-php-route-open',status='PASS',http_status=200,php_executed=True,audit_status='OPEN',configuration_unchanged=True))
        def route_variant(extra):
            head,tail=nginx_text.rsplit('}',1)
            nginx.write_text(head+extra+' }'+tail)
            run(['nginx','-t']);run(['systemctl','reload','nginx'])
        route_variant('location ^~ /uploads/ { return 403; }')
        assert upload_row()['status']=='OK'
        status,body=upload_response(403)
        assert status==403 and b'P2S_UPLOAD_FIXTURE' not in body
        evidence['cases'].append(dict(name='actual-upload-static-guard-blocks',status='PASS',http_status=403,php_executed=False,audit_status='OK',configuration_unchanged=True))
        route_variant('location /uploads/ { location ~ \\.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php'+version+'-fpm.sock; } }')
        assert upload_row()['status']=='UNKNOWN'
        assert upload_response()==(200,b'P2S_UPLOAD_FIXTURE')
        evidence['cases'].append(dict(name='actual-upload-nested-route-never-false-green',status='PASS',http_status=200,php_executed=True,audit_status='UNKNOWN',configuration_unchanged=True))
        # Review is an explicit UNKNOWN acknowledgement, never an OK verdict.
        draft=Path('/root/p2s-nginx-review.json')
        drafted=cli('--check','--runtime-dir',str(uploads),'--write-nginx-review-draft',str(draft))
        review=json.loads(draft.read_text());assert review['entries'] and all(entry['reviewed'] is False for entry in review['entries'])
        assert draft.stat().st_mode & 0o777 == 0o600
        rejected=cli('--check','--runtime-dir',str(uploads),'--nginx-baseline',str(draft))
        assert any(row['rule_id']=='P2S-NGX002' and row['status']=='UNKNOWN' for row in rejected['findings'])
        for entry in review['entries']:entry.update(reviewed=True,reason='Disposable fixture: independently inspected route and live response; execution is intentionally allowed here.')
        draft.write_text(json.dumps(review))
        accepted=cli('--check','--runtime-dir',str(uploads),'--nginx-baseline',str(draft))
        assert accepted['accepted_unknown']==1 and any(row.get('review_accepted') and row['status']=='UNKNOWN' for row in accepted['findings'])
        nginx.write_text(nginx.read_text()+'\n# configuration identity changed\n')
        expired=cli('--check','--runtime-dir',str(uploads),'--nginx-baseline',str(draft))
        assert expired['accepted_unknown']==0
        evidence['cases'].append(dict(name='actual-nginx-reviewed-unknown-expires-on-change',status='PASS',unreviewed_rejected=True,unknown_retained=True,changed_configuration_rejected=True))
        generic='location ~ \\.php$'
        def ordered_variant(guard):
            assert generic in nginx_text
            nginx.write_text(nginx_text.replace(generic,guard+' '+generic,1))
            run(['nginx','-t']);run(['systemctl','reload','nginx'])
        weak='location ~* ^/uploads/.*\\.php$ { deny all; }'
        ordered_variant(weak)
        assert upload_row()['status']=='OPEN' and upload_row()['evidence']['outcome']=='regex_line_break_gap'
        assert upload_response(403)[0]==403
        assert upload_response(200,'/uploads/p2s-line%0abreak.php')==(200,b'P2S_UPLOAD_FIXTURE')
        evidence['cases'].append(dict(name='actual-upload-regex-line-break-bypass',status='PASS',http_status=200,php_executed=True,audit_status='OPEN',configuration_unchanged=True))
        robust=weak.replace('^/','(?s)^/')
        ordered_variant(robust)
        assert upload_row()['status']=='OK'
        assert upload_response(403)[0]==403 and upload_response(403,'/uploads/p2s-line%0abreak.php')[0]==403
        assert upload_response(200,'/uploads/image.svg')==(200,b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        evidence['cases'].append(dict(name='actual-upload-ordered-regex-guard-preserves-images',status='PASS',http_status=403,php_executed=False,audit_status='OK',image_http_status=200,line_break_http_status=403,configuration_unchanged=True))
        route_variant('location ^~ /uploads/ { location ~* \\.php$ { deny all; } }')
        assert upload_row()['status']=='OK'
        assert upload_response(403)[0]==403 and upload_response(403,'/uploads/p2s-line%0abreak.php')[0]==403
        assert upload_response(200,'/uploads/image.svg')[0]==200
        evidence['cases'].append(dict(name='actual-upload-nested-denial-preserves-images',status='PASS',http_status=403,php_executed=False,audit_status='OK',image_http_status=200,line_break_http_status=403,configuration_unchanged=True))
        route_variant(robust)
        assert upload_row()['status']=='OPEN' and upload_response()==(200,b'P2S_UPLOAD_FIXTURE')
        evidence['cases'].append(dict(name='actual-upload-late-regex-denial-loses-to-handler',status='PASS',http_status=200,php_executed=True,audit_status='OPEN',configuration_unchanged=True))
        nginx.write_text(nginx_text);run(['nginx','-t']);run(['systemctl','reload','nginx'])
        preview=cli('--dry-run')
        assert preview['plan']['ini'] and not preview['plan']['blockers']
        assert any('+disable_functions' in e['diff'] for e in preview['plan']['ini'])
        assert ini.read_bytes()==baseline and root.stat().st_uid==33
        evidence['cases'].append(dict(name='preview-diff-without-mutation',status='PASS'))
        unapproved=cli('--fix')
        assert unapproved['exit_code']==2 and unapproved['transaction'] is None
        assert any('--fix --json requires --yes' in row['detail'] for row in unapproved['findings'])
        assert ini.read_bytes()==baseline and root.stat().st_uid==33
        assert observed()['system'] is True
        evidence['cases'].append(dict(name='unapproved-json-fix-refused-without-mutation',status='PASS'))
        fixed=cli('--fix','--yes')
        assert fixed['transaction']['status']=='applied',fixed
        assert ini.stat().st_mtime_ns!=before.st_mtime_ns
        assert root.stat().st_uid==0
        assert all(row['status']=='OK' for row in fixed['findings'] if row['rule_id'] in ('P2S-PHP001','P2S-PHP002','P2S-FS001','P2S-FS002'))
        after=observed()
        assert after['system'] is False and after['include'].lower() in ('','0','off'),after
        evidence['cases'].append(dict(name='actual-fix-systemd-reload-and-worker-values',status='PASS',
            json_stdout_validated=True,ini_upgrade_notice_in_stdout=False))
        restored=cli('--rollback','--backup-id',fixed['transaction']['id'])
        assert restored['transaction']['status']=='rolled_back'
        assert ini.read_bytes()==baseline and ini.stat().st_mtime_ns==before.st_mtime_ns
        assert root.stat().st_uid==33
        final=observed()
        assert final['system'] is True and final['include'].lower() in ('1','on'),final
        evidence['cases'].append(dict(name='actual-rollback-metadata-service-and-worker-values',status='PASS'))
        repeated=cli('--rollback')
        assert repeated['transaction']['noop'] is True and ini.read_bytes()==baseline
        evidence['cases'].append(dict(name='repeated-rollback-noop',status='PASS'))
        evidence['exit_code']=0
    except (OSError,ValueError,RuntimeError,AssertionError,KeyError,subprocess.SubprocessError) as exc:
        evidence['error']=str(exc) or type(exc).__name__
    if args.json: print(json.dumps(evidence,indent=2))
    else:
        for case in evidence['cases']: print(case['status']+' '+case['name'])
        if evidence.get('error'): print('UNKNOWN '+evidence['error'])
    return evidence['exit_code']


if __name__=='__main__': sys.exit(main())
