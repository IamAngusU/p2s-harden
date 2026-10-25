#!/usr/bin/env python3
"""Reproduce three upload-guard outcomes in an isolated, disposable Docker lab.

Python 3.8+, Docker CLI and a Linux-container daemon are needed for this optional
lab only. No host paths are mounted, no ports published, no production URL used.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

LABEL = 'p2s.upload-guard-lab'
CLIENT = r'''$context=stream_context_create(["http"=>["ignore_errors"=>true,"timeout"=>2]]);
$body=@file_get_contents("http://127.0.0.1:18080".$argv[1],false,$context);
if($body===false){exit(2);} preg_match('/^HTTP\/\S+\s+(\d+)/',$http_response_header[0],$status);
echo json_encode(["status"=>(int)$status[1],"body"=>base64_encode($body)]);'''
FIXTURE = r'''mkdir("/fixtures/uploads",0755);
$code='<?php header("Content-Type: application/json"); echo json_encode(["marker"=>"P2S_INERT_MARKER","sapi"=>PHP_SAPI,"version"=>PHP_VERSION]);';
file_put_contents("/fixtures/uploads/y.php",$code);
file_put_contents("/fixtures/uploads/x\n.php",$code);
file_put_contents("/fixtures/uploads/image.svg",'<svg xmlns="http://www.w3.org/2000/svg"/>');'''
START = 'printf %s "$1" | base64 -d > /tmp/nginx.conf; exec nginx -c /tmp/nginx.conf -g "daemon off;"'


def docker(*args, timeout=45, required=True):
    result = subprocess.run(['docker', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if required and result.returncode:
        reason = result.stderr.strip() or result.stdout.strip() or 'exit ' + str(result.returncode)
        raise RuntimeError('docker ' + args[0] + ' failed: ' + reason[-1200:])
    return result


def inspect(kind, identity):
    result = docker(kind, 'inspect', identity, required=False)
    if result.returncode:
        if ('no such ' + kind) in result.stderr.lower():
            return None
        raise RuntimeError('Docker resource state could not be inspected: ' + identity)
    return json.loads(result.stdout)[0]


def configuration(guard):
    return ('pid /tmp/nginx.pid; error_log stderr; worker_processes 1; events {} http { '
            'access_log off; '
            'server { listen 127.0.0.1:18080; root /fixtures; ' + guard + r' location ~ \.php$ { '
            r'fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; '
            r'fastcgi_param REQUEST_METHOD $request_method; fastcgi_param SCRIPT_NAME $fastcgi_script_name; '
            'fastcgi_param REDIRECT_STATUS 200; fastcgi_pass 127.0.0.1:9000; } } }')


def verify_isolation(info, network, volume):
    settings = info['HostConfig']
    if (settings['NetworkMode'] != network or settings.get('PortBindings') or not settings['ReadonlyRootfs'] or
            any(mount['Type'] not in ('volume', 'tmpfs') or mount['Type'] == 'volume' and mount.get('Name') != volume
                for mount in info['Mounts'])):
        raise RuntimeError('The lab container isolation does not match the requested configuration.')


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='backslashreplace')
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--nginx-image', default='nginx:stable', help='Official Nginx image tag or digest')
    parser.add_argument('--php-image', default='php:8.3-fpm-bookworm', help='Official PHP-FPM image tag or digest')
    parser.add_argument('--json', action='store_true', help='Machine-readable observations and actual image identities')
    args = parser.parse_args(argv)
    result = dict(schema_version=1, scope='isolated Docker lab; no host mounts or published ports',
                  cases=[], cleanup_complete=False, exit_code=2)
    token, containers, volume = uuid.uuid4().hex, [], None
    label = LABEL + '=' + token
    prefix = 'p2s-upload-lab-' + token
    try:
        if not shutil.which('docker'):
            raise RuntimeError('Docker CLI is missing. Install/start Docker with Linux containers for this optional lab. Ordinary p2s audits do not need Docker.')
        for image in (args.nginx_image, args.php_image):
            if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}', image) is None:
                raise RuntimeError('Use a Docker image tag or digest, without options or whitespace.')
        if docker('info', '--format', '{{.OSType}}').stdout.strip() != 'linux':
            raise RuntimeError('This lab requires a running Linux-container Docker daemon.')
        sys.dont_write_bytecode = True
        engine = Path(__file__).resolve().parents[1] / 'p2s_harden.py'
        spec = importlib.util.spec_from_file_location('p2s_lab_engine', engine)
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        result['engine_sha256'] = hashlib.sha256(engine.read_bytes()).hexdigest()
        result['version'] = audit.VERSION
        volume = prefix + '-files'
        docker('volume', 'create', '--label', label, volume)
        volume_info = inspect('volume', volume)
        if not volume_info or (volume_info.get('Labels') or {}).get(LABEL) != token:
            raise RuntimeError('Fixture volume ownership could not be verified.')
        limits = ['--memory', '128m', '--cpus', '1', '--pids-limit', '64', '--read-only',
                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--security-opt', 'no-new-privileges',
                  '--cap-drop', 'ALL', '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'CHOWN']
        fpm = prefix + '-fpm'
        containers.append(fpm)
        docker('run', '-d', '--name', fpm, '--label', label, '--network', 'none', *limits,
               '--mount', 'type=volume,source=' + volume + ',target=/fixtures', args.php_image, timeout=180)
        docker('exec', fpm, 'php', '-r', FIXTURE)
        fpm_info = inspect('container', fpm)
        verify_isolation(fpm_info, 'none', volume)
        result['fpm_image'] = dict(requested=args.php_image, image_id=fpm_info['Image'],
                                  repo_digests=inspect('image', fpm_info['Image']).get('RepoDigests', []))
        weak = r'location ~* ^/uploads/.*\.php$ { deny all; }'
        nginx_image = args.nginx_image
        variants = [('no_guard', '', 'OPEN', (200, 200, 200)),
                    ('ordinary_dot', weak, 'OPEN', (403, 200, 200)),
                    ('dotall', weak.replace('^/', '(?s)^/'), 'OK', (403, 403, 200))]
        for index, (name, guard, verdict, statuses) in enumerate(variants):
            config = configuration(guard)
            tree = audit.parse_nginx(config)
            http = next(n for n in tree if n['name'] == 'http')
            server = next(n for n in http['children'] if n['name'] == 'server')
            status, outcome = audit.nginx_upload_route(http, server, '/uploads/')
            nginx = prefix + '-nginx-' + str(index)
            containers.append(nginx)
            docker('run', '-d', '--name', nginx, '--label', label, '--network', 'container:' + fpm, *limits,
                   '--tmpfs', '/var/cache/nginx:rw,noexec,nosuid,size=16m',
                   '--mount', 'type=volume,source=' + volume + ',target=/fixtures,readonly',
                   '--entrypoint', '/bin/sh', nginx_image, '-c', START, 'p2s-lab',
                   base64.b64encode(config.encode('ascii')).decode('ascii'), timeout=180)
            nginx_info = inspect('container', nginx)
            verify_isolation(nginx_info, 'container:' + fpm_info['Id'], volume)
            nginx_image = nginx_info['Image']  # All variants use the same actual image.
            result['nginx_image'] = dict(requested=args.nginx_image, image_id=nginx_image,
                                        repo_digests=inspect('image', nginx_image).get('RepoDigests', []))
            result['observed_nginx_version'] = docker('exec', nginx, 'nginx', '-v').stderr.strip()
            observations = []
            for uri, expected in zip(('/uploads/y.php', '/uploads/x%0a.php', '/uploads/image.svg'), statuses):
                deadline = time.monotonic() + 15
                while True:
                    response = docker('exec', fpm, 'php', '-r', CLIENT, uri, timeout=10, required=False)
                    if response.returncode == 0:
                        observation = json.loads(response.stdout)
                        if observation['status'] in (200, 403):
                            break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Lab HTTP endpoint did not become ready; inspect the Docker/image setup.')
                    time.sleep(0.2)
                body = base64.b64decode(observation['body'])
                executed = False
                if uri.endswith('.php') and observation['status'] == 200:
                    payload = json.loads(body)
                    executed = payload.get('marker') == 'P2S_INERT_MARKER' and payload.get('sapi') == 'fpm-fcgi'
                    result['observed_fpm_version'] = payload.get('version')
                if observation['status'] != expected or (uri.endswith('.php') and executed != (expected == 200)):
                    raise RuntimeError('Unexpected response in ' + name + ' for ' + uri)
                if uri.endswith('.svg') and body != b'<svg xmlns="http://www.w3.org/2000/svg"/>':
                    raise RuntimeError('Static image bytes changed in ' + name)
                observations.append(dict(uri=uri, http_status=observation['status'], php_executed=executed))
            if status != verdict or name == 'ordinary_dot' and outcome != 'regex_line_break_gap':
                raise RuntimeError('Static route assessment disagrees with expected lab behavior in ' + name)
            result['cases'].append(dict(name=name, tool_status=status, outcome=outcome, requests=observations, isolation_verified=True))
            docker('container', 'rm', '-f', '-v', nginx)
        result['exit_code'] = 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    finally:
        errors = []
        if containers or volume:
            for name in reversed(containers):
                try:
                    info = inspect('container', name)
                    if info is not None:
                        if (info.get('Config', {}).get('Labels') or {}).get(LABEL) != token:
                            raise RuntimeError('Container ownership mismatch')
                        docker('container', 'rm', '-f', '-v', name)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    errors.append(name)
            if volume:
                try:
                    info = inspect('volume', volume)
                    if info is not None:
                        if (info.get('Labels') or {}).get(LABEL) != token:
                            raise RuntimeError('Volume ownership mismatch')
                        docker('volume', 'rm', volume)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    errors.append(volume)
        result['cleanup_complete'] = not errors
        if errors:
            result['cleanup_incomplete_resources'] = errors
            result['exit_code'] = 2
    if args.json:
        print(json.dumps(result, ensure_ascii=True, indent=2))
    else:
        for case in result['cases']:
            codes = ', '.join(str(r['http_status']) for r in case['requests'])
            print(case['name'] + ': normal / newline / image = ' + codes + '; tool ' + case['tool_status'] + ' (' + case['outcome'] + ')')
        if result.get('error'):
            print('INCOMPLETE: ' + ''.join(c if c.isprintable() else '?' for c in result['error']))
        print('Cleanup complete: ' + str(result['cleanup_complete']))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
