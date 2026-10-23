"""Reproducible source archive; explicit allowlist excludes host reports/secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

base = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--output-directory', type=Path, default=base / 'dist')
args = parser.parse_args()
out = args.output_directory.resolve()
out.mkdir(parents=True, exist_ok=True)
version = re.search(r'^VERSION = "([0-9A-Za-z.+-]+)"$', (base / 'p2s_harden.py').read_text(encoding='utf-8'), re.M)[1]
names = [
    'p2s-harden.sh', 'p2s-harden.ps1', 'p2s_harden.py', 'p2s-launcher.sh.in', 'p2s-launcher.ps1.in',
    'build-standalone.py', 'test_p2s_harden.py', 'test_p2s_resilience.py', 'test_p2s_transactions.py',
    'test_p2s_language.py', 'test_p2s_http.py', 'test_p2s_cli.py', 'test_p2s_contracts.py', 'test-windows-launcher.ps1',
    'README.md', 'README.de.md', 'LICENSE', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md',
    '.gitattributes', '.gitignore', '.github/workflows/ci.yml', '.github/workflows/public-proof-badge.yml',
    'docs/VALIDATION.md', 'docs/DETAILS.de.md', 'docs/DETAILS.md', 'docs/FINDINGS.md', 'docs/CI.md',
    'docs/REVIEW-FOLLOWUP.md', 'docs/REVIEW-rc3.md', 'docs/FPM-RUNTIME.json',
    'tools/test-linux.sh', 'tools/package-release.py', 'tools/render-public-proof-badge.py', 'tools/test_public_proof.py',
    'tools/test_fpm_runtime.py', 'tools/test_fpm_runtime_protocol.py',
    'tools/test_system_runtime.py', 'tools/test_system_runtime_guard.py',
]
names += sorted(path.relative_to(base).as_posix() for path in (base / 'docs/assets/readme').glob('*.svg'))
names += sorted(path.relative_to(base).as_posix() for path in (base / 'src').glob('*.py'))
files = {name: (base / name).read_bytes() for name in sorted(names)}
files['SHA256.json'] = (json.dumps({name: hashlib.sha256(data).hexdigest() for name, data in files.items()}, indent=2) + '\n').encode()
archive = out / ('p2s-harden-v' + version + '.zip')
prefix = 'p2s-harden-v' + version + '/'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name, data in sorted(files.items()):
        info = zipfile.ZipInfo(prefix + name, date_time=(2026, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
        bundle.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
with zipfile.ZipFile(archive) as bundle:
    assert bundle.testzip() is None
for name in ('p2s-harden.sh', 'p2s-harden.ps1'):
    (out / name).write_bytes(files[name])
(base / 'SHA256.json').write_bytes(files['SHA256.json'])
checksums = ''.join(hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name + '\n'
                    for name in (archive.name, 'p2s-harden.sh', 'p2s-harden.ps1'))
(out / 'p2s-harden-SHA256SUMS.txt').write_bytes(checksums.encode())
print('Verified source archive:', archive.name)
