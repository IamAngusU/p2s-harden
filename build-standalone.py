from pathlib import Path
import hashlib
import base64
import argparse

base = Path(__file__).parent
engine = (base / 'p2s_harden.py').read_text(encoding='utf-8')
template = (base / 'p2s-launcher.sh.in').read_text(encoding='utf-8')
assert '__P2S_ENGINE_EOF__' not in engine
content = template + engine + '\n__P2S_ENGINE_EOF__\n'
bootstrap = template.split('bootstrap() {', 1)[1].split('\n}\nif [ "$target" = local ]; then', 1)[0]
ps_template = (base / 'p2s-launcher.ps1.in').read_text(encoding='utf-8')
ps_content = ps_template.replace('__BOOTSTRAP__', 'bootstrap() {' + bootstrap + '\n}').replace(
    '__ENGINE_BASE64__', base64.b64encode(engine.encode('utf-8')).decode('ascii'))
parser = argparse.ArgumentParser(description='Build or verify the exact self-contained launchers.')
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
for name, expected in (('p2s-harden.sh', content), ('p2s-harden.ps1', ps_content)):
    if args.check:
        if (base / name).read_text(encoding='utf-8') != expected:
            raise SystemExit(name + ' is stale; run python3 build-standalone.py')
    else:
        with (base / name).open('w', encoding='utf-8', newline='\n') as output:
            output.write(expected)
print('Standalone launchers verified' if args.check else 'Standalone launchers built',
      '; engine SHA256:', hashlib.sha256(engine.encode()).hexdigest())
