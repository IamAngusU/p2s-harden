#!/usr/bin/env bash
# Tests mutate disposable fixtures only, never target configuration.
set -euo pipefail
base=$(cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(id -u)" != 0 ]; then
  printf '%s\n' 'Fixture-Tests brauchen root fuer Owner/ACL/Rollback. Ausfuehren: sudo bash tools/test-linux.sh' >&2
  exit 2
fi
missing=()
for program in python3 bash runuser ps; do
  command -v "$program" >/dev/null 2>&1 || missing+=("$program")
done
if ! id www-data >/dev/null 2>&1; then missing+=('Benutzer www-data'); fi
if [ "${#missing[@]}" != 0 ]; then
  printf 'Test-Voraussetzung fehlt: %s\n' "${missing[@]}" >&2
  printf '%s\n' 'Das Audit kann unabhaengig mit --doctor und Teilpruefungen verwendet werden.' >&2
  exit 2
fi
scratch=$(mktemp -d /root/p2s-fixtures.XXXXXXXX)
cleanup() {
  # mktemp used this literal parent/prefix; verify before recursive removal.
  case "$scratch" in /root/p2s-fixtures.????????) rm -rf -- "$scratch" ;; *) return 2 ;; esac
}
trap cleanup EXIT
cp -- "$base"/p2s_harden.py "$base"/p2s-harden.sh "$base"/p2s-harden.ps1 \
  "$base"/p2s-launcher.sh.in "$base"/p2s-launcher.ps1.in "$base"/build-standalone.py \
  "$base"/test_p2s*.py "$scratch/"
mkdir -p "$scratch/tools" "$scratch/docs/assets/readme" "$scratch/src"
cp -- "$base"/src/*.py "$scratch/src/"
cp -- "$base"/tools/test_fpm_runtime.py "$base"/tools/test_fpm_runtime_protocol.py \
  "$base"/tools/render-public-proof-badge.py "$base"/tools/test_public_proof.py \
  "$base"/tools/test_system_runtime.py "$base"/tools/test_system_runtime_guard.py "$scratch/tools/"
cp -- "$base"/tools/reproduce-nginx-upload-guard.py "$base"/tools/test_upload_guard_lab.py "$scratch/tools/"
cp -- "$base"/docs/assets/readme/public-proof-template.svg "$scratch/docs/assets/readme/"
cd -- "$scratch"
python3 -B build-standalone.py --check
bash -n p2s-harden.sh
python3 -B -m unittest discover -v -s . -p 'test_p2s*.py'
python3 -B -m unittest discover -v -s tools -p 'test_*.py'
