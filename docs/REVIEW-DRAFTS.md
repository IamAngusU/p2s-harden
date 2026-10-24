# Follow-up: interoperable paths and deliberate baseline drafts

This is **2.3.0-dev.5 development preview**, following the independent review of
`c8518bf` / dev.4. The [six previous fixes and their evidence](https://github.com/IamAngusU/p2s-harden/blob/c8518bf1bbea0cc29249aa729f64fddfb06219f4/docs/REVIEW-WEBSHELLS.md)
remain historical context. Published 2.2.1 assets are unchanged and their release
notes warn about the known old INI editor limitation.

## 1. Unicode parser interoperability

ASCII escaping prevented raw invalid UTF-8 bytes but did not make lone surrogate
escapes interoperable with ordinary Rust strings. Output now replaces these
display characters with U+FFFD and adds exact `path_bytes_hex` plus
`path_encoding: "utf-8-replacement+bytes-hex"` on affected path objects. Root
objects use corresponding root fields. The whole document contains Unicode
scalar strings; the original filesystem paths still determine IDs, hashes and
acceptance. Paths with the same display spelling retain separate byte identities.
Redaction discards all original path/hex/hash metadata.

Baseline import decodes the hex and verifies agreement with the display spelling
before canonical path validation. Invalid/mismatched encoding, odd/truncated hex,
NUL, relative and noncanonical paths cannot authorize different files. Older
surrogateescape reports remain readable locally by Python for compatibility.

`python -B tools/test_json_interop.py` exercises real pinned `serde_json::Value`:
new report and draft fixtures must parse, while the former lone-surrogate fixture
must fail. Cargo's lock file is committed. This is a development-only dependency
and also runs in native Windows CI; users still need only the existing runtime.
Linux fixtures and actual Bash/PowerShell SSH scans verify byte filenames and
baseline matching, including mutation after approval.

## 2. A draft without automatic acceptance

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site \
  --write-baseline-draft /root/p2s-draft.json
```

The explicit option creates one new mode-0600 JSON file, never overwrites an
existing file, refuses symlink ancestors and leaves scanned files unchanged.
With SSH it writes on the target. It is incompatible with `--redact` because
the file intentionally contains local paths/hashes. JSON stdout remains a single
report; a write failure adds UNKNOWN without hiding independent scan results.

Indicator entries are grouped by exact path/hash and every generated entry starts
with `reviewed: false`, including previously accepted rows. A `requires_review: true`
marker also makes missing per-entry review flags invalid. Any explicit false or
nonboolean review flag rejects the whole baseline; no partial approvals escape.
Only a deliberate edit to `true` after complete-file trusted-source comparison
can approve an entry. Remove entries you cannot approve; future scans still
report them. Legacy indicator baselines without the new flag remain compatible.

Only stable, completely hashed parse/window gaps can be proposed. Timeouts,
access/race failures and unvisited content cannot become coverage exceptions.
The draft records omitted/unreviewable diagnostic counts and does not claim an
inventory of all skipped content. Changes to bytes/path/indicator/reason still
invalidate acceptance; accepted incomplete files remain visibly incomplete.

[The baseline recipe](WEBSHELLS.md#reviewed-baselines) requires separate trusted
source comparison, starting WordPress checks with `wp core verify-checksums`.
The pinned WordPress fixture additionally exercises draft creation, rejection
before review, full-file comparison against the pinned archive, deliberate
approval and a final exit 0 with three incomplete files still visible.

## 3. Large generated PHP and release scope

Streaming tokenization is deferred. The existing per-file/root budgets and bounded
windows remain; payloads outside selected windows may be missed. Such content
retains UNKNOWN until a separately verified full-file exception is approved.
There is no new whitelist, execution of suspect PHP or claim of universal malware
detection. A report from a potentially compromised host is not a trusted baseline.

Validation includes **262 tool tests + 23 auxiliary tests**, the native Windows
launcher and actual Rust parser, **20 actual SSH cases**, the pinned full WordPress
archive, and the existing CI matrix: Python 3.8/3.12, 104 FastCGI observations,
56 real INI parser cases, and four booted Debian/Ubuntu systemd VMs. Exact PR/main
run links identify tested commits; runtime artifacts identify the engine hash.
Main additionally requires signed provenance and matching public source/fork heads.
These are maintainer-run checks. Three independent external server trials and a
measured detection rate on real/evasive malware are **not** claimed. This remains
a development preview rather than an automatic stable/RC promotion.
