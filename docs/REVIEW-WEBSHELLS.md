# Review response: 2.3.0-dev.4

This addresses the adversarial review of `347ad4a` / dev.3. It is an unreleased
development preview; published 2.2.1 files do not contain these corrections.
Both READMEs flag its known multiline-INI editing limitation before the download
and fix instructions. Read-only checks are unaffected. The previous
[dev.3 decisions](https://github.com/IamAngusU/php-fpm-audit/blob/347ad4a258ac7eb41a226d7b394d495166a8e038/docs/REVIEW-WEBSHELLS.md)
remain historical context, not the current contract.

## 1. Byte filenames and strict JSON

Report JSON now uses ASCII escapes and UTF-8 transport. Surrogate-escaped Linux
filename bytes cannot escape as raw 0xff/0xfe. `path_encoding` identifies the
filesystem-surrogateescape representation; Python `os.fsencode()` reconstructs
the exact original bytes. IDs and baseline matching still use the original
path. Regression tests create actual invalid-UTF-8 filenames, decode the report
strictly and verify the byte roundtrip and file hash. Node JSON.parse and jq
also accept the escaped wire representation.

Human stdout/stderr use backslash replacement under restricted encodings and
the banner uses an ASCII hyphen. Real CLI help/doctor runs cover ASCII with
UTF-8 mode/coercion disabled; terminal control-character sanitization remains.
[Ten actual SSH cases](WEBSHELL-SSH.json) cover both Bash and native PowerShell,
including legacy byte filenames, baseline matching, changed hashes and redaction.

## 2. INI edits and effective configuration

The reported multiline value could leave a trailing quoted line and stop PHP
from loading subsequent settings. The editor now refuses multiline/unclosed
quotes anywhere in the target file before a line-based rewrite. It preserves
a leading BOM and CRLF and appends only one PHP section for missing targets.
It does not attempt to repair general INI syntax automatically.

Before the first replacement, affected FPM instances provide effective registered
INI tables; after writing, every unrelated directive is compared before reload.
Incomplete/ambiguous tables refuse the fix. Values are hashed in memory, never
printed or stored in the transaction/report. A mismatch restores original files
before the altered configuration is reloaded. Digests, metadata checks and
interrupted rollback remain in place.

The runtime harness adds **14 real editor/parser cases per PHP image**: plain,
CRLF, BOM, duplicates, quoted values, inline comments, quoted semicolons, escaped
quotes, absent keys, no final newline, ordinary sections, conditional sections,
multiline targets and multiline unrelated values. A **379M memory_limit** sentinel
and all unrelated effective registered directives must survive. Refused inputs
must remain byte-identical. Four FPM versions exercise these alongside the
existing 104 FastCGI observations; no production config is mounted or changed.

## 3. Useful WordPress triage without blanket exclusions

Constant-prefixed request includes now have **P2S-WS007 MEDIUM/OPEN**. Direct
input, copies, casts and basename still cannot hide the finding as INFO. A prefix
does not prevent traversal; unrestricted request includes remain HIGH. This is
a preview rule/indicator change, so an older baseline needs contextual review.

Oversized files with explicit PHP openers receive bounded window analysis;
binary files that hit token/expression bounds get additional window leads. Each
window is at most 64 KiB; parser bytes, opener count, root bytes and clocks remain
bounded. Full-file hashing, global line numbers and post-reread metadata checks
remain. Windows can miss aliases/control flow elsewhere and therefore retain
`window` incomplete coverage. Large startup/short-tag-only files retain size
gaps. No PHP payload is executed, unpacked, uploaded or deleted.

An explicit protected schema-1 `reviewed_files` entry may acknowledge a stable,
fully hashed file after trusted full-file comparison. It must name the canonical
path, complete SHA256, `reviewed: true` and selected parse/window reasons. An
ordinary scan report never automatically approves coverage. Read/access/race,
symlink, timeout, global-budget and unvisited-content failures cannot be accepted.
New indicators remain independent; changed bytes/path/reason invalidate approval.
Accepted incomplete files remain in the diagnostics and incomplete counters,
with separate `accepted_incomplete_files`; they never become fully examined.

The [WordPress recipe](WEBSHELLS.md#wordpress-integrity-first) starts with trusted
`wp core verify-checksums`, followed by separate trusted-source checks for themes,
plugins and extra files as needed. No checksum tool is installed or run by p2s.
This is integrity evidence, not a clean-server guarantee.

The [pinned 5320-file archive](WEBSHELL-FULL-CORPUS.json) has 5317 fully examined
files and 3 window gaps under defaults; expanded limits have 5318 / 2. One
MEDIUM include and three review indicators remain. A third disposable fixture
run compares the exact known files against the pinned archive and explicitly
accepts four indicators and three gaps. It exits 0 with **5317 examined, 3
incomplete, 3 reviewed exceptions**, retaining the accepted OPEN row in JSON.
It does not claim all 5320 files were analyzed, nor that WP-CLI verified this
development Git archive. No WordPress filename/framework whitelist is built in.

## 4. System-wide transaction coordination

All current fix/rollback writers now acquire the fixed protected mode-0700
`/run/p2s-harden` directory lock before the backup-root lock. Changing
`--backup-root` cannot bypass it. The legacy root lock remains for compatibility.
Ownership, mode, no-symlink and inode checks protect both directories; there is
no configurable global path or stale PID file. The kernel releases locks after
exit/termination. Actual separate-process tests cover prepare/apply/rollback
contention and a different backup root with no target changes. Unrelated editors
and older versions do not participate in the new system lock. Read-only modes
do not acquire it, and backup retention remains an explicit operator decision.

## Validation and release boundary

**251 tool tests and 23 auxiliary tests** cover the new failure modes and previous
contracts. Native PowerShell verifies exact UTF-8 source payload/option forwarding;
the actual SSH cases additionally verify byte-filename reports. The public CI
matrix covers Python 3.8/3.12, Windows, PHP-FPM 8.2–8.5 (104 FastCGI + 56 INI
parser cases), and four real Debian/Ubuntu systemd VMs with fix/reload/worker and
rollback observations. The PR/main run links identify the exact tested commits;
runtime artifacts carry the engine hash. Main additionally has signed build
provenance and commit-specific public proof. The fork belongs to the same
maintainer and is not an independent audit. No production compromise recovery,
universal detection or evasive-malware detection rate is claimed.
