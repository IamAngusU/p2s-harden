# Webshell preview review response: 2.3.0-dev.3

This update addresses the follow-up review of `037c500` / dev.2. It remains a
development preview. Stable 2.2.1 downloads and main are separate. The earlier
[dev.2 response](https://github.com/IamAngusU/p2s-harden/blob/037c5005cf5271adea60cc34d2bd84f2dc40ccf0/docs/REVIEW-WEBSHELLS.md)
records the previous comment-lexer, coverage-path, file-timer and baseline work.
The [scanner guide](WEBSHELLS.md) is the current behavioral contract.

## 1. Include aliases no longer reduce priority

Plain request copies, copy chains, casts, interpolated copies and selected known
transforms such as `basename()`/`trim()` retain `request-include` HIGH/OPEN even
with a constant directory prefix. The scanner tracks their provenance through
reassignment and function-local scope. Values passing through helpers of unknown
semantics may remain `prefixed-include` review; registry callbacks remain visible
review items. These are triage priorities, not proof that any value is safe.

This correction makes a legitimate `wp-admin/update.php` include OPEN again. Its
application guards require contextual review; suppressing all copies simply to
make WordPress return zero would restore the reported defect. A reviewed exact
baseline can accept unchanged indicators, but cannot accept coverage gaps.

## 2. Stream opener searches before the parser cap

Each stable regular file is fully streamed for applicable PHP openers, with
cross-chunk/short-read handling. A large file without an opener or selected
startup configuration no longer hits the PHP parse-size cap. Every read still
consumes global bytes and per-file/root time; large PHP/startup files remain
explicitly incomplete. Full-file SHA256 and identity/metadata checks remain.

Files containing NUL/selected ASCII control bytes require explicit `<?php` or
`<?=` openers; other text also accepts generic short tags except XML declarations.
This avoids random generic short tags in binary assets without filename or
framework exemptions. Generic short-tag PHP embedded in binary-like data is a
documented detection limitation. Explicit tags can still occur in benign data.

The [complete pinned WordPress archive](WEBSHELL-FULL-CORPUS.json) has 5320 files
and 167112154 bytes. The default run now fully examines **5317**, leaving **3**
incomplete (previously 38): one large JS file with PHP-like text and two fonts
with explicit PHP-like tags hitting lexical bounds. Expanded budgets leave the
two fonts incomplete. There are **3 review rows and 1 OPEN include**. The exact
relative paths and reasons remain recorded; neither run is called a clean pass.
The [25-file calibration](WEBSHELL-CORPUS.json) has two review indicators, complete
coverage and no OPEN. These are benign-source measurements, not detection rates.

## 3. Low-priority scanning without restarting SSH

The scanner lowers its own CPU priority to nice 10 using the OS API, preserving
an already lower priority. Optional trusted `ionice -c 3 -p PID` requests idle
I/O under a two-second helper timeout. Missing, unsafe or denied helpers leave
an INFO scheduling result and the file scan continues. Nothing is installed.
`--no-nice` skips both changes without raising inherited priorities.

The Python payload is never re-executed, so stdin/SSH transport stays intact.
Actual subprocess tests verify inherited child niceness and an unaffected parent;
negative tests cover absent/denied helpers and opt-out. Scheduling priorities are
not hard resource caps and are not applied by ordinary configuration audits.

## 4. Optional blocking review policy

`--fail-on review` returns 1 for unaccepted WS004 review items or OPEN, before
considering UNKNOWN. Without those, UNKNOWN returns 2; ordinary INFO never fails.
The default UNKNOWN-first and existing OPEN-first policies retain their behavior.
Exact baselines and explicit finding/rule ignores can accept review exit impact;
rows remain visible in JSON with unchanged status/evidence. `has_review` and
`suppressed_review` are additive schema-2 fields; `suppressed_open` counts only
suppressed OPEN. Coverage cannot become a pass through an ignore or baseline.

## 5. Concurrent transaction writers

Fix preparation/apply/reload/recovery and rollback selection/restore acquire a
nonblocking kernel `flock` on the protected backup-directory inode. The CLI holds
it across prepare and apply. There is no replaceable lock file or stale PID to
remove; process exit releases the lock. Contention becomes actionable UNKNOWN
before target changes. Ownership, mode, no-symlink and inode checks protect the
lock target. Read-only checks never acquire it.

Actual separate-process regressions attempt prepare, apply and rollback while
another writer holds the lock, assert no changes, and verify recovery after the
holder exits/is terminated. Use one backup root for overlapping targets: distinct
custom roots and unrelated package tools/editors do not coordinate. Existing
digest and metadata conflict checks remain necessary.

## 6. Retention and supported scope

Both READMEs now put Debian/Ubuntu host PHP-FPM with Nginx/systemd beside the
initial introduction. Configuration fixes for RHEL, Apache/mod_php and hosting
panels are outside the tested workflow. Explicit-root static scans have broader
Linux applicability. The transaction documentation explains that backups are not
automatically pruned; operators retain needed recovery data and monitor storage.

## Validation and release boundary

The fixture suite has **236 tool tests and 23 auxiliary tests**, including the
new alias, streaming, priority, review-policy and real concurrency cases. Native
PowerShell 5.1 verifies the exact payload and new option forwarding.
[Eight actual SSH cases](WEBSHELL-SSH.json) exercise both Bash and PowerShell:
review exit 1, protected exact-baseline exit 0, redaction privacy, and changed
hashes requiring review again. Tests use owned disposable fixtures only.

The PR links exact-commit public CI and verified runtime artifacts: Python
3.8/3.12, native Windows, PHP-FPM 8.2–8.5 and four Debian/Ubuntu systemd VMs.
The VM harness asserts pure JSON during actual `--fix --json --yes` and validates
reload, workers and rollback. Never run that destructive developer harness on
an existing server. The CI account belongs to the same maintainer; this is not
an independent audit. Branch CI is not stable-release attestation verification.
No production compromise recovery or evasive-malware detection rate is claimed.
