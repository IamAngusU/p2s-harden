# Webshell preview review response: 2.3.0-dev.2

This is a preview update, not a stable release announcement. Published 2.2.1
assets and main are separate. The following changes address the supplied review;
the [scanner guide](WEBSHELLS.md) specifies the remaining detection boundaries.

## Comment-heavy file and continuation

The repeated suffix search for a closing PHP tag in each line comment was
quadratic. A single scan to the next newline/closing tag now consumes each
comment once. Whitespace is consumed in runs and repeated same-indicator line
counting is avoided. Each file also has its own two-second deadline, checked
during reads, lexical work and analysis. A file timeout produces a path-specific
`file-time` coverage gap and later entries continue. Root-wide work/byte/finding
budgets remain independent; no finite scanner promises that unlimited attacker
input cannot exhaust an explicitly selected root budget.

[Before/after stress evidence](WEBSHELL-REVIEW-STRESS.json) uses the prior
`5fc0ca52de55f6a42bd5752fb1b3641ac9f03fb7` engine and the updated engine on the
same inert 1800024-byte input: 450000 line comments followed by an indicator.
The old engine hits its two-second deadline before reaching the indicator; the
updated engine reaches line 450002 within that budget. A regression also places
a comment-heavy file alongside 300 inert indicator files and reaches the
intentional 200-active-finding cap. Timing varies by machine.

## Incomplete paths and honest counters

Local text and JSON include incomplete/skipped paths with finite reason codes.
Default text displays 20, verbose/JSON retains up to 1000 diagnostics per root,
with explicit omitted counts if more exist. Global limits identify the current
subtree, not a fictitious exhaustive inventory of unvisited files. Redaction
removes the complete path list and retains validated counts/reasons only.
Fully examined files exclude partial analysis. Attempted and incomplete regular
file counts are separate; symlinks/special entries have their own issue counters.

## Larger trees

The webshell root default is now 120 seconds and 256 MiB read; its file allowance
defaults to two seconds. Root time can be raised to 86400 seconds or explicitly
disabled with `--walk-seconds 0`; file time and other bounds remain. Configuration
audits retain their previous limits. The complete pinned WordPress archive has
5320 regular files and 167112154 uncompressed bytes. Both default and expanded
runs, including exact incomplete relative paths, are in
[WEBSHELL-FULL-CORPUS.json](WEBSHELL-FULL-CORPUS.json). Large files and PHP-like
byte sequences in binary assets still leave explicit UNKNOWN coverage; this is
not presented as a full clean pass.

## Review context and explicit baselines

Indirect constant-prefixed includes and registry callbacks, including simple
aliases of registry results, now have an INFO review rule. Direct request
includes and request-supplied callback/registry values retain HIGH/OPEN. These
are priorities for human investigation, not proof that a prefix/registry makes
code safe. There is no WordPress-path or framework exemption.

`--baseline` accepts a reviewed nonredacted scan report or a schema 1 file list.
Only the same canonical absolute path, SHA-256 and indicator can match. Accepted
rows remain in JSON/verbose, with explicit baseline acceptance; changed files,
new paths/indicators and UNKNOWN coverage do not disappear. The loader enforces
protected ownership/modes, no symlinks, regular files, stable metadata, finite
JSON/entry limits and valid fields. Invalid baselines yield UNKNOWN and scanning
continues. A baseline copied from an unreviewed compromised host is not trusted
source evidence; promotion is an explicit operator decision.

## Startup syntax and JSON fixes

Apache and INI startup references now use separate comment/quote handling. In
`.htaccess`, semicolons are value bytes, comments are whole logical # lines,
and continuation/argument escapes are handled. Invalid selected directives
remain UNKNOWN. INI semicolons inside quotes are preserved.

The INI-upgrade notice is already inside the human-only branch. The Linux CLI
fixture suite parses actual fix/rollback stdout as single JSON documents. The
real systemd VM harness additionally asserts that neither the English nor
German notice occurs in stdout, and records that assertion on the actual
`--fix --json --yes` integration stage. These are disposable marked VMs; the
developer harness must never be run on an existing production server.

## Validation and release boundary

The public PR links exact-commit CI results and runtime artifact verification.
The matrix covers Python 3.8/3.12, native PowerShell, four PHP-FPM versions and
four real Debian/Ubuntu systemd VMs. Selected-pattern regressions, negative
examples and the recorded benign source are not a general detection-rate
measurement. The new mode remains a preview; no production-server recovery,
arbitrary evasive malware or complete OS persistence coverage is claimed.
