# PHP webshell indicator triage (2.3.0-dev.2 preview)

`--scan-webshells` is a separate read-only mode. It supplies local leads for
investigation, not a malware verdict, an application vulnerability assessment
or a compromise-removal procedure. Published 2.2.1 does not include this feature.

## Run

Use the preview's generated Bash/PowerShell launcher. Automatic Nginx roots work
as in the configuration audit. Prefer explicit `--root /absolute/site` for a
specific application or a host without Nginx/FPM. No third-party package,
PHP interpreter, external scanner, network request or signature download is
required. The existing Linux/Python prerequisite applies. No HTTP probes or
FPM discovery run in this mode when a root is supplied.

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --lang de
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --json > local-indicators.json
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --redact --json > shareable-indicators.json
```

Exit policy is unchanged: default UNKNOWN=2 before OPEN=1, otherwise 0. With
`--fail-on open`, a found OPEN takes precedence; unknown coverage stays visible.
A zero exit means no unsuppressed selected indicators and no reported coverage
failure; review-only INFO can remain. It is never a clean-server certificate. `--ignore` retains the row and changes
its exit impact only. The mode cannot be combined with `--fix` or `--rollback`.

## Rules and evidence

- **P2S-WS001 (high, OPEN):** `request-execution`, `encoded-execution`,
  `request-include`, `request-callable`, `network-shell`. The lexer filters PHP comments and
  strings, recognizes PHP blocks/short tags, and uses bounded syntactic proximity
  plus simple local variable/constant aliases. It covers selected request
  superglobals, `filter_input` and literal `php://input` reads, the selected shell
  functions, `eval`, legacy string `assert`/`create_function`, include/require and
  six decoder names. Selected request-controlled callback arguments are checked.
  `network-shell` combines a socket connection and a literal shell launch within
  one file, or a shell command containing `/dev/tcp/`; it does not establish that
  the socket and shell are connected. A report does not prove reachability, malicious intent or
  exploitable data flow; sanitization, custom functions and PHP-version semantics
  require manual review. One row per indicator/file retains its first matching line.
- **P2S-WS002 (medium, OPEN):** nonempty `auto_prepend_file` or `auto_append_file`
  in files named `.user.ini`, `.htaccess` or `php.ini`. A legitimate bootstrap,
  monitoring agent or framework hook may explain this. Directive values are
  omitted and targets are not followed. Inspect the effective configuration
  and intended target separately, including targets outside the webroot.
- **P2S-WS003 (INFO or UNKNOWN):** examined-file and indicator counts, with finite
  coverage reason codes. A complete bounded pass is INFO, never a malware-free OK.
  Reason codes map to access failures, skipped symlinks/mounts/special files,
  changed files, depth/entry/time/byte/token/expression/finding limits. Access
  failures and per-file timeouts continue with independent entries; global budgets stop that root.
- **P2S-WS004 (INFO, review required):** `prefixed-include` and `registry-callable`.
  An indirectly request-derived value in a constant-prefixed include, or selection
  from a registry array (including simple registry-result aliases), remains visible
  for manual review without a HIGH/OPEN verdict. Direct request expressions in
  includes and a request-supplied callback/registry remain WS001. This is triage
  priority, not proof of safety: a prefix does not stop traversal and a registry
  can be attacker-controlled. No framework/filename whitelist exempts the file.
- **P2S-WS005 (INFO or UNKNOWN):** reviewed baseline loading. Invalid, unsafe or
  unreadable baselines yield UNKNOWN and the independent file scan continues.

Local JSON adds a `sha256` to each indicator row. The hash covers the bytes read
for that file and supports comparison; it is not checked against a reputation
service. Paths belong to `resource`; no source excerpt, request parameter name,
string payload or startup target is printed. Redaction omits file hashes and
paths/IDs, retaining only validated indicator enums, line numbers and counts.
Reads can update filesystem access times. Scanner/report code writes no target
files; a shell report redirection is an explicit operator action.

`examined_files` counts only stable, fully read files whose selected analysis
completed. `attempted_files` also includes incomplete regular files;
`incomplete_files` is their difference. Local JSON lists skipped/incomplete paths
and reason codes in `discovery.webshell_coverage`; text shows the first 20 and
`--verbose` shows the retained list. At most 1000 diagnostic path records per root
are retained; omitted-path and per-reason counters stay visible. Narrow the root
when the list is truncated. A global budget marks the current subtree; remaining
unvisited entries are not enumerated. Redacted output contains only validated
coverage counters/reasons, never that path list.

Startup files have separate syntax handling: INI semicolons start comments only
outside quotes; in `.htaccess` a semicolon is an ordinary argument byte. Apache
whole-line comments, continuation and argument escapes are handled separately;
invalid selected directives stay UNKNOWN. This is not a complete Apache/INI
configuration validator. [Apache syntax](https://httpd.apache.org/docs/2.4/configuring.html#syntax),
[PHP INI syntax](https://www.php.net/manual/en/configuration.file.php#configuration.file.syntax).

## Scope and budgets

Every regular file is considered regardless of suffix. Hidden files and
dependencies are not silently pruned. A local descriptor-based walk pins directory
handles, refuses symlinks at every root component and child, avoids device/FIFO
reads, checks filesystem boundaries, and checks opened identity and post-read
size/mtime/ctime. This limits traversal races; it does not provide a consistent
snapshot of a live tree or defeat an attacker who already controls the host/kernel.

Defaults **per root**: 250000 entries, **120 seconds**, 2 MiB per regular file,
**256 MiB** total bytes and 200 unaccepted indicator rows. Each file has an
independent **2-second** budget; an expensive file becomes `file-time` UNKNOWN
and later files continue. Baseline-accepted rows do not exhaust the active
finding budget. Files over the byte limit remain
unexamined and make coverage UNKNOWN even if their suffix looks harmless.
The traversal depth is 64; per-file lexical analysis is capped at 100000 tokens,
128 nested parentheses/brackets and 512 tokens per inspected expression.
Root and file time budgets are checked during traversal, chunk reads and analysis;
it cannot interrupt a blocked kernel/filesystem operation. Use local filesystems
or a local snapshot when storage can stall.

Raise `--scan-file-bytes` (1024–16777216), `--scan-total-bytes`
(1024–1073741824), `--max-paths` (1–1000000) or webshell `--walk-seconds`
(0.05–86400) when justified, or split the roots. `--walk-seconds 0` disables only
the webshell root clock, leaving all other limits active. `--scan-file-seconds`
can increase an individual file's allowance (0.05–30). Ordinary configuration
audits retain their 10-second default and 0.05–120 range; 0 is rejected there.
These are bounded reads, not archive extraction
or recursive decoder execution. Reports never silently certify skipped content.

This is not a full PHP parser/taint engine: cross-function/file flows, indirect
aliases, complex expressions, wrappers, escaped/interpolated constructs and
version-dependent behavior may be missed. There is no signature database,
reputation service, automatic trusted-source baseline, archive/PHAR parser,
recursive payload decoding, external scanner or OS persistence analysis.
Non-PHP backdoors, cron/SSH users/keys, native modules, OPcache-only/in-memory
payloads, remote startup targets, and files outside the selected roots need
separate investigation. Legitimate test fixtures and encoded commercial code
can produce indicators. Rewriting a sample can evade these rules.

## Reviewed baselines

An operator can explicitly accept selected, unchanged indicators with `--baseline`.
This is an acknowledgement, not a malware-clean result. First export a local
nonredacted webshell JSON report; keep it outside the audited webroot:

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --json > candidates.json
```

Inspect the actual source and compare with a trusted deployment before promoting
any entry. A report generated by a possibly compromised host is not a trust source
by itself. For root scans, install only reviewed entries in a protected location:

```bash
sudo install -m 600 candidates.json /root/p2s-reviewed.json
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --baseline /root/p2s-reviewed.json
```

Alternatively maintain a minimal allowlist, using lowercase SHA-256 and canonical
absolute Linux paths:

```json
{"schema_version":1,"files":[{"path":"/srv/site/file.php","sha256":"REPLACE_WITH_REVIEWED_64_HEX_HASH","indicators":["registry-callable"]}]}
```

Only the identical **path + file bytes' SHA-256 + indicator name** match. A new
path, changed file or new indicator needs review again. Accepted rows remain in
JSON/`--verbose`, marked `baseline_accepted`; accepted OPEN rows are also visibly
suppressed. Default text hides accepted rows and prints their count. UNKNOWN
coverage cannot be accepted. After package/application updates, review changes
before replacing the baseline. The target reads this file locally; SSH does not
upload a client-side baseline.

The file and ancestors must be owned by root/the current scanner UID without
group/other write access and without symlinks. Root therefore does not accept an
ordinary user's writable home baseline directly. The loader accepts only a
regular, stable JSON file up to 2 MiB and 10000 path/indicator entries. Redacted
or unrelated reports, conflicts, invalid paths/hashes and unsafe files are refused;
other scan checks continue without baseline acceptance.

## Validation and benign-source calibration

The standard-library-only, inert sample suite can be run from the full source
package on Linux without installing PHP or starting a service:

```bash
python3 -B -m unittest -v test_p2s_webshells
```

It covers selected patterns and benign strings/comments, aliases, filesystem
access/race/limit behavior, report privacy and actual Bash transport. These are
regressions for the documented rules, not an independently measured malware
detection rate. The normal suite also tests native PowerShell option forwarding.

A focused calibration uses **25 unchanged WordPress PHP files** (2666825 bytes)
at commit `c9675182926de3c788cd7c594705111a920403d3`, including authentication,
plugin/import dispatch, HTTP, database, formatting and KSES code. The exact
selection, SHA-256s, scanner hash, budgets and results are recorded in
[WEBSHELL-CORPUS.json](WEBSHELL-CORPUS.json). It produces **two expected review
indicators** in legitimate `wp-admin/admin.php` (plugin include and importer
callback), with no incomplete coverage under the recorded expanded budgets.
The guards and application context explain those uses; the scanner deliberately
does not treat a filename/framework name as an exemption. This small chosen
sample does not establish a general false-positive rate or certify WordPress.

The same pinned commit is also tested as a **complete 5320-file source archive**
(167112154 uncompressed bytes), including media and fonts. Default and expanded
runs record fully examined/incomplete counts and **every retained incomplete
relative path** in [WEBSHELL-FULL-CORPUS.json](WEBSHELL-FULL-CORPUS.json). Binary
assets can contain PHP-like short-tag byte sequences; large files and parser
limits remain UNKNOWN even in known benign source. The tool does not silently
skip those files or claim that the whole tree passed. Timing is a measurement
on the recorded run, not a performance guarantee. The regression suite also
includes 450000 line comments followed by an indicator and a 300-file indicator
tree that still reaches the active 200-finding cap.

## What to do with a finding

1. Preserve the file, its metadata and relevant logs using your incident-response
   process. Compare it with a known trusted application/deployment, not another
   copy from the same potentially compromised machine. Review the reported line
   and startup configuration without executing the suspect content.
2. If compromise is plausible, restrict access/isolate the host while preserving
   evidence and assess accounts, other sites, logs and persistence outside the
   document root. A deleted webshell or a newly hardened PHP setting does not
   establish that the intrusion is contained.
3. For confirmed compromise, close the exploited entry point, rebuild from trusted
   sources and rotate exposed credentials through trusted systems. Recheck the
   application and surrounding host. This CLI performs none of those actions
   automatically.

The design follows the distinction between indicators and confirmed compromise
in [NSA/ASD webshell detection guidance](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2159419/detect-prevent-cyber-attackers-from-exploiting-web-servers-via-web-shell-malware/).
The [PHP eval manual](https://www.php.net/manual/en/function.eval.php) describes
the execution sink; [PHP core INI documentation](https://www.php.net/manual/en/ini.core.php)
documents startup-file directives. These references do not endorse or validate
this tool's detection coverage.
