# PHP webshell indicator triage (2.3.0-dev.5 preview)

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

Exit policies: default UNKNOWN=2 before OPEN=1, otherwise 0. With
`--fail-on open`, a found OPEN takes precedence; unknown coverage stays visible.
`--fail-on review` returns 1 for any unaccepted WS004 review or OPEN before considering UNKNOWN; absent those, UNKNOWN still returns 2. Ordinary INFO never triggers it. Review rows accepted by an exact baseline or `--ignore` retain their status/evidence and lose exit impact. JSON adds `has_review` and `suppressed_review`; `suppressed_open` still counts only OPEN rows.
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
  six decoder names. Constant-prefixed request includes use WS007 instead. Selected request-controlled callback arguments are checked.
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
  An unknown-helper-derived request value in a constant-prefixed include, or selection
  from a registry array (including simple registry-result aliases), remains visible
  for manual review without a HIGH/OPEN verdict. Direct request expressions in
  includes without a prefix and a request-supplied callback/registry remain WS001; constant-prefixed direct/copy/cast/`basename()` flows remain OPEN under WS007. A helper of unknown semantics can only lower triage priority to visible review, never establish safety. Reassignments and function-local scopes are tracked conservatively within the documented small heuristic. This is triage
  priority, not proof of safety: a prefix does not stop traversal and a registry
  can be attacker-controlled. No framework/filename whitelist exempts the file.
- **P2S-WS007 (medium, OPEN):** `request-prefixed-include`, including direct request values, copies, casts and known transforms with a constant directory prefix. A prefix does not prevent traversal. The lower severity distinguishes the context without hiding it as INFO. This is a preview rule/indicator change; older indicator baselines need review again.
- **P2S-WS005 (INFO or UNKNOWN):** reviewed baseline loading. Invalid, unsafe or
  unreadable baselines yield UNKNOWN and the independent file scan continues.
- **P2S-WS006 (INFO):** scan scheduling. The engine lowers its own CPU priority to nice 10 using the standard OS API, preserving an already lower priority, and invokes optional trusted `ionice -c 3 -p PID` with a two-second timeout. Missing/denied capabilities are reported independently; no package is installed and the scan continues. `--no-nice` skips both adjustments, without raising inherited priorities. The SSH payload is not restarted, and the caller/parent process is unaffected. Scheduling is not a hard resource cap.

JSON remains ASCII-escaped UTF-8 and now contains only Unicode scalar strings, including legacy byte filenames. Affected `resource` and coverage path objects carry `path_encoding: "utf-8-replacement+bytes-hex"`, a readable `path` using U+FFFD, and exact `path_bytes_hex`. Use `bytes.fromhex(resource["path_bytes_hex"])` for the original Linux filename bytes, not the display spelling; normal UTF-8 paths need no extra fields. Root objects use `root_encoding`/`root_bytes_hex` in the same way. The report-level `path_encoding` documents this convention. IDs and hashing use original paths; display collisions do not merge findings or approvals. Baseline loading validates that hex bytes reproduce the display before applying canonical-path checks. Older local surrogateescape reports remain importable. Redaction removes byte metadata along with paths and hashes. Restricted terminal encodings use backslash replacement. [serde_json documents why lone surrogates fail ordinary Rust strings](https://docs.rs/serde_json/latest/serde_json/struct.Deserializer.html#method.deserialize_bytes); the test harness exercises the real parser.

Local JSON adds a `sha256` to each indicator row. The hash covers the bytes read
for that file and supports comparison; it is not checked against a reputation
service. Paths belong to `resource`; no source excerpt, request parameter name,
string payload or startup target is printed. Redaction omits file hashes and
paths/IDs, retaining only validated indicator enums, line numbers and counts.
Reads can update filesystem access times. Scanner/report code writes no scanned target files. An explicit `--write-baseline-draft FILE` creates one separate unreviewed JSON file; shell report redirection is also an operator action.

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

Defaults **per root**: 250000 entries, **120 seconds**, 2 MiB PHP materialization/parse budget per file,
**256 MiB** total bytes and 200 unaccepted indicator rows. Each file has an
independent **2-second** budget; an expensive file becomes `file-time` UNKNOWN
and later files continue. Baseline-accepted rows do not exhaust the active
finding budget. Files are fully streamed for PHP openers (including across read boundaries) before applying the parse-size cap. A stable file with no applicable opener and no selected startup configuration is fully examined even when larger than that cap. Every byte still consumes root byte/time and per-file time budgets. Oversized startup configuration or short-tag-only PHP remains `file-size` UNKNOWN. For oversized files with explicit PHP openers, bounded windows supply additional indicators while retaining incomplete coverage.

Binary-like means any NUL or ASCII control byte except tab/LF/CR appears anywhere in the file. These files require explicit `<?php` or `<?=` tags; text also accepts generic `<?` short tags except XML declarations. This content heuristic avoids random generic-tag bytes in assets without exempting any suffix. It deliberately misses generic short-tag PHP in binary-like content, including deliberately constructed polyglots with control bytes. Explicit tags can also occur randomly or in benign embedded examples; they still trigger analysis and limits, not a safety exemption. No PHP interpreter settings or runtime execution are inferred.
Explicit-opener windows inspect at most **64 KiB per opener**, at most **256 windows** and at most the configured per-file parse bytes in total; the default 2 MiB permits 32 windows. Small binary-like files use full selected analysis; if token/expression limits stop it, windows add leads. Window reads also consume the root byte/time budgets. Global line numbers and the full stable-file hash are retained and metadata is rechecked after rereads. Omitted aliases/control flow outside the windows can change interpretation: windowed files remain `window` incomplete, even if the visible blocks look benign. Windows do not certify the rest of the file.

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
This is an acknowledgement, not a malware-clean result. Generate an unreviewed
draft outside the audited webroot, on the Linux target:

```bash
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --write-baseline-draft /root/p2s-draft.json
```

The scan keeps its usual exit status; creating a draft cannot make findings pass.
The new file has mode **0600**. Existing files (including symlinks/FIFOs) are never
overwritten, symlink ancestors are refused, parents are not created, and failure
adds an UNKNOWN diagnostic without hiding the scan. The option cannot be combined
with `--redact` because drafts contain local paths and hashes. With `--ssh`, FILE
is a path on the target, not a local download. Rust is only a development-test
dependency; users need no new runtime or installation.

Drafts carry `requires_review: true`; keep this marker so missing review flags
cannot silently fall back to the legacy format. Every generated entry has
**`reviewed: false`**, including previously accepted
findings. Indicators are grouped per exact path/hash. Only stable, fully hashed
`file-size`/`tokens`/`expression`/`window` coverage gaps can be proposed; read/access,
race, symlink, timeout and unvisited-content failures are not draftable. Source
metadata reports omitted/unreviewable diagnostics; the draft is not a complete
file inventory or an integrity certificate. Reports themselves are not trust sources.

Compare **each complete file** against separately obtained trusted source and
review the indicator in context. Set `reviewed` to `true` only for entries you
approve; remove the others from the draft (they remain unaccepted in future scans).
A false/nonboolean review flag anywhere rejects the baseline; no entries from it
are applied and independent scan checks continue. Keep path/hex/hash/reason fields
unchanged. Store the reviewed file in a protected location:

```bash
sudo install -m 600 /root/p2s-draft.json /root/p2s-reviewed.json
sudo bash p2s-harden.sh --scan-webshells --root /srv/site --baseline /root/p2s-reviewed.json
```

An indicator entry looks like this before review:

```json
{"path":"/srv/site/file.php","sha256":"REPLACE_WITH_FULL_64_HEX_HASH","indicators":["registry-callable"],"reviewed":false}
```

Legacy schema-1 indicator lists without a review flag and explicitly reviewed
nonredacted schema-2 reports remain accepted for compatibility. Ordinary reports
never automatically accept coverage. Prefer drafts for a deliberate per-entry
review. Byte-valued paths include exact hex/encoding fields; do not substitute the
replacement-character display as a real filesystem path.

Only the identical **path + file bytes' SHA-256 + indicator name** match. A new
path, changed file or new indicator needs review again. Accepted rows remain in
JSON/`--verbose`, marked `baseline_accepted`; accepted OPEN rows are also visibly
suppressed. Default text hides accepted indicator rows and prints their count. An ordinary scan report never implicitly accepts coverage. After package/application updates, review changes
before replacing the baseline. The target reads this file locally; SSH does not
upload a client-side baseline.

The file and ancestors must be owned by root/the current scanner UID without
group/other write access and without symlinks. Root therefore does not accept an
ordinary user's writable home baseline directly. The loader accepts only a
regular, stable JSON file up to 2 MiB and 10000 path/indicator entries. Redacted
or unrelated reports, conflicts, invalid paths/hashes and unsafe files are refused;
other scan checks continue without baseline acceptance.

## Explicit reviewed coverage exceptions

A separate manual **schema 1** baseline may contain `reviewed_files`. Each entry requires a canonical absolute path, the **complete stable file SHA256**, `reviewed: true`, and explicit `coverage_reasons` drawn only from `file-size`, `tokens`, `expression`, or `window`. This records an operator acknowledgement after trusted full-file comparison; it never claims the scanner fully analyzed that content. The protected baseline ownership rules still apply.

```json
{"schema_version":1,"files":[],"reviewed_files":[{"path":"/srv/site/assets/font.ttf","sha256":"REPLACE_WITH_REVIEWED_64_HEX_HASH","reviewed":true,"coverage_reasons":["window"]}]}
```

Accepted gaps stay in `discovery.webshell_coverage.paths` with reason, hash and `baseline_accepted: true`. `examined_files` stays unchanged; `incomplete_files` includes them and `accepted_incomplete_files` counts the reviewed subset. The coverage row is INFO only if every remaining gap is explicitly accepted; `coverage_counts` still records the gaps. New indicators remain independent, even in a coverage-accepted file. A changed hash/path/reason loses acceptance. Access failures, symlinks, changed files, root/file timeouts, total-byte/entry/finding limits and unvisited files cannot be accepted. `--ignore P2S-WS003` still cannot turn UNKNOWN into a pass.

## WordPress integrity first

With a trusted WP-CLI installation, first run:

```bash
wp core verify-checksums --path=/srv/site --include-root
```

Use the intended released version/locale; investigate mismatches and do not bypass TLS validation or exclude unexplained files. If WP-CLI is unavailable, compare with a separately obtained trusted matching release. Plugins, themes and extra files need their own trusted-source checks. A core checksum pass does not prove application safety or absence of other persistence. Only then review indicator context and selected full-file coverage exceptions; do not promote a scan of an untrusted host straight into an approved baseline. [Official WP-CLI command and scope](https://developer.wordpress.org/cli/commands/core/verify-checksums/).

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
relative path** in [WEBSHELL-FULL-CORPUS.json](WEBSHELL-FULL-CORPUS.json). The dev.5 default run fully examines 5317 files with 3 windowed incomplete files (the large JS worker and two fonts); expanded budgets leave 2 incomplete fonts. Three review rows and one MEDIUM/OPEN include remain. There is no framework exemption. The fixture generates an unreviewed draft, proves that it accepts nothing, compares every proposed file against the pinned archive and deliberately approves the entries. A third recorded scan then exits 0 with 5317 examined / 3 incomplete / 3 reviewed exceptions. The raw accepted OPEN row remains in JSON. This is an acknowledgement demonstration on pinned benign test data, not a malware-clean result or evidence that WP-CLI was run on this development Git archive. Timing is a measurement
on the recorded run, not a performance guarantee. The regression suite also
includes 450000 line comments followed by an indicator and a 300-file indicator
tree that still reaches the active 200-finding cap.

[Actual SSH launcher evidence](WEBSHELL-SSH.json) records twenty cases using Bash and native Windows PowerShell against a protected disposable fixture: review exit 1, exact-baseline exit 0, redacted reports without paths/hashes, changed hashes requiring review again, raw-byte filename JSON roundtrips, draft creation, rejection before review, approval of exact byte paths, revocation after byte changes and refusal of redacted drafts. This is transport/baseline evidence, not production compromise recovery.

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
