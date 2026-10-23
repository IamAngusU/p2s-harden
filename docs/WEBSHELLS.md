# PHP webshell indicator triage (2.3.0 development preview)

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
failure, never a clean-server certificate. `--ignore` retains the row and changes
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
  failures continue with independent entries; global budgets stop that root.

Local JSON adds a `sha256` to each indicator row. The hash covers the bytes read
for that file and supports comparison; it is not checked against a reputation
service. Paths belong to `resource`; no source excerpt, request parameter name,
string payload or startup target is printed. Redaction omits file hashes and
paths/IDs, retaining only validated indicator enums, line numbers and counts.
Reads can update filesystem access times. Scanner/report code writes no target
files; a shell report redirection is an explicit operator action.

## Scope and budgets

Every regular file is considered regardless of suffix. Hidden files and
dependencies are not silently pruned. A local descriptor-based walk pins directory
handles, refuses symlinks at every root component and child, avoids device/FIFO
reads, checks filesystem boundaries, and checks opened identity and post-read
size/mtime/ctime. This limits traversal races; it does not provide a consistent
snapshot of a live tree or defeat an attacker who already controls the host/kernel.

Defaults **per root**: 250000 entries, 10 seconds, 2 MiB per regular file,
128 MiB total bytes and 200 indicator rows. Files over the file limit remain
unexamined and make coverage UNKNOWN even if their suffix looks harmless.
The traversal depth is 64; per-file lexical analysis is capped at 100000 tokens,
128 nested parentheses/brackets and 512 tokens per inspected expression.
The monotonic time budget is checked during traversal, chunk reads and analysis;
it cannot interrupt a blocked kernel/filesystem operation. Use local filesystems
or a local snapshot when storage can stall.

Raise `--scan-file-bytes` (1024–16777216), `--scan-total-bytes`
(1024–1073741824), `--max-paths` (1–1000000) or `--walk-seconds` (0.05–120)
when justified, or split the roots. These are bounded reads, not archive extraction
or recursive decoder execution. Reports never silently certify skipped content.

This is not a full PHP parser/taint engine: cross-function/file flows, indirect
aliases, complex expressions, wrappers, escaped/interpolated constructs and
version-dependent behavior may be missed. There is no signature database,
reputation service, baseline of a trusted deployment, archive/PHAR parser,
recursive payload decoding, external scanner or OS persistence analysis.
Non-PHP backdoors, cron/SSH users/keys, native modules, OPcache-only/in-memory
payloads, remote startup targets, and files outside the selected roots need
separate investigation. Legitimate test fixtures and encoded commercial code
can produce indicators. Rewriting a sample can evade these rules.

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
