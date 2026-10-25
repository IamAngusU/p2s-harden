# Stable scope and release gates

php-fpm-audit 2.2.2 is a stable terminal product for the supported host workflow.
It is not a universal vulnerability scanner. A successful audit means its
selected checks passed for the reported resources. It cannot establish that
an application is free of vulnerabilities or that PHP-to-shell is impossible.

This is a maintenance backport, not promotion of the 2.3 development preview.
The 2.2.1 INI editing advisory is addressed by refusing ambiguous input and
checking unrelated effective INI values before service reload.

## Supported workflow

The complete discover â†’ audit â†’ preview â†’ confirmed fix â†’ service reload â†’
rollback workflow is tested in actual booted Debian 12 / PHP 8.2 and Ubuntu
24.04 / PHP 8.3 VMs with distro Nginx, protected `/etc/php/VERSION/fpm` INIs
and systemd. Separate PHP 8.2â€“8.5 containers exercise effective FPM settings
through FastCGI. These settings tests do not extend the host-layout support
claim to every distribution, container orchestration system or PHP build.

The client is one Bash or Windows PowerShell file. The Linux target needs
Python 3.8+ and readable `/proc`. Root is needed for complete cross-user checks
and changes. Existing SSH access is used; the CLI installs nothing. Missing
optional capabilities produce actionable UNKNOWN findings while independent
checks continue. No Python means the bootstrap explains the missing runtime;
the Python audit itself cannot execute.

## What the product can close automatically

Supported existing INIs receive the seven documented function restrictions and
`allow_url_include=Off`. Explicit directory targets can receive the documented
non-recursive owner/mode change. Every change needs a reviewed preview and
confirmation or `--yes`, a protected backup, conflict checks and verified service
mapping. A successful reload is followed by another configuration audit.

Application compatibility belongs to the operator: preview, test on a staging
copy with representative requests/jobs, apply during an appropriate change
window, and keep the printed exact rollback command. A new FPM configuration
can affect queues, image processing, mail or other application functionality.
No automatic profile guesses those application requirements.

Listener policy, socket permissions, environment inheritance, extension policy,
FFI, HTTP exposures and isolation findings include next steps but remain manual.
The CLI does not rewrite network bindings, firewall policy, pools or application
code, or recursively chmod a discovered tree.

## Evidence required for release

All twelve public CI jobs must pass at the source commit being released:

- Python 3.8 and 3.12: complete fixture tests, protocol/guard/proof tests, exact
  standalone build and Bash syntax. The suite includes a real 36000-file tree,
  local HTTP edge cases, transaction conflicts and interrupted recovery.
- PHP 8.2, 8.3, 8.4 and 8.5: 26 cases each, including actual harmless function
  calls, URL-include controls, `.txt` execution allowed/denied by extension policy,
  parent environment clearing and comparison with parsed real TCP pool dumps.
  Each image also runs 14 real INI editor/parser cases, preserving unrelated
  effective values and refusing multiline or conditional input.
  The network fixture publishes no port and has no external network.
- Debian 12/13 and Ubuntu 22.04/24.04: nine integration stages each, with actual `/proc`
  and Nginx discovery, PHP-user permissions, new pool checks, private reports,
  preview, refusal of unapproved JSON fixes, fix/reload/worker observation and rollback/idempotence. These tests
  run only in explicitly marked disposable VMs.
- Native Windows PowerShell 5.1: help/language, quoting, exact engine transport,
  option forwarding, JSON failure privacy and SSH exit handling.

- Dependent provenance job: reproduce the exact distribution bytes only after
  all eleven test jobs pass, require matching source/fork heads, then sign the
  four files with GitHub build attestations. [Verification](PROVENANCE.md).

The [commit-specific public proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md)
must match source `release/2.2`, CI-fork `release/2.2` and the release tag. Downloaded release
assets must match SHA-256 sums, the reproducible source manifest and expected signed build provenance. The public
CI belongs to the same maintainer; it is reproducible evidence, not independent
security certification.

## Boundaries that remain visible

Configuration is inspected on disk. Existing production workers are not actively
probed or attested. The JSON `discovery.assessment` states that boundary. The VM
integration's worker probes validate the tool's test fixtures, not a user's host.
A master's start time alone is not proof of worker configuration after reload.

TCP findings assess the bind/allowlist configuration. Exact localhost names
also require loopback-only current host resolution with a two-second deadline;
the name alone is never enough for a pass. They do not inspect the
firewall, remote Internet access, container port publication or all named ACL
grant intentions. Loopback does not exclude hostile local processes. Shared
UIDs are context: separate pools can intentionally serve one application.

Filename-based HTTP probes do not find every secret. Redirects, soft-404s,
unreadable paths, namespace differences, unsupported mappings and reached
budgets remain unverified. `--ignore` can accept an OPEN finding, but cannot
make UNKNOWN coverage pass. The tool does not scan application dependencies,
business logic, authentication, SQL injection, every web-server routing rule,
kernel vulnerabilities, extension CVEs or arbitrary PHP bypass techniques.

Further breadth should arrive through separately tested adapters and checks,
not a claim that a generic hardening profile secures every application. New-file
drop-ins, production-worker probes and additional server layouts need their own
ordering, recovery, compatibility and evidence contracts before automatic use.

Primary configuration semantics:
[PHP-FPM](https://www.php.net/manual/en/install.fpm.configuration.php),
[FFI](https://www.php.net/manual/en/ffi.configuration.php).
