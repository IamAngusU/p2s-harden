# Validation

## 2.2.2 maintenance release

The stable maintenance branch backports INI quote/section refusal, BOM/CRLF
preservation, complete effective-setting comparison before reload and
system-wide transaction serialization. It retains the 2.2 configuration scope;
the 2.3 webshell, residual-policy, systemd-posture and new upload-route features
are not promoted by this release.

All twelve jobs are required at the release commit: Python 3.8/3.12 fixtures,
Windows transport, 104 real FastCGI cases, 56 real INI parser cases, four distro
VM fix/reload/rollback workflows and signed build provenance. Exact run/commit
evidence is in the [2.2.2 release notes](https://github.com/IamAngusU/php-fpm-audit/releases/tag/v2.2.2)
and [maintenance proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof-2.2/proof/README.md).
Stable artifacts require `refs/heads/release/2.2`; historical 2.2.1 artifacts
retain their original main-ref policy.

## 2.2.1 release gate

Required: 179 tool tests plus 23 protocol/proof/guard tests per Linux Python
job; 26 actual FastCGI cases for each PHP 8.2–8.5; nine integration stages on
each Debian 12/13 and Ubuntu 22.04/24.04 VM, including unapproved JSON-fix
refusal; native PowerShell transport; then signed build provenance for the
exact four distribution files. All twelve jobs must pass at the released commit.
Downloaded release files must also pass expected GitHub attestation policies,
and altered bytes or incorrect signer/source policies must be rejected.

See the [current exact-commit proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md)
and [review response](REVIEW-2.2.1.md). Older runs below validate their named
versions only; they are not evidence for a newer release.

## Stable 2.2.0 release gate

The stable release adds FPM listener/socket/extension/environment checks,
loaded FFI context, private report projection and bounded include provenance.
The real runtime test caught a dump-parser bug: a trailing empty assignment was
lost after whitespace stripping, potentially hiding unrestricted script suffixes.
The parser now retains empty values; unit and FastCGI regressions cover it.

The required gate is 167 tool tests plus 23 protocol/proof/guard tests on each
Linux Python job, 26 real FPM cases for each of PHP 8.2â€“8.5, eight integration
stages on each supported distro VM, and the native PowerShell transport suite.
See the [current exact-commit proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md)
for measured results and retained runtime artifact identities. A workflow file
alone is not a passed run. [Production scope](PRODUCTION.md) defines the claim.

## 2.2.0-rc.3

Local Linux fixtures passed **153 tool regressions and 23 protocol/proof/guard tests**,
including a real 36000-PHP-file tree, explicit finding/suppression/exit policies,
preview digest/confidentiality checks, approval gates and canonical-English AST
checks. Windows PowerShell 5.1 transport/help/Unicode tests also passed.

The release workflow requires nine jobs: Python 3.8/3.12 fixture suites, Windows,
four PHP 8.2â€“8.5 FastCGI matrices and separate Debian 12/Ubuntu 24.04 systemd VMs.
The system VM harness uses installed distro PHP-FPM/Nginx and actual `/proc`,
service identities, HTTP requests, confirmed changes and rollback. The exact
executed commit/run, job outcomes and steps are in the [public proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md).
Retained runtime artifacts include engine hashes and observed package versions.
A workflow definition or an older green commit is not evidence for a new one.

[rc.3 review response and deferred scope](REVIEW-rc3.md) Â· [English manual](DETAILS.md).

## 2.2.0-rc.2

Executed locally on 2026-10-23: **143 tool regressions and 21 protocol/proof
tests passed** on the existing Linux host in protected disposable fixtures.
Native Windows PowerShell 5.1 passed language/help, Unicode JSON errors,
argument quoting, exact embedded payload and SSH exit/language transport checks.
The real FPM experiment passed 20 cases each on PHP 8.1.34, 8.4.27 and 8.5.12.

The final self-contained launcher also completed doctor, discovery, check and
JSON dry-run on the existing host. Hash/owner/group/mode/mtime snapshots of
monitored PHP/Nginx/Fail2ban/UFW configuration and protected web directories
were unchanged. Doctor returned 0; discovery/check/dry-run returned 2 for
explicit incomplete coverage. A real minimal PATH containing only Python
retained FPM discovery via `/proc` and HTTP checks without curl; unavailable
foreign-user checks were reported. No production fix was applied.

The current workflow runs fixture tests on Python 3.8/3.12, native Windows
PowerShell transport tests, and actual PHP 8.4/8.5 FPM requests. The public
[commit-specific proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md)
records executed jobs and steps; consult that result for the exact release
commit. [Real FPM cases and the review follow-up](REVIEW-FOLLOWUP.md).

Fix/recovery tests operate only on disposable files. Local HTTP tests cover
actual sockets, soft-404s, redirect behavior, incomplete bodies, byte budgets
and slow peers. JSON tests exercise real fixture fix/rollback and failed fix
recovery; they reject output mixed with transaction progress. Dedicated
transaction tests cover original timestamps, metadata conflicts, repeated
rollback and recovery after interruption.

The rc.1 record below is historical, including its then-current curl behavior
and unconditional manual ImageMagick unknown. rc.2 removes those limitations;
it continues to report actual incomplete checks as exit 2.

## Historical validation of 2.2.0-rc.1

Executed 2026-10-22. These are CLI correctness and compatibility checks, not a complete PHP-to-shell attack test.

- **Python 3.8.20 / Debian Bookworm container:** all 71 fixture/regression tests passed.
- **Python 3.10.12 / existing Ubuntu host:** all 71 tests passed in protected disposable fixtures.
- **Python 3.12 / Debian Bookworm container:** all 71 tests passed.
- **Windows PowerShell 5.1:** syntax parsing, native SSH argv transport with spaces, apostrophes, double quotes, backslashes and IPv6; exact UTF-8 engine payload; SSH exit propagation passed using a temporary fake SSH executable.
- **PowerShell 7 and MSYS Bash on Windows:** real OpenSSH `--doctor --json` to the Linux host completed successfully.
- **Existing Linux host:** self-contained file without sidecar engine completed doctor, discovery, default check and dry-run. SHA-256, owner, group, mode and modification-time snapshots of monitored PHP/Nginx/Fail2ban/UFW configuration and protected web directories stayed unchanged. Doctor exited 0; inventory/check/dry-run exited 2 for explicit incomplete coverage.
- **Real minimal PATH:** with only Python available, FPM discovery used `/proc`; missing curl/runuser were explained, independent host checks continued, and monitored configuration stayed unchanged. The fixture suite also tests absent Python, absent SSH, failed SSH, non-root access, unknown users, one broken FPM instance and blocked fixes.
- Generated Bash/PowerShell launchers match the tested engine; Bash syntax and source consistency checks passed.

Automatic fix and rollback failure handling were exercised on fixture files, including conflicts and metadata. No new production fix was applied during this release's read-only integration checks. The previously repaired web application and homepage returned HTTP 200 after the checks.

## Public CI evidence

Public CI uses [the maintainer's CI fork](https://github.com/angusu-de/p2s-harden/actions/workflows/ci.yml). Its generated [commit/run/job/step proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) records the actual result and the exact tested source commit. [How the proof is produced and synchronized](CI.md). Local test results above were executed on 2026-10-22; repository publication and CI integration were prepared on 2026-10-23.

## What remains before a stable release

Broader real-world feedback, additional Linux/FPM layouts and application compatibility testing remain necessary. Current automatic INI support stays limited to conventional Debian/Ubuntu host FPM configuration and matching systemd services.

No claim is made that every running worker uses the disk configuration, every vHost/container is covered, or every PHP-to-shell technique is blocked. Public test artifacts intentionally omit server domains, private paths, credentials and raw host reports.

## Reproduce

`sudo bash tools/test-linux.sh` copies the tested sources into protected temporary fixtures and removes that exact fixture directory afterwards. It requires Python 3.8+, Bash, curl, runuser, ps and the www-data account. It never changes real PHP/Nginx/firewall configuration. For Windows use `powershell -NoProfile -File test-windows-launcher.ps1`.

The CI Linux command runs the same test runner in temporary Python 3.8/3.12 containers and provisions its fixture prerequisites inside those containers only. No external Python packages are required.
