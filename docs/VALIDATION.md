# Validation

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
