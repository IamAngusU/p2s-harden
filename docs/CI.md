# Public CI and commit evidence

The source repository is [IamAngusU/php-fpm-audit](https://github.com/IamAngusU/php-fpm-audit).
GitHub-hosted runner access is currently unavailable in the source account. Public checks therefore run in its fork [angusu-de/p2s-harden](https://github.com/angusu-de/p2s-harden), a separate account belonging to the same maintainer. This follows the maintainer's ByeClaude/ContextBridge setup. It is not an independent audit.

The source repository was renamed from `IamAngusU/p2s-harden`. The CI fork and
provenance signer keep their existing `angusu-de/p2s-harden` identity. Launcher
and release filenames also keep `p2s-harden` for compatibility. Source-head
checks use the new repository name; this rename does not change the expected
signer or make earlier CI evidence apply to a newer commit.

## What is checked

- Linux/Python 3.8: the complete fixture/regression suite (including local HTTP, JSON, language and rollback tests), exact embedded engine, Bash syntax, plus CI-proof and FastCGI-protocol tests.
- Linux/Python 3.12: the same checks in a separate disposable Debian container.
- Real PHP 8.2, 8.3, 8.4 and 8.5 FPM containers: actual FastCGI requests, function operations, pool configuration, URL-include controls, script-extension enforcement, parent environment inheritance, TCP policy dumps and comparison with the audit engine. Image identities and observed PHP versions are recorded in runtime evidence artifacts.
- Four real booted VMs with distro Nginx/systemd: Debian 12/PHP 8.2, Debian 13/PHP 8.4, Ubuntu 22.04/distro PHP 8.1 and Ubuntu 24.04/PHP 8.3. The guarded system harness exercises actual discovery, automatic mapping, check, private report projection, preview, unapproved-JSON-fix refusal, confirmed fix, permission changes, service reload and HTTP worker observations, then rollback and repeated rollback. No fixture instance or mocked systemctl is used.
- Windows: generated-file consistency and native PowerShell/SSH transport with a temporary fake SSH executable, including quoting and exit codes.

- Each real FPM job additionally runs 14 INI editor/parser cases: BOM, CRLF, duplicates, comments, quoting, missing keys, section handling and multiline refusal. All unrelated effective registered directives and the 379M memory sentinel must remain unchanged.

- A dependent provenance job signs the four exact distribution files only after all eleven test jobs pass and source/fork heads match. [Signer identity and verification](PROVENANCE.md).

Actual jobs and steps are recorded in the [public proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) and [JSON](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/public-proof.json). Each snapshot names its exact source commit, run and attempt. The badge counts measured job results; missing expected jobs remain visible and do not pass.

The proof workflow publishes only when the tested commit, source `main` and CI-fork `main` match. A newer commit requires a new matching run. This is reproducibility evidence from the maintainer, not a third-party audit or a guarantee about a user's server.

All twelve expected jobs must pass for a full proof, including all four system VMs and provenance.
VM actions, checkout/setup and artifact actions are pinned to commit SHAs.
Runtime JSON artifacts retain the tested engine hash, actual package/PHP
versions and observations. Ordinary fixture tests do not invoke the destructive
system harness. The VM harness requires an explicit environment flag and an
exact protected marker created only inside these disposable CI VMs. Never
create that marker on an existing server.

## Updating the fork

The fork is synchronized for releases; it does not automatically track every source push. Maintainers with access to the CI account can synchronize it with:

```bash
gh repo sync angusu-de/p2s-harden --source IamAngusU/php-fpm-audit --branch main
```

Then inspect the new run, or trigger `CLI tests` manually in the fork. Compare the source/fork commit IDs and wait for all expected jobs and proof publication before relying on the badge for a release. A later source change does not inherit a previous successful result.

The separate `ci-proof` branch contains generated evidence only and is excluded from ordinary push CI. The proof workflow is enabled only in the named CI fork and uses its own scoped workflow token. No cross-account personal token is stored in this repository.

The native Windows job also runs `python -B tools/test_json_interop.py`: real pinned Rust `serde_json::Value` must accept generated report/draft JSON and reject the former lone-surrogate fixture. Cargo and its locked dependencies are development-only; the distributed CLI does not invoke Rust or install anything.

The dev.6 matrix retains 104 FastCGI and 56 real INI cases, adding residual-function existence observations in actual FPM (including dl absence and a pool that disables putenv/mail). Each of the four disposable systemd VMs adds real manager-property comparison plus upload PHP execution, static 403 rejection and a nested unsupported route that must stay UNKNOWN: 13 stages per VM, 52 overall. No production upload probes or service changes are part of ordinary p2s checks.
