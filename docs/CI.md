# Public CI and commit evidence

The source repository is [IamAngusU/p2s-harden](https://github.com/IamAngusU/p2s-harden).
Public GitHub-hosted checks run in its fork [angusu-de/p2s-harden](https://github.com/angusu-de/p2s-harden), a separate account belonging to the same maintainer. This follows the maintainer's ByeClaude/ContextBridge setup.

## What is checked

- Linux/Python 3.8: the complete fixture/regression suite (including local HTTP, JSON, language and rollback tests), exact embedded engine, Bash syntax, plus CI-proof and FastCGI-protocol tests.
- Linux/Python 3.12: the same checks in a separate disposable Debian container.
- Real PHP 8.4 and 8.5 FPM containers: actual FastCGI requests, function operations, pool configuration, URL-include controls and comparison with the audit engine. Image identities and observed PHP versions are recorded in runtime evidence artifacts.
- Windows: generated-file consistency and native PowerShell/SSH transport with a temporary fake SSH executable, including quoting and exit codes.

Actual jobs and steps are recorded in the [public proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md) and [JSON](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/public-proof.json). Each snapshot names its exact source commit, run and attempt. The badge counts measured job results; missing expected jobs remain visible and do not pass.

The proof workflow publishes only when the tested commit, source `main` and CI-fork `main` match. A newer commit requires a new matching run. This is reproducibility evidence from the maintainer, not a third-party audit or a guarantee about a user's server.

## Updating the fork

The fork is synchronized for releases; it does not automatically track every source push. Maintainers with access to the CI account can synchronize it with:

```bash
gh repo sync angusu-de/p2s-harden --source IamAngusU/p2s-harden --branch main
```

Then inspect the new run, or trigger `CLI tests` manually in the fork. Compare the source/fork commit IDs and wait for all expected jobs and proof publication before relying on the badge for a release. A later source change does not inherit a previous successful result.

The separate `ci-proof` branch contains generated evidence only and is excluded from ordinary push CI. The proof workflow is enabled only in the named CI fork and uses its own scoped workflow token. No cross-account personal token is stored in this repository.
