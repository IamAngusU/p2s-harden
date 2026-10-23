# rc.3 review response

The rc.2 follow-up correctly identified automation, preview and distribution
integration gaps. This release prioritizes those contracts rather than expanding
automatic changes into untested application/security profiles.

## Implemented

- **1, traversal limits:** 250000 default entries, still bounded by time. A real
  36000-PHP-file regression also verifies a nested Git directory and `.env.local`
  under vendor. Dependencies are not silently removed from the claimed scope.
- **2, machine-readable findings:** schema 2 adds stable rule/resource IDs,
  severity, structured resource and remediation. `--ignore` keeps accepted OPEN
  findings visible and cannot make incomplete coverage pass.
- **3, exit precedence:** `--fail-on open` prioritizes OPEN over UNKNOWN. The
  default retains the existing incomplete-first contract; JSON exposes both
  flags, raw counts and suppressions under either policy.
- **5, HTTP coverage:** found `.env*`, SQL/SQL.GZ, BAK and log files plus named
  phpinfo/eval-stdin scripts join the bounded sensitive-endpoint set. This is
  explicit filename-based coverage, not an exhaustive secret/backup detector.
- **6, ImageMagick noise:** the manual notice appears only with a found policy
  or an enabled Imagick module in an inspected FPM configuration.
- **7, meaningful preview/approval:** directive values in a zero-context unified
  diff, `/dev/tty` confirmation with No as default, real `--yes` forwarding,
  JSON approval enforcement, preview digest checks and a precise undo command.
- **9–11, onboarding/trust:** complete engine option descriptions, examples,
  bilingual README examples/check coverage/audience, an English detailed manual,
  rule-level remediation, checksum commands, Unblock-File guidance and readable
  source/build links. Unblock-File does not override enforced/Restricted policy.
- **16, real supported-layout integration:** separate disposable Debian 12 and
  Ubuntu 24.04 VMs install distribution PHP-FPM/Nginx and boot actual systemd.
  The guarded harness exercises real discovery, automatic Nginx mapping, audit,
  preview, confirmed fix, directory protection, service reload and HTTP worker
  observations, then rollback and its idempotent repeat. It supplies no fixture
  FPM instance to scan and does not mock systemctl. PHP 8.2/8.3 also join the
  independent FastCGI settings matrix.
- **17, CI location:** runner access is unavailable in the source account, so
  the README explains the same-maintainer public fork and exact-commit proof.
- **18, maintainability/language:** English diagnostic sources, a separate German
  catalog and AST regression for error/finding literals and explicit IDs. Eight
  reviewable source components are assembled into the one-file distribution.

Exact run results belong to the [public commit-specific proof](https://github.com/angusu-de/p2s-harden/blob/ci-proof/proof/README.md)
and its retained runtime artifacts. A workflow definition alone is not a passed test.

## Deliberate boundaries

**4, redirects:** a redirect to the same path is not evidence that the target
denies access. The CLI keeps it UNKNOWN; automatic discovery prefers HTTPS,
and an explicit HTTPS mapping verifies the actual endpoint. Soft-404 results
also remain unverified, rather than being converted to a pass.

**8, new drop-in writes:** automatic changes retain the tested existing-file
transaction model. Creating/deleting a drop-in requires distinct ownership,
ordering, crash-recovery and rollback-conflict contracts, plus upgrade tests.
Deletion alone is not a substitute for those checks. This release does not claim
to have solved package-upgrade behavior or add unverified new-file mutation.

**12, redaction:** reports still need manual privacy review before sharing.
An automatic mode needs schema-wide tests for domains, paths, users, URLs and
nested diagnostics so it cannot misleadingly promise anonymous bug reports.

**13–15, broader checks/profiles/runtime attestation:** listener exposure, pool
isolation, additional function/extension profiles and existing-worker attestation
remain separate future work. Disk settings alone do not prove external network
reachability, and a master's start time alone does not establish the current
worker configuration. A stricter function list can break applications and must
not be presented as a universal fix. The existing fixed-sentinel FastCGI lab is
test infrastructure, not permission to install a probe into production webroots.

The tool remains a scoped audit/hardening assistant. The successful lab cases
and additional checks do not certify arbitrary production installations.
