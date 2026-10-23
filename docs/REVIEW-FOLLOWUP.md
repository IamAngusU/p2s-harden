# Review follow-up: real PHP-FPM pool behavior

The review identified a useful gap: mocked discovery and configuration dumps do
not establish what a PHP-FPM worker can actually do. We added a separate Docker
integration harness and tested real FastCGI requests on **PHP 8.1.34, 8.4.27 and
8.5.12**, with **20 cases per version**. PHP 8.1 is included only for historical
compatibility; its upstream support ended on 31 December 2025.

The corrected audit agreed with all 60 recorded runtime cases. This is evidence
for these settings and fixtures, not a claim of complete server hardening.
[Compact runtime evidence](FPM-RUNTIME.json) records the images, observations and
before/after engine snapshots.

## Which criticism was confirmed?

- **The previous tests needed real FPM coverage: confirmed.** The new oracle is
  JSON returned by a running `fpm-fcgi` worker. Where available, `exec`, `system`
  and `shell_exec` also execute a fixed, harmless sentinel command. A fixed
  `data://` include checks whether `allow_url_include` really permits inclusion.
- **A shorter or empty pool `disable_functions` list removes global bans: not
  reproduced.** Global removals remained effective with both `php_value` and
  `php_admin_value`. Additional pool removals accumulated. With both pool forms
  present, global, ordinary and admin removals all remained effective.
- **`php_value` is ignored for an `INI_SYSTEM` setting: not true for these FPM
  pool cases.** Both settings reported access metadata `4` (`INI_SYSTEM`), yet
  `php_value[disable_functions]` removed functions and
  `php_value[allow_url_include]` enabled the real include. FPM applies pool
  settings through its own initialization path. The generic access label alone
  is insufficient to predict that path.
- **Reading only `ini_get('disable_functions')` can mislead: confirmed.** With
  global `exec` and pool `system`, the request displayed `system`, while both
  functions were unavailable. A replaced display string does not restore an
  internal function that was already removed.

The additive union used by the audit was therefore retained. The tests also
cover `php_flag`/`php_admin_flag` URL-inclusion settings and an admin `Off`
overriding an ordinary `On`. The auxiliary FPM dump is parsed in the comparison:
FPM normalizes flag entries to value entries. The dump is configuration
provenance, not the runtime success oracle.

## A real tokenizer bug, before and after

The runtime checks exposed a separate defect in the audit's function-list parser:

- **Uppercase names:** PHP did not remove `EXEC`, `SYSTEM`, etc. The old audit
  lowercased those names and could report a protected pool while the functions
  still worked. This affected both global and pool lists.
- **Space-separated names:** PHP accepts ASCII spaces as well as commas between
  names. The old comma-only parser reported an open pool even when the functions
  were unavailable.

The minimal correction splits on commas and ASCII spaces without lowercasing or
general whitespace stripping. This follows Zend's actual tokenizer. Against the
old engine, the suite returned **1**, with these four audit disagreements on each
PHP version. Against the corrected snapshot, all 60 cases returned **0**.

The engine SHA-256 values in the JSON identify the **historical snapshots used
for this experiment**. They are not final release hashes or proof that a later
commit was tested. Public CI against the final commit supplies that separate
evidence.

## Reproduce the checks

The integration tests need **Linux, Python 3.8+ and access to Docker**. PHP runs
inside official images; no host PHP, Nginx, curl, pip packages or production FPM
configuration are needed. The protocol tests need only Python:

```sh
python3 -B tools/test_fpm_runtime_protocol.py
```

Run the integration matrix from the source root:

```sh
python3 -B tools/test_fpm_runtime.py --engine p2s_harden.py --json \
  --image php:8.1-fpm-bookworm \
  --image php:8.4.27-fpm-bookworm \
  --image php:8.5-fpm-bookworm
```

Missing images are downloaded. Add `--pull never` when the images are already
cached; a missing image then produces incomplete evidence rather than a skip.
For an exact image reproduction, use the `php@sha256:...` repository digests in
the JSON with repeated `--image` options. The harness runs the resolved local
image ID throughout each version's cases, so a tag moving mid-run cannot change
the tested image.

Each disposable container has a 0.5-CPU, 128-MiB memory and 32-PID limit. It runs
unprivileged, with no network, no published ports, a read-only root filesystem
and only its generated fixture directory mounted. Requests use a private Unix
socket with mode `0600`. On a nonroot host, the container uses the caller's
effective UID and GID so the host client can connect; a root caller instead uses
container UID/GID `33:33`. FPM never runs as root. Cleanup checks the run's exact
container label before removal.

Exit codes describe **test evidence**:

- **0:** every requested case was observed and all runtime/audit assertions passed.
- **1:** an observed result disagreed with an assertion or the audit.
- **2:** a required image, capability, response or other evidence was unavailable.

The client also has ten protocol regressions, including fragmented responses,
premature EOF, HTTP/CGI error status, invalid JSON, wrong request identity and
FastCGI application/protocol failure. They passed on Windows and Linux. These
prevent transport failures from being accepted as successful runtime evidence.
Three additional fixture regressions check the Docker user argument and private
socket mode for root, nonroot and nonzero-UID/root-group callers.

## What this does not establish

The requests execute real PHP-FPM workers; they are not CLI `php -i` substitutes.
However, the optional `--engine` comparison supplies the known fixture instance
to `scan()` and isolates unrelated host checks. It tests the audit's pool
decisions against runtime evidence, not production discovery, systemd reloads,
Nginx routing, filesystem isolation or every PHP-to-shell technique.

`pcntl_exec` was already absent in all three images' baseline. The evidence
distinguishes baseline absence from functions removed by a setting; it does not
claim to have exercised a compiled PCNTL function. The other function checks use
availability/internal identity, with the three harmless operation controls noted
above. Results cover these Linux images and versions, not every PHP build,
extension, FastCGI override or future PHP release.

## Primary references

- [PHP-FPM configuration](https://www.php.net/manual/en/install.fpm.configuration.php):
  pool values and the additive `disable_functions` exception.
- FPM's own pool-setting initialization:
  [PHP 8.4](https://github.com/php/php-src/blob/PHP-8.4/sapi/fpm/fpm/fpm_php.c)
  and [PHP 8.5](https://github.com/php/php-src/blob/PHP-8.5/sapi/fpm/fpm/fpm_php.c).
- [Zend's function-removal tokenizer](https://github.com/php/php-src/blob/PHP-8.4/Zend/zend_API.c):
  `zend_disable_functions` and `zend_disable_function`.
- [Supported PHP branches](https://www.php.net/supported-versions.php) and
  [unsupported branches](https://www.php.net/eol.php).
- [Official PHP image manifest](https://github.com/docker-library/official-images/blob/master/library/php):
  current image tags; exact tested digests are retained in the evidence file.
