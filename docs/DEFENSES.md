# What p2s-harden can reduce - 2.3.0-dev.7 preview

Assume an attacker may already execute PHP through an application bug or an
uploaded file. Restricting selected direct functions reduces some follow-on
paths; it does not prevent that first compromise or contain all effects of PHP
execution. A successful fix is a bounded configuration change, not a clean-host
or isolation certificate. Published 2.2.1 files still carry their separate INI
editor advisory; the new observations are development-preview features.

## Direct functions and residual policy

The supported fix preserves existing restrictions, adds the seven selected
direct functions, and disables URL includes in supported FPM INIs. Pool policy,
service mapping, application compatibility, confirmation, backups and rollback
remain part of that existing workflow. No new functions are added to the fix.

**P2S-PHP005 is INFO**, even if all listed functions are disabled. It groups pools
with the same residual policy and reports finite names not disabled by policy:
`putenv`, `mail`, `error_log`, `dl`, `pcntl_fork`, `symlink`, `link`, and
`file_put_contents`. It also reports `enable_dl` as on/off/unknown and whether
`sendmail_path` is configured/empty/unknown. The helper command and its arguments
are never printed. Missing values stay unknown evidence; an empty helper setting
does not prove every mail-related path is blocked.

Not disabled is not the same as installed, callable, exploitable or necessary to
disable. The scanner does not call these functions in production. `dl()` is not
available in FPM; CLI observations cannot be transferred to the web SAPI.
`pcntl_fork()` does not itself execute a new program. An FFI class can exist even
when FFI calls from ordinary requests are restricted; the existing FFI policy
check is separate. Mail and file APIs are normal application dependencies.
Neither these observations nor a green direct-function check establish that a
particular bypass exists or that all bypasses are closed. [PHP function policy](https://www.php.net/manual/en/ini.core.php#ini.disable-functions),
[dl SAPI scope](https://www.php.net/manual/en/function.dl.php),
[FFI configuration](https://www.php.net/manual/en/ffi.configuration.php).

## Upload routes: configuration evidence, no production probes

**P2S-NGX001** reads the expanded, bounded Nginx configuration already used for
discovery. With explicit mappings or `--no-auto`, supply `--nginx-config` to
select it. `--runtime-dir` declares actual storage under selected roots; existing
`uploads` and `wp-content/uploads` directories are also reported as candidates,
without assuming that these are all application upload paths. Names alone are
not trust evidence. No known storage produces INFO asking for scope; an unmapped
declared directory or unsupported mapping is UNKNOWN.

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --nginx-config /etc/nginx/nginx.conf --runtime-dir /srv/site/uploads
```

The check handles literal server/http roots and a small static location subset:

- **OPEN:** a conceptual `.php` URI in that prefix selects an unambiguous
  FastCGI handler with a supported script mapping. Recognized generic PHP
  patterns are `\.php$`, `\.php(/|$)` and `\.php(?:/|$)` with `~`/`~*`.
  SCRIPT_FILENAME must use `$document_root$fastcgi_script_name` or
  `$realpath_root$fastcgi_script_name`. This is a configuration opportunity if
  a PHP file can be stored there, not an uploaded/executed exploit or proof of
  network reachability.
- **OK:** a supported ordered PHP denial or one nested regex leaf under a static
  `^~` prefix can preserve images; the guard must cover case, extensions,
  PATH_INFO and line breaks. See [tested examples and review](NGINX-UPLOADS.md).
  The checker also recognizes a selected static `^~` prefix with an unconditional leaf
  `return 403`, `404`, `410` or `444`, no conflicting exact/longer child route,
  no aliases, and no unsupported control flow. OK applies to the selected URI
  prefix in that parsed server block, not all ways an application might include
  the file. A plain `/uploads/` location does not outrank a generic PHP regex.
- **UNKNOWN:** aliases, unsupported nested/named/predicate locations, arbitrary regexes,
  conflicting mappings, access gates, nonstandard script-name rewrites, selected root overrides, internal redirects/error pages,
  conditionals and unsupported directives. Unknown PCRE is not executed through
  Python's regex engine. A static front-controller mapping is not treated as
  execution of an uploaded PHP file. At most 128 target/server pairs are assessed;
  exceeding the budget stays UNKNOWN. Selected unsupported routing can be
  explicitly acknowledged through a protected complete-configuration review;
  UNKNOWN stays visible and changed includes invalidate it. Read/race/scope
  failures are never reviewable. Ordinary `.*` before a PHP suffix can permit
  URL-decoded line breaks; a detected gap remains OPEN, not reviewable.

Related static roots are checked even when an upload directory is another
server's entire document root. Alias presence prevents a blanket static-block
verdict; aliases can expose alternate URIs. Exact matching, prefix priority and
regex order are why a generic copy-pasted deny rule is not applied automatically.
[Nginx location selection](https://nginx.org/en/docs/http/ngx_http_core_module.html#location),
[FastCGI script mapping](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_param).

There is **no production upload, HTTP execution probe, Nginx edit or reload**.
Parsed disk configuration is not proof of what existing workers loaded. Validate
your intended configuration with `nginx -t`, review every real virtual host and
alternate storage route, and arrange a controlled application test in an
appropriate environment. Blocking a URI does not stop an already compromised
PHP application from reading or including files it can access.

## systemd properties: selected manager policy only

**P2S-SYS002** reads `NoNewPrivileges`, `ProtectSystem` and `PrivateTmp` using a
trusted `systemctl show` binary and a five-second timeout. The discovered service
must be loaded/active, its Id must agree, and MainPID must match the discovered
FPM master. Duplicate/missing/unknown properties or an identity mismatch produce
UNKNOWN. An unavailable systemd context is explicitly not assessed. Valid
properties are INFO, including hardened values: they are not an all-safe verdict.

- `NoNewPrivileges` limits privilege gain through execution; it does not prevent
  ordinary subprocess creation or access already held by the PHP identity.
- `ProtectSystem` selects read-only filesystem mounts. The mode and write/bind
  exceptions matter; `full` does not make application data read-only and `strict`
  still needs a correct writable-data design. It does not isolate Unix sockets.
- `PrivateTmp` separates temporary-file namespaces. Shared helper workflows may
  need compatibility review; it is not a general filesystem or process sandbox.

The check does not attest existing worker namespaces, `/proc` enforcement,
kernel support, capabilities, syscall/network restrictions or every write
exception. Manager properties can differ from the effective context of old
workers, so the report keeps `worker_attestation: false`. Review the actual unit,
loaded properties and application requirements; no service unit or drop-in is
written, and no service is restarted for these observations. [systemd execution
properties and their limitations](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

## Validation and release boundary

The regression suite has **309 tool tests and 23 auxiliary tests**. It covers route priority, exact/longer descendants, aliases,
unknown regex/module behavior, missing scopes, residual-policy grouping/privacy,
active service identity and property parsing. Native launchers and real Rust JSON
interoperability retain their existing checks. Actual FPM observations distinguish
function existence from policy and verify that FPM lacks `dl()`; a controlled
pool also disables `putenv`/`mail` without invoking either.

Each of the four disposable distro VMs adds manager-property comparison and
harmless fixture HTTP observations: stored PHP executes under an open route,
a static prefix guard returns 403, and a nested executable route must remain
UNKNOWN. The normal tool does not run this harness. The full matrix retains 104
FastCGI observations and 56 real INI cases, with **18 stages per VM / 72 overall**.
Exact tested commits, engine hashes and signed main build provenance identify
the evidence; the CI fork has the same maintainer.

Three independent external server trials are still pending, and no measured
real/evasive-malware detection rate is claimed. This remains a development
preview; the additional observations do not expand the automatic fix scope or
turn `--fix` into compromise prevention, universal confinement or incident recovery.
