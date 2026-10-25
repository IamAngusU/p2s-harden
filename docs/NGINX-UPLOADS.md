# Upload execution checks - dev.7 preview

`P2S-NGX001` assesses selected upload directories against parsed Nginx disk
configuration. It never writes a probe, sends an upload request, edits Nginx or
reloads a service. Declare actual storage with `--runtime-dir`; a directory name
alone does not establish an application's upload paths.

## A guard that keeps images available

For a static `root /srv/site`, this example rejects PHP-family requests within
WordPress uploads while leaving images to the site's normal static routing:

```nginx
# In the same server block, BEFORE the generic PHP regex handler.
# (?s) is deliberate: it includes URL-decoded line breaks in .*
location ~* (?s)^/wp-content/uploads/.*\.(php|phtml|phar)(?:/|$) {
    deny all;
}

# Keep the site's existing PHP handler AFTER the upload denial.
location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
}
```

The snippet/socket names above are Debian/Ubuntu examples. Use the actual
installed FPM socket; inspect the complete server first. This is a reviewable
example, not an automatically applied fix. Validate with `nginx -t`, reload
through your normal procedure and independently test your actual virtual hosts.

For a simple upload prefix, the checker also recognizes one nested leaf:

```nginx
location ^~ /uploads/ {
    location ~* \.(php|phtml|phar)(?:/|$) {
        deny all;
    }
}
```

The parent must remain static, without alias/root overrides, executable content,
redirects or conflicting descendants. A `^~` prefix suppresses outer regex
handlers; take care to reject every script/source extension your deployment
uses. The audit is an execution check, not a complete source-disclosure audit.

## Why ordinary `.*` is reported OPEN

`^/uploads/.*\.php$` looks correct, but PCRE's ordinary dot excludes line breaks.
Nginx accepts a URL-decoded `%0a` in a normalized URI: the upload guard can miss
it while a later unanchored `\.php$` handler still matches. The checker reports
`regex_line_break_gap` when this is the uncovered part of the handler language.
This is reproduced with an inert PHP marker in the disposable distro VM tests;
the corrected DOTALL guard rejects both names and leaves the static image
available. A conventional filename alone is insufficient to establish safety.

## Bounded grammar and remaining UNKNOWNs

- `~` and `~*`, in configuration order; earlier handlers win over later guards.
- Generic suffixes `\.php$`, `\.(php|phtml|phar)$` and the equivalent noncapturing
  extension groups, with `$`, `(/|$)` or `(?:/|$)` termination.
- Anchored literal directory segments followed by `/.*` and those suffixes,
  optionally starting with `(?s)` for DOTALL. Segments use ASCII letters,
  digits, `_` and `-`; `(uploads|files)` / `(?:uploads|files)` choices expand to
  at most 64 literal prefixes. Arbitrary PCRE is never evaluated by Python.
- A guard must cover the handler's extension, case and PATH_INFO language over
  the complete selected directory. A partial subdirectory denial cannot
  certify its parent. The checker may conservatively reject separately split
  guards that would require combining multiple languages.
- Leaf `deny all` or bare `return 403/404/410/444`; allow exceptions, access gates,
  `satisfy any`, inherited error pages and conditionals are not assumed safe.
- Exact/longer competing prefixes, aliases, arbitrary regexes, named/predicate
  locations, complex nesting, `merge_slashes off`, unsupported modules,
  fixed front controllers and absent proven PHP handlers can stay UNKNOWN.
  An unresolved or changing include closure cannot be acknowledged.
- More than 512 direct locations in a server yields an unreviewable limit
  UNKNOWN before comparing guard languages; scope remains at most 128 pairs.

OK concerns only these selected root/URI mappings in the parsed server blocks.
Application-level includes, alternate filesystem paths, symlinks, workers'
loaded configuration and network enforcement still need separate assessment.

## Explicit review of unsupported routing

For a configuration you have independently inspected and tested, a separate
Nginx review file can acknowledge selected UNKNOWNs:

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --runtime-dir /srv/site/uploads \
  --write-nginx-review-draft /root/p2s-nginx-review.json
sudoedit /root/p2s-nginx-review.json
# Review entries individually: supply a reason and change reviewed:false to true.
sudo bash p2s-harden.sh --check --root /srv/site \
  --runtime-dir /srv/site/uploads \
  --nginx-baseline /root/p2s-nginx-review.json
```

The exclusive draft starts at mode 0600, never overwrites an existing file and
accepts nothing. Delete entries you cannot approve. Loading requires a protected
regular JSON file and protected ancestors, without symlinks or group/other write
access. Options work only with `--check`; drafting is incompatible with
`--redact`. Over SSH the file is created/read on the Linux target.

Entries bind the finding identity (target, root, URI, source line and server
index), finite UNKNOWN reason and SHA256 of the complete stable include
snapshot. Raw file contents, source paths, expanded directive order, empty
globs and their matches are included. Editing a comment, adding an include,
changing order or changing the target invalidates the review. The report's
local `nginx_review` object supplies the identity; `--redact` omits it.

Acknowledgement **retains UNKNOWN**, its raw count and `has_unknown:true`.
It adds `review_accepted:true`, `accepted_unknown` and
`has_unaccepted_unknown`; only the acknowledged row's exit-2 impact is removed.
Text retains the finding with `[reviewed UNKNOWN]`. Other UNKNOWNs and OPENs
continue to affect the exit code; `--ignore` still cannot accept UNKNOWN.
Missing configuration, read/race failures, unmapped storage and scope limits
are never reviewable. Acknowledgement is a documented operator decision,
not proof of blocking or an OK result.

## Evidence and limits

Regression fixtures exercise language coverage, order, case, extensions,
PATH_INFO, prefix bypasses, inherited controls, malformed patterns, review
privacy, protected drafts and include changes. The guarded disposable VM
harness additionally checks real Nginx/FPM responses for the newline bypass,
corrected guard, nested denial, image access and misplaced denial, alongside
fix/rollback checks. See the exact-commit [CI proof](CI.md).

These are controlled developer tests. Three independent real-server trials
remain pending; this work does not promote the preview to a stable release.

References: [Nginx location selection](https://nginx.org/en/docs/http/ngx_http_core_module.html#location),
[access-rule ordering/inheritance](https://nginx.org/en/docs/http/ngx_http_access_module.html),
[satisfy](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy),
[PCRE2 pattern options](https://www.pcre.org/current/doc/html/pcre2pattern.html#SEC16).
