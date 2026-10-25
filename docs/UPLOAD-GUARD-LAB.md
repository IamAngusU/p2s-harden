# Reproduce the upload-guard gap

A common Nginx denial, `^/uploads/.*\.php$`, can miss a filename containing a
line break: ordinary PCRE `.` does not match that character. A later generic
`\.php$` handler can still send the file to FPM. This is a configuration gap,
not a PHP vulnerability or a claim that every upload form is exploitable.
An attacker would need a way to place such a filename in that executable path.

## One command, disposable fixtures

Use a machine with Python 3.8+, Docker CLI and a running **Linux-container**
daemon. Docker is needed only for this optional reproduction, not ordinary
p2s-harden audits. From a clone or unpacked source archive:

```bash
python3 tools/reproduce-nginx-upload-guard.py
```

No pip packages, Compose file, host Nginx/FPM installation, sudo inside the tool,
or server URL is required. Your account must already have access to Docker.
Missing prerequisites produce an explanatory incomplete result with exit 2;
nothing is installed automatically. The first run may download official images.

The lab creates one FPM container and, sequentially, three Nginx containers.
They share only an isolated loopback network and a labelled fixture volume.
It publishes **no ports**, mounts **no host paths**, uses read-only container
root filesystems and limits CPU, memory and process counts. The PHP fixtures
only return a fixed marker, PHP version and SAPI; they accept no input and
execute no shell command. Images remain cached after the run.

Normal completion and handled failures remove the owned containers and volume.
Resources are checked against a unique ownership label before removal. If the
Docker daemon becomes unavailable or the process is forcibly killed, inspect
only this lab's resources before cleaning up:

```bash
docker ps -a --filter label=p2s.upload-guard-lab
docker volume ls --filter label=p2s.upload-guard-lab
```

The JSON report names resources if cleanup could not finish. Do not use global
Docker prune commands for this lab.

## What it checks

Each variant requests a normal PHP file, a PHP file with a line break encoded as
`%0a`, and a static SVG. HTTP 200 alone is insufficient: the lab verifies the PHP
marker **and `fpm-fcgi` SAPI**, or the image's exact bytes. It compares those live
observations with the same static route function used by `P2S-NGX001`.

Expected output:

```text
no_guard: normal / newline / image = 200, 200, 200; tool OPEN (php_fastcgi_mapping)
ordinary_dot: normal / newline / image = 403, 200, 200; tool OPEN (regex_line_break_gap)
dotall: normal / newline / image = 403, 403, 200; tool OK (ordered_php_rejection)
Cleanup complete: True
```

The corrected guard in this fixture is placed **before** the generic PHP handler:

```nginx
location ~* (?s)^/uploads/.*\.php$ {
    deny all;
}
```

`(?s)` explicitly enables DOTALL. For a real deployment, also account for every
executable extension, PATH_INFO, aliases, nested routes, other virtual hosts and
internal redirects. See the broader [reviewable configuration examples](NGINX-UPLOADS.md).
The lab checks its own fixtures; it does not upload files to or certify your site.

## Keep a reproducible observation

```bash
python3 tools/reproduce-nginx-upload-guard.py --json > upload-lab.json
# Optional historical version comparison; still an isolated lab:
python3 tools/reproduce-nginx-upload-guard.py --nginx-image nginx:1.24 --json
```

Exit 0 means all three fixture observations matched their expected outcomes and
cleanup finished. Exit 2 means missing capabilities, an unexpected result or
incomplete cleanup. This is a lab exit contract, separate from audit exit codes.

Default image tags can change. JSON records the actual image IDs/repository
digests, observed Nginx/FPM versions and audit-engine SHA256. All three variants
use the same actual Nginx image. To repeat a specific run, supply the recorded
`nginx@sha256:...` and `php@sha256:...` through `--nginx-image` / `--php-image`.
Use trusted images. Retain your checkout's Git commit alongside the JSON.

The lab runs in CI together with a wrong-FPM-image failure case that must remove
its resources. Its `nginx-upload-lab` artifact is separate from the four distro
VM artifacts. Controlled container/VM runs and reviewer reproductions do not
replace independent production-server trials.

## Check your existing configuration without uploading anything

Use the **dev.7 preview** Bash launcher from this checkout (the older published
2.2.1 download does not include this check):

```bash
sudo bash p2s-harden.sh --check --root /srv/site \
  --nginx-config /etc/nginx/nginx.conf --runtime-dir /srv/site/uploads
```

Replace the paths with your actual document root and upload directory. Audit
only systems you administer. The audit reads configuration and permissions;
it creates no marker files, edits no Nginx rule and performs no upload probe.
`OPEN` establishes a supported configuration opportunity, not proof that the
application accepts a hostile filename. `UNKNOWN` needs manual review rather
than an automatic all-clear. Review changes, run `nginx -t`, and test real
virtual hosts through your normal deployment process.

References: [PCRE2 dot/newline semantics](https://www.pcre.org/current/doc/html/pcre2pattern.html),
[Docker's isolated network](https://docs.docker.com/engine/network/drivers/none/).
