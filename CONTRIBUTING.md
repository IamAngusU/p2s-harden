# Contributing

Keep the default command read-only and make incomplete coverage explicit. Isolate failures by subsystem and never convert a tool/network error to OK. Do not add automatic package installation or infer permission changes from discovery.

Edit `src/*.py` and launcher templates, run `python3 build-standalone.py`, then `python3 build-standalone.py --check`. The engine and launchers are generated; do not edit them directly. Run `sudo bash tools/test-linux.sh` in a disposable Linux checkout. The ownership, ACL and rollback fixtures need root and the `www-data` account. Run `powershell -NoProfile -File test-windows-launcher.ps1` on Windows for native transport coverage.

Any new fix must include a concrete preview, capability checks before mutation, failure recovery, conflict detection and meaningful fixture tests. Tests must never change a real host's PHP, Nginx, firewall or SSH configuration. Do not publish unredacted server reports, credentials or application environments.

The separate `tools/test_system_runtime.py` is destructive integration infrastructure for explicitly marked disposable VMs only. Never invoke it from ordinary unit tests or on an existing host. The public VM jobs test actual systemd and distribution packages; they must not mock discovery or service management. New findings need explicit stable rule/resource IDs, remediation and canonical English diagnostics. JSON schema changes require migration notes.

The CI workflow is a definition; a passing local suite must not be described as a completed public CI run. A new supported FPM layout needs real configuration fixtures and integration evidence before expanding the support claim.

For real FPM semantics, run `python3 tools/test_fpm_runtime.py --engine p2s_harden.py` on Linux with Docker. This uses disposable containers, real FastCGI requests and a fixed data-URI include control. See [the review follow-up](docs/REVIEW-FOLLOWUP.md) for the cases and limits.
