# Contributing

Keep the default command read-only and make incomplete coverage explicit. Isolate failures by subsystem and never convert a tool/network error to OK. Do not add automatic package installation or infer permission changes from discovery.

Edit the engine/templates, run `python3 build-standalone.py`, then `python3 build-standalone.py --check`. Run `sudo bash tools/test-linux.sh` in a disposable Linux checkout. The ownership, ACL and rollback fixtures need root and the `www-data` account. Run `powershell -NoProfile -File test-windows-launcher.ps1` on Windows for native transport coverage.

Any new fix must include a concrete preview, capability checks before mutation, failure recovery, conflict detection and meaningful fixture tests. Tests must never change a real host's PHP, Nginx, firewall or SSH configuration. Do not publish unredacted server reports, credentials or application environments.

The CI workflow is a definition; a passing local suite must not be described as a completed public CI run. A new supported FPM layout needs real configuration fixtures and integration evidence before expanding the support claim.
