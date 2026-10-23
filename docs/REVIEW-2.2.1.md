# 2.2.1 review response

This is the current response to the review of stable 2.2.0 (`21b1c17`).
The earlier [rc.3 response](REVIEW-rc3.md) records decisions at that earlier
release; it is not a current feature inventory.

1. **Documentation:** historical decisions are labeled and linked to current
   scope. Redaction and the listed pool/FFI checks arrived in 2.2.0. Strict
   application profiles and existing-worker attestation remain deferred.
   Historical announcements are not evidence for a newer commit; use its tag
   and exact-commit public proof.
2. **Duplicate findings:** pools with the same missing required functions share
   the global finding, even when the pool adds unrelated restrictions. Equivalent
   include settings are also grouped. Original global resource IDs remain stable;
   normal JSON records `affected_pools` and a safe count. Different function sets
   remain distinct even when both are OPEN. An explicit unsafe include override
   is an independent cause that survives a global fix, so it remains visible even
   when its current value equals the global value.
3. **Useful private reports:** typed `evidence` fields retain missing known
   functions, mode/source, safe boolean/enum settings, counts and HTTP status.
   Each rule has its own allowlist and type/value checks, applied again during
   redaction. Arbitrary suffix names, host identifiers, resource metadata,
   exception prose, plans and transactions remain omitted. No regex guesses
   which portions of a raw diagnostic are private.
4. **Build provenance:** the dependent CI job signs the four generated
   distribution files with GitHub build attestations. The expected signer is the
   same-maintainer CI fork's pinned workflow, not the source account or a third
   party. The release gate requires live verification of published artifacts,
   including rejection of modified bytes and wrong identity/commit policies.
5. **localhost:** the exact names `localhost` and `localhost.` use the host's
   current name-service result through an isolated Python child with a two-second
   timeout and per-instance cache. All answers must be loopback. An outside
   address is OPEN; failed/malformed resolution is UNKNOWN. Other hostnames
   remain UNKNOWN. Names alone do not establish what an existing FPM worker
   bound earlier; this remains disk/current-host configuration evidence.
6. **Compatibility and feedback:** add actual Debian 13 / PHP 8.4 and Ubuntu
   22.04 / distro PHP 8.1 VMs to Debian 12 and Ubuntu 24.04. Ubuntu 22.04 coverage
   is distribution compatibility evidence, not endorsement of upstream PHP 8.1
   security support. Add an Audit feedback issue form requesting reviewed
   `--redact --json` output. The four VMs also exercise real `--fix --json`
   refusal without `--yes`, checking bytes, ownership and worker behavior.
7. **Drop-ins/upgrades:** keep the existing-file transaction model and explicitly
   document possible conffile prompts when both a locally modified `php.ini`
   and the package maintainer's version change. A drop-in needs independently
   tested ordering, creation, recovery and deletion-conflict behavior.

The supported scope remains [explicit](PRODUCTION.md). More distributions and
signed builds do not establish universal vulnerability coverage or independent
security certification.
