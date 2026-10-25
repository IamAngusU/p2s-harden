# Verify build origin as well as download integrity

Checksums published with a release detect corruption or mismatched downloads.
If an attacker could replace both a file and its checksum, that comparison alone
would not establish origin. GitHub-signed build provenance adds the identity of
the workflow and source commit that produced the exact artifact bytes.

## Identity to require

The expected signer is `angusu-de/p2s-harden/.github/workflows/ci.yml` on
`refs/heads/release/2.2` for stable 2.2.2, on GitHub-hosted runners. This is the existing public CI fork,
owned by the same maintainer as `IamAngusU/php-fpm-audit`. It is not an independent
builder/auditor. Runner access remains unavailable in the source account.

The source repository was renamed from `IamAngusU/p2s-harden` to
`IamAngusU/php-fpm-audit`; the CI fork and signer were not renamed. Existing
launcher names, release assets and the provenance bundle retain `p2s-harden`.
Keep the signer identity below unchanged when verifying these downloads.

The provenance job depends on all eleven test jobs. It rebuilds the tested
commit, requires source/fork heads to match, verifies the standalone build and
tracked source manifest, then attests the Bash file, PowerShell file, source ZIP
and checksum file. The release uploads those exact CI-generated distribution
files and includes the signed `p2s-harden-provenance.json` bundle.

Stable 2.2.2 is built from matching source/fork `release/2.2` heads. Its public
proof is on `ci-proof-2.2`. Earlier 2.2.1 and development-main artifacts use
`refs/heads/main`; require that ref when verifying those specific historical or
preview files. The release tag and exact source digest identify the version.

## Verify a downloaded file

GitHub CLI is optional for verification; it is not needed to run the tool.
With a current, authenticated `gh`, this command works in Bash and PowerShell:

```text
gh attestation verify p2s-harden.sh --repo angusu-de/p2s-harden --signer-workflow angusu-de/p2s-harden/.github/workflows/ci.yml --source-ref refs/heads/release/2.2 --deny-self-hosted-runners
```

Use `p2s-harden.ps1` or the source ZIP filename for another asset. For stricter
verification, append `--source-digest EXPECTED_COMMIT`. Obtain the commit from
the release tag and compare it with the commit-specific public CI proof. The
tag is in the source repository; its commit equals the tested fork commit.

To verify the downloaded bundle instead of querying GitHub for attestations,
add `--bundle p2s-harden-provenance.json` to the same command. The bundle's
signature and subject digest are checked; do not merely inspect its JSON.
Network access may still be needed for trust material unless a complete offline
verification environment is configured.

Do not loosen the repository/workflow identity to make a failed verification
pass. A modified artifact, unexpected source commit or different signer must
fail the corresponding verification policy. Release validation checks these
negative cases as well as successful verification of the published downloads.

## Limits

Provenance authenticates a build claim, not the safety of its source code or the
state of the target server. A compromised authorized source/workflow could still
produce attested malicious code. Review the source, pinned workflow, expected
commit and CI evidence according to your trust requirements. GitHub CLI and its
trust roots are part of the verification boundary.

Primary references: [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
and [GitHub CLI verification policy](https://cli.github.com/manual/gh_attestation_verify).
