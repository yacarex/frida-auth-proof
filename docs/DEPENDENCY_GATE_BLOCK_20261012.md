# Dependency gate stopped — 2026-10-12

Result: **FUSIONAUTH PROOF BLOCKED — HARNESS_DEPENDENCY_SECURITY**.
Candidate inspected: `f94b56a6ef377a16bd2edc5a3fcd4ebfb9e1e0ed`.
This is not a FusionAuth protocol failure. Actions and K1 remain NOT_RUN.

Direction authorized adding reproducible installation, integrity verification
and isolated audit, with an explicit stop if incompatible vulnerabilities were
found. Before installing dependencies, release-specific PyPI metadata was queried
for all 13 exact pins. Every query succeeded. Active advisory records were found
for four packages. The maintainer independently confirms a HIGH affecting the
pinned cryptography version. Work stopped without changing dependency versions,
introducing exceptions, running services or claiming an executable ready state.

| Package | Pinned version | Finding |
|---|---|---|
| cryptography | 46.0.2 | GHSA-r6ph-v2qm-q3c2 / CVE-2026-26007, HIGH confirmed by maintainer; additional active advisories in snapshot |
| oauthlib | 3.3.1 | GHSA-xpv3-w29h-x7cv / CVE-2026-49265 |
| PyJWT | 2.10.1 | Multiple active advisory records; exact IDs/aliases in snapshot |
| requests | 2.32.5 | GHSA-gc5v-m9x4-r6x2 / CVE-2026-25645 |

The remaining nine queried pins returned empty vulnerability arrays at the
recorded cutoff. This is not a full installed-environment audit: no installation,
resolver or installed-file integrity test ran. Alias records are not counted as
independent vulnerabilities. Severity of every advisory was not individually
reclassified; a verified HIGH is sufficient to keep the candidate blocked.

## Reachability and interpretation

The confirmed cryptography advisory affects SECT curves. K1 is configured for
RS256; this review does not claim that K1 exercises the vulnerable path. The
oauthlib finding concerns authorization-server PKCE comparison; this harness
uses its client helpers. Requests' advisory concerns direct use of
extract_zipped_paths, not ordinary Requests usage. These limits do not constitute
an approved exception to the dependency gate. No provider rejection is inferred.

The maintainer lists 46.0.5 as fixing the cited cryptography advisory. That is
NOT a recommendation that 46.0.5 clears every current advisory. The snapshot
contains later fixes and no aggregate remediation assessment was authorized or
performed here. No dependency updates were made to obtain PASS.

## Evidence and reproduction

- [Sanitized package/version/advisory snapshot](../evidence/dependency-advisories-20261012.json).
- PyPI API contract: https://docs.pypi.org/api/json/#known-vulnerabilities
- Primary maintainer advisory: https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2
- OAuthlib primary advisory: https://github.com/oauthlib/oauthlib/security/advisories/GHSA-xpv3-w29h-x7cv

For each line `name==version` in requirements.txt, GET the recorded
`https://pypi.org/pypi/name/version/json` over verified HTTPS. Check the returned
version and the presence/type of vulnerabilities; retain non-withdrawn records.
Do not treat a request failure, absent field or malformed response as zero
findings. Responses contain aliases which need deduplication for totals. The
snapshot retains response hashes as provenance; live advisories may change.
No tokens, user data, credentials, wheel binaries or old private logs are included.

## Exact delivery delta and state

Only this note, the sanitized snapshot and the public inventory are added/updated.
K1, setup, runner, workflow, requirements and the frozen profile are unchanged.
The inventory is regenerated to cover the new evidence files. The manual trigger
and standard free public runner remain unchanged; no Actions were dispatched.

Reproducible installation/hash-lock implementation and installed-environment
audit remain unfinished under the stop condition. Do not run the old workflow.
Next decision required: bounded dependency remediation for this isolated harness,
then finish the installation/integrity/audit gate and re-review a new candidate.
No implicit approval to upgrade, waive findings or widen scope is requested here.

No service, DB, tenant, synthetic account or runtime secret was created during
this review; no runtime cleanup is pending. Only metadata/evidence were read.
`NEW AUTH CAPABILITIES: OFF`. Private Frida repository unchanged.

FUSIONAUTH PROOF BLOCKED
