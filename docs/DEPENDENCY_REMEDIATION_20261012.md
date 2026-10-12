# Advisory remediation decision — 2026-10-12

Decision recorded before updating the public pins. Sources are release-specific PyPI/OSV records; aliases are deduplicated. No reachability waiver or ignored advisory.

| Package | Advisory / aliases | First fixed release reported | Source |
|---|---|---|---|
| cryptography | GHSA-r6ph-v2qm-q3c2, CVE-2026-26007, PYSEC-2026-2141 | 46.0.5 | https://osv.dev/vulnerability/GHSA-r6ph-v2qm-q3c2 |
| cryptography | GHSA-m959-cc7f-wv43, CVE-2026-34073, PYSEC-2026-35 | 46.0.6 | https://osv.dev/vulnerability/GHSA-m959-cc7f-wv43 |
| cryptography | GHSA-p423-j2cm-9vmq, CVE-2026-39892, PYSEC-2026-36 | 46.0.7 | https://osv.dev/vulnerability/GHSA-p423-j2cm-9vmq |
| cryptography | GHSA-537c-gmf6-5ccf | 48.0.1 | https://osv.dev/vulnerability/GHSA-537c-gmf6-5ccf |
| cryptography | GHSA-m2h6-j472-rp4c, CVE-2026-69248, PYSEC-2026-3554 | 49.0.0 | https://osv.dev/vulnerability/GHSA-m2h6-j472-rp4c |
| cryptography | GHSA-g6cj-pr64-35w5, CVE-2026-69247, PYSEC-2026-3552 | 50.0.0 | https://osv.dev/vulnerability/GHSA-g6cj-pr64-35w5 |
| cryptography | GHSA-jwv3-5hgf-82ww, CVE-2026-69249, PYSEC-2026-3553 | 49.0.0 | https://osv.dev/vulnerability/GHSA-jwv3-5hgf-82ww |
| oauthlib | GHSA-xpv3-w29h-x7cv, CVE-2026-49265 | 4.0.0 | https://osv.dev/vulnerability/GHSA-xpv3-w29h-x7cv |
| PyJWT | GHSA-752w-5fwx-jx9f, CVE-2026-32597, PYSEC-2026-120 | 2.12.0 | https://osv.dev/vulnerability/GHSA-752w-5fwx-jx9f |
| PyJWT | PYSEC-2025-183, CVE-2025-45768 | No fixed event; last affected 2.10.1, next stable 2.11.0 | https://osv.dev/vulnerability/PYSEC-2025-183 |
| PyJWT | PYSEC-2026-179, CVE-2026-48526, GHSA-xgmm-8j9v-c9wx | 2.13.0 | https://osv.dev/vulnerability/PYSEC-2026-179 |
| PyJWT | PYSEC-2026-175, CVE-2026-48522, GHSA-993g-76c3-p5m4 | 2.13.0 | https://osv.dev/vulnerability/PYSEC-2026-175 |
| PyJWT | PYSEC-2026-177, CVE-2026-48524, GHSA-fhv5-28vv-h8m8 | 2.13.0 | https://osv.dev/vulnerability/PYSEC-2026-177 |
| PyJWT | PYSEC-2026-178, CVE-2026-48525, GHSA-w7vc-732c-9m39 | 2.13.0 | https://osv.dev/vulnerability/PYSEC-2026-178 |
| PyJWT | PYSEC-2026-176, CVE-2026-48523, GHSA-jq35-7prp-9v3f | 2.12.1 | https://osv.dev/vulnerability/PYSEC-2026-176 |
| PyJWT | GHSA-w6j9-cwv2-h6wq, CVE-2026-102274 | 2.14.0 | https://osv.dev/vulnerability/GHSA-w6j9-cwv2-h6wq |
| PyJWT | GHSA-2gx3-rcp4-g85q, CVE-2026-101917 | 2.14.0 | https://osv.dev/vulnerability/GHSA-2gx3-rcp4-g85q |
| PyJWT | GHSA-hxm8-2xgr-2p9m, CVE-2026-102269 | 2.14.0 | https://osv.dev/vulnerability/GHSA-hxm8-2xgr-2p9m |
| PyJWT | GHSA-9v7f-9g4p-ffgj, CVE-2026-102267 | 2.14.0 | https://osv.dev/vulnerability/GHSA-9v7f-9g4p-ffgj |
| PyJWT | GHSA-ffc3-869f-jxw9, CVE-2026-102268 | 2.14.0 | https://osv.dev/vulnerability/GHSA-ffc3-869f-jxw9 |
| PyJWT | GHSA-p4g4-x82p-q773, CVE-2026-102271 | 2.14.0 | https://osv.dev/vulnerability/GHSA-p4g4-x82p-q773 |
| PyJWT | GHSA-jwrc-g2q2-pq5p, CVE-2026-102270 | 2.14.0 | https://osv.dev/vulnerability/GHSA-jwrc-g2q2-pq5p |
| PyJWT | GHSA-42vr-xj54-vc7v, CVE-2026-101918 | 2.15.0 | https://osv.dev/vulnerability/GHSA-42vr-xj54-vc7v |
| PyJWT | GHSA-x33g-cr3x-6449, CVE-2026-102275 | 2.15.0 | https://osv.dev/vulnerability/GHSA-x33g-cr3x-6449 |
| requests | GHSA-gc5v-m9x4-r6x2, CVE-2026-25645, PYSEC-2026-2275 | 2.33.0 | https://osv.dev/vulnerability/GHSA-gc5v-m9x4-r6x2 |

## Minimum common candidate

| Dependency | Previous | Candidate | Delta |
|---|---|---|---|
| cryptography | 46.0.2 | 50.0.0 | Major; latest active advisory requires 50.0.0 |
| oauthlib | 3.3.1 | 4.0.0 | Major |
| PyJWT | 2.10.1 | 2.15.0 | Minor |
| requests | 2.32.5 | 2.33.0 | Minor |

These exact candidate releases have empty active-advisory lists at the review cut. All nine other application pins are retained. Optional extras are not enabled. No new transitive package is required. CPython 3.12 satisfies all Requires-Python and active dependency markers. Installed metadata plus pip check must confirm the graph.

PYSEC-2025-183 has a last_affected event, not an unbounded range: https://osv.dev/vulnerability/PYSEC-2025-183 . Do not describe absence of fixed_in as an exception or ignore. For CVE-2026-48523, PYSEC reports 2.12.1 whereas GHSA reports 2.13.0; the chosen 2.15.0 is beyond both and release-specific 2.12.1 readback still contains GHSA-jq35-7prp-9v3f. Thus 2.13.0 is the first release satisfying both records; the disagreement is retained rather than silently erased.

## Retained pin / toolchain

Soup Sieve 3.0.1 is yanked because its original Python marker admitted Python <3.11.5 with a regex bug. The supported proof runtime is CPython 3.12; its HTML-selector API is checked offline. This is not an advisory allowlist. The original pin remains to minimize churn.

pip 26.2.1 is newly pinned as installation tooling (not an OAuth dependency). A venv is created without bundled pip; only the hash-verified pip wheel bootstraps the locked install. This avoids an uncontrolled bootstrap distribution in the installed graph.

## Scope

No OAuth helper behavior, K1 case, redirect semantics, provider version/image, N01–N54, K1–K6 or workflow trigger changes. No AS requests, Actions or K1 in this remediation. Installation integrity is distinct from future FusionAuth behavior.

## Execution evidence / limits

See `evidence/dependency-remediation-20261012.json`: fresh CPython 3.12.14 environment,
14 exact distributions (13 harness + pip), 878 installed wheel payload files checked,
`pip check` PASS, PyPI release-specific installed-graph audit zero active findings,
and offline import/API checks PASS. Four negative dependency-barrier tests PASS:
corrupt download prevents installation; installed payload corruption rejected;
advisory-source outage rejected; any active advisory rejected. Tamper state restored.
Local venvs/downloaded wheels were removed; no services or external fixtures created.

The runner uses the same installer and blocks before fixture generation on failure.
No Actions or K1 executed. Hosted Ubuntu execution remains pending manual approval.
No secrets, real accounts, private application source, token/code/verifier values,
private keys, cookies or credentials are included in publication. Workflow is unchanged:
manual dispatch only, standard public Ubuntu runner, isolated PostgreSQL service,
no configured paid infrastructure, caches/artifact uploads or shared secrets.

Historical dependency-block evidence is retained, not rewritten as a PASS. This
evidence covers dependencies only and does not alter the independent Frida security hold.
