# Publication safety review — 2026-10-12 UTC

Dependency remediation delta on the public proof repository. Exact commit/readback
is recorded in the delivery; no Actions/K1 execution is claimed.

## File-by-file scope

| File | Review |
|---|---|
| README.md | Reproduction/gates/limits, no private source or credentials |
| manifest.json | Candidate/image digests, policy and historical commit identities only |
| requirements.txt | Exact application dependency versions; dependency-only evidence recorded separately |
| .gitignore | Excludes private execution files, traces and dumps |
| .github/workflows/fusionauth-k1.yml | Sole trigger workflow_dispatch; standard public Ubuntu; read-only contents; no secrets, caches or paid action |
| harness/setup.py | New synthetic setup; random ephemeral credentials; no hardcoded password/key; no tenant remote write |
| harness/k1.py | New protocol test source; no private Frida implementation; OAuthlib/PyJWT; transport allowlist, no raw outputs |
| harness/runner.py | New local-to-runner lifecycle; no shared credentials; logging disabled; targeted cleanup |
| harness/audit_public.py | Hash inventory, secret-pattern scan and static trigger checks; not a universal secret detector |
| docs/NORMATIVE_MATRIX.md | All 54 approved rows preserved byte-for-byte; private Android anchor and internal links omitted |
| docs/KNOCKOUT_PROFILE.md | Frozen six gates/oracles; normative specification only |
| docs/HARNESS_PLAN.md | Approved specification; obsolete private delivery note replaced with public scope note |
| docs/SAFETY_REVIEW.md | This review; no runtime claims |
| PUBLIC_INVENTORY.json | Paths, sizes and SHA-256 of all other public payload files |

Manual source review finds no real users/data, credentials, API keys, passwords,
codes, verifier values, tokens, cookies or private keys. Source identifiers for
these fields are necessary test code, not their values. Synthetic UUIDs and
`fixture@example.invalid` are explicitly artificial. No old logs, dumps, .env,
private app code, private signing information or downloaded vendor examples copied.

The automated denylist complements that review; no scanner guarantees universal
absence of secrets. Inventory fingerprints prevent an unreviewed extra file from
silently entering a dispatched payload. Scan runs before AS setup.

## Infrastructure/cost

Public standard `ubuntu-24.04` runner only, not a larger/custom runner. No
artifact upload/cache or registry push. Results in logs/summary only. PostgreSQL
and FusionAuth run inside that runner; no cloud DB, external tenant, subscription,
license activation, DNS or email service. No account purchase or billing change.

GitHub official documentation, consulted 2026-10-12:
https://docs.github.com/en/billing/concepts/product-billing/github-actions
Standard hosted runners are free for public repositories; job logs/summaries
do not count toward artifact storage. Larger runners and storage are different
products and are deliberately excluded. This is a configuration-based statement,
not inspection of account billing or a claim of free productive FusionAuth hosting.

## Explicit remaining gates

- Exact new public commit/tree/hash readback before reporting readiness.
- Dependency install/audit is rerun fail-closed in the manual workflow before K1.
  Local dependency-only evidence does not constitute a hosted runner/K1 PASS.
- Static syntax review does not establish Docker startup, login form compatibility,
  code expiry, redirect binding or any OAuth behavior.
- Workflow dispatch capability: current connector does not expose it; manual
  execution may be necessary only after publication readback.
- K2–K6 not implemented/executed in this initial K1 package.

Any K1 emitted token on an invalid exchange immediately yields rejection;
infrastructure/harness ambiguity yields BLOCKED. No threshold/contract relaxed.

## Cleanup protection

No services were started during package preparation. No fixtures, tenant or
external credentials were created. Runner future cleanup destroys all generated
private material and named containers/volumes. Failure/cancellation still relies
on GitHub destroying the ephemeral runner; cannot claim that future cleanup ran.

## Remediation delta review

New public files contain only: exact dependency pins/hashes/artifact URLs; dependency
installer and advisory/integrity gate; offline API smoke checks; advisory version
matrix; sanitized installed audit and results. The sole modified runtime lifecycle
is the dependency barrier before fixture creation. K1/setup/specifications/workflow
remain byte-for-byte unchanged. Synthetic RSA keys/tokens in the offline smoke test
exist only in memory and are never printed/exported. No vendor wheel binaries,
raw downloaded metadata, venv, private filesystem paths or historical logs are published.

The dependency auditor uses the documented PyPI release-specific vulnerability
feed for every installed distribution, including pip. It does not suppress findings.
The exact wheel is authenticated by the reviewed hash before installation; immutable
installed payload is compared to that wheel. pip-generated RECORD/pyc/entry-point
wrappers are distinguished from upstream wheel payload. This is not a signature
or provenance attestation from the library vendor.
