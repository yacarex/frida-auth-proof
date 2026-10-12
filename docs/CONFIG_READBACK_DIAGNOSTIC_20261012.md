# CONFIG_READBACK_HTTP — bounded diagnostic delta

Base: `6ff259ceb088aaa4e34be59608a66b1d6548c28e`.
Run #5: https://github.com/yacarex/frida-auth-proof/actions/runs/38250643314
GitHub job metadata confirms container initialization, checkout, payload check and
cleanup succeeded; the execution step failed. Direction accepts dependency gates
and reports CONFIG_READBACK_HTTP. No accepted gate is rerun by this change.

## What can be established from the captured evidence

The old harness queried exactly these endpoints with GET, using its synthetic
API key and X-FusionAuth-TenantId for the expected tenant:

- `/api/application/22222222-2222-4222-8222-222222222222`
- `/api/tenant/11111111-1111-4111-8111-111111111111`

It then combined both status checks into one error and discarded both response
categories/statuses. At least one status was not 200. Individual HTTP statuses,
body categories, resource existence and complete kickstart success are UNKNOWN.
The connector rejects the job-log endpoint; even the old public report schema
did not include these fields. No values are reconstructed or invented.

The runner's status probe had succeeded before reaching this readback, but that
alone is not proof that all kickstart requests completed. Existing API-key setup
and tenant-scoped application requests follow documented Kickstart structure.
The retrieve-tenant API documents API-key authentication and its tenant header;
there is no basis for attributing this failure to the global-key restriction of
other APIs such as tenant search. No key/header/configuration change is made.

Primary sources reviewed:
- https://fusionauth.io/docs/get-started/download-and-install/development/kickstart
- https://github.com/FusionAuth/fusionauth-site/blob/main/astro/src/content/docs/apis/tenants/retrieve-a-tenant.mdx
- https://fusionauth.io/docs/apis/authentication

## Instrumental correction

A read-only observer now captures method, exact synthetic path, attempt, HTTP
status, fixed category, JSON/empty/non-JSON classification, expected object/ID
booleans and structured-error presence. No response values, error messages,
headers, key fingerprints, cookies or raw body are emitted.

Readiness is bounded to five attempts, two seconds between attempts, and applies
only when both statuses are 200/404/503. 401/403/400/429 and other statuses block
without retry. Each request retains the existing transport timeout, no redirects,
loopback-only boundary and credentials. No config writes, alternative API key,
permission escalation, container logs or corrective API fallback.

Both endpoints must still return 200, and every original configuration/MUST check
must then pass before the first authorization request. OAuth case functions,
oracles and real code-expiry timing are byte-for-byte unchanged. This is not a
FusionAuth failure, K1 PASS, or demonstrated runtime resolution of the root cause.

## Interpretation of the next manually authorized run

- 200 with expected objects: resource existence established; original field
  validation must still pass. Does not independently prove every kickstart step.
- 404 then 200: readiness delay supported by observed transition.
- Persistent 404: missing resources/partial kickstart remain candidates.
- 401/403: API authentication/scope denied; not proof which underlying cause.
- 400 or config mismatch: stop for exact configuration analysis; do not relax MUST.
- 5xx/transport error: infrastructure/server state, not OAuth rejection.

Complete kickstart completion remains UNKNOWN until appropriate runtime evidence;
no automatic extra execution is authorized. This commit prepares that observation.

## Validation / preserved evidence

Six offline observer tests PASS: success, authorization denial without retry,
readiness transition, bounded absence, response-value non-disclosure, transport
failure. Python syntax and unchanged OAuth-function AST/source checks PASS.
No network/AS requests in these tests. Dependencies, lock, artifact hashes,
installer/audit, setup/kickstart, runner, workflow, images and normative documents
are unchanged. Inventory and secret-pattern/manual delta review PASS.

GitHub executor/PostgreSQL/dependency integrity/audit/API compatibility/cleanup
PASS from run #5 remain accepted evidence, not new executions. Actions and K1
were not executed. NEW AUTH CAPABILITIES: OFF. Private Frida untouched.

Publication status: READY for a separately approved manual K1 attempt with bounded
configuration diagnostics; historical run #5 remains BLOCKED / K1 NOT_RUN.
