# Structured HTTP 400 diagnosis — 2026-10-12

Base: `0c255850352b414e672f49f129e2de48495f472e`.
Direction's accepted run #6 evidence: both configuration GETs returned HTTP 400,
JSON objects and structured errors. K1 NOT_RUN, cases empty, transport empty.
Classification remains CONFIG_READBACK_HTTP, not a FusionAuth rejection.
Actual error codes/field names are not present in the prior report. Root cause,
tenant/application existence and full Kickstart completion remain UNKNOWN.

## Static setup/readback review for the pinned 1.69.3

| Surface | Finding | Limit |
|---|---|---|
| Kickstart key | `apiKeys: [{key: ...}]`; generated once with token_urlsafe(48), reused unchanged by readback. Documentation allows a string key, not only UUID/hex. | Does not prove the key was created at runtime. |
| Key authority | First bootstrap key is global; no tenant lock or endpoint restrictions configured. Raw key in Authorization follows API-key authentication. No Basic/Bearer conversion needed. | 400 is not proof that authentication succeeded. |
| Tenant header | X-FusionAuth-TenantId is an optional supported scope on these two retrieve APIs; syntactically valid fixture UUID, matching the requested tenant. | A syntactically valid UUID does not prove that tenant exists. |
| Application GET | `/api/application/{applicationId}` is the documented single-object endpoint. | No response-object evidence yet. |
| Tenant GET | `/api/tenant/{tenantId}` is the documented single-object endpoint. | Do not confuse it with global-only tenant-search APIs. |
| Bootstrap ordering | Signing key → tenant → application in that tenant → synthetic user/registration in that tenant. | Every prior write must succeed; none of their actual statuses was captured. |

Expected intermediate results: a key at the fixed key ID; a tenant referring to
that key; an application referring to the tenant/key with the unchanged OAuth/JWT
settings; then the synthetic registration. Top-level tenantId appears only on the
application and registration requests. No code changes to this sequence, key,
headers, endpoints or configuration are justified by the current evidence.

The review uses current official API documentation and the release entry for
1.69.3 (2026-09-28). It is not execution of version 1.69.3 or a source-code audit
of its private server implementation. The 1.69.3 release note concerns passwordless
URL encoding, not an announced change to these readback contracts. No demonstrated
inability to configure a K1 MUST was found.

## Bounded observability delta

Only HTTP 400 records gain a `validation` projection:
- separate fieldErrors/generalErrors presence;
- scope, reviewed field name, reviewed stable code, validation category;
- message presence only; messages omitted unconditionally;
- malformed/truncated flags, at most 16 error records.

Output codes and fields are selected by exact membership in closed constant sets.
There is no regex accepting arbitrary server identifiers. Unknown strings become
UNREVIEWED_CODE / UNREVIEWED_FIELD with UNKNOWN category; they are neither logged
nor hashed. Categories describe a recognized code, not an independently established
root cause. No full body, headers, interpolated error messages or error data escape.
The vocabulary is a diagnostic output filter, not an advisory/security allowlist.

If an unreviewed code is encountered, diagnosis remains incomplete. It cannot
be interpreted as PASS or trigger a configuration repair. No extra request,
endpoint, retry policy, setup mutation or dependency change was introduced.

## Checks and delivery boundary

Ten offline observer tests PASS, including exact known code/field extraction,
unknown strings/embedded markers suppressed, malformed structures and output cap.
Python syntax PASS. All base files except the observer and its test are unchanged
before adding this document and regenerating inventory. K1 source, Kickstart,
workflow, runner, pinned images, dependencies, O20-PKCE/N01–N54/K1–K6 unchanged.
Publication inventory and manual/automated secret review PASS.

Executor, PostgreSQL, clean install/integrity/audit/import compatibility and cleanup
remain accepted historical evidence, not rerun. No Actions, K1 or provider request.
No private Frida modification. NEW AUTH CAPABILITIES OFF.

This delivery is READY only for a separately authorized manual diagnostic attempt.
It fixes the visibility gap; it does not claim the underlying HTTP 400 is resolved.
Any later substantive configuration correction must be proposed to Direction first.

## Primary sources

- https://fusionauth.io/docs/get-started/download-and-install/development/kickstart
- https://fusionauth.io/docs/apis/authentication
- https://fusionauth.io/docs/apis/applications/retrieve-an-application
- https://fusionauth.io/docs/apis/tenants/retrieve-a-tenant
- https://fusionauth.io/docs/apis/errors
- https://fusionauth.io/docs/release-notes
- https://github.com/FusionAuth/fusionauth-site/blob/main/astro/src/content/docs/apis/_shared/_x-fusionauth-tenant-id-header-scoped-operation.mdx
- https://github.com/FusionAuth/fusionauth-site/blob/main/astro/src/content/docs/apis/_shared/_tenant-authentication.mdx
