# Isolated FusionAuth proof — publication candidate

Intended repository: `yacarex/frida-auth-proof`, PUBLIC. This is not Frida source.
State: **FUSIONAUTH PROOF BLOCKED — repository creation/access required**.
No public commit exists for this package yet. No runner or Auth test has run.

## Frozen contract

FusionAuth **1.69.3**, **O20-PKCE**, [N01–N54](docs/NORMATIVE_MATRIX.md),
[K1–K6](docs/KNOCKOUT_PROFILE.md), [harness plan](docs/HARNESS_PLAN.md).
Specifications are publication-sanitized copies of approved normative material.
No requirement row was changed. Historical Android package/certificate metadata
and private documentation links are omitted. N03 remains the unselected mode;
it cannot replace N02 after a failed test.

`NEW AUTH CAPABILITIES: OFF`. No production code, SDK integration, migrations,
APK, tenants, private configuration, old logs or other provider proofs included.
Prior evidence identity stays in manifest; its private contents are not copied.

## Publication and execution gates

1. Create the public repository with a README initial commit and grant the
   existing GitHub connection access. No new token or secret is needed in chat.
2. Publish exactly the reviewed files in `PUBLIC_INVENTORY.json` plus the inventory
   itself. Do not upload the working parent directory or a private repository.
3. Independently read back the public tree, file hashes, public visibility and
   `.github/workflows/fusionauth-k1.yml`; record the exact public commit.
4. Report PUBLIC_PROOF_REPOSITORY_READY_FOR_K1 only after those checks succeed.
5. Dispatch manually with `reviewed_sha` equal to that exact commit.

The workflow has no automatic trigger. It rejects a different repository,
private visibility or mismatched reviewed SHA before provisioning its job.
It uses the standard `ubuntu-24.04` public runner and a PostgreSQL service container.
No larger runner, cache, upload-artifact, cloud service, external credential,
billing operation or package registry publication is configured. Only sanitized
JSON goes to job logs/summary. GitHub documents standard public runners as free;
logs and summaries do not consume artifact storage. See [safety](docs/SAFETY_REVIEW.md).

## K1 implementation boundary

This package prepares K1 only. K2–K6 remain NOT_RUN and will be prepared/executed
in order only if K1 passes, under the existing authorization. K1 PASS is not
FUSIONAUTH KNOCKOUT PASS or consumer acceptance.

K1 uses synthetic password authentication solely to obtain independent codes;
it does not establish passwordless, verified email, recovery or mobile UX.
Callback URLs are reserved `.invalid` HTTPS addresses, intercepted in memory:
no DNS, callback server, bearer in URL, native secret, or real mailbox.
Issuer HTTP is loopback-only inside the isolated test runner, not a production
transport recommendation or a physical Android PASS.

Application PKCE policy is the documented `Required`; S256 is sent on every K1
attempt. Server downgrade resistance belongs to K2 and is not inferred here.
An engine-generated client secret, if returned by configuration APIs, remains
unused and unpublished. The Native client never submits a secret.

The transport observer captures PreparedRequest fields immediately before send.
Values of codes, verifier/challenge, nonce/state and cookies are never recorded.
No HTML, request dumps, browser traces, raw token responses or container logs.
HTTP errors/timeouts/unrecognized login pages produce BLOCKED, not a fake PASS.
Malformed negative responses do not erase evidence that a token was issued.

Dependency versions are proposed exact pins using the prior isolated Python
inventory plus OAuthlib. This candidate has only syntax/static review: dependency
installation, isolated audit, AS startup and functional checks are NOT_RUN.
Runtime dependency audit must be completed before accepting the executable
candidate; publication safety is a separate gate. Do not assume old dependency
evidence covers a new graph. No dependency from the private Frida tree is changed.

## Cleanup

Credentials are randomly generated on the runner and held in a private temporary
directory. They are not repository secrets. PostgreSQL bootstrap uses trust only
inside the isolated service network, with no host ports; no persistent/public DB.
FusionAuth alone exposes loopback port9011. Container logging is disabled.
Cleanup removes only this run's named container, PostgreSQL service and anonymous
volumes, plus private files/venv; it reports absence. `finally` and an always step
cover failures; GitHub destroys the hosted runner after cancellation/termination.
No Docker-wide prune, production resource or remote Frida write.

## Remaining limits

No public readback or public SHA can be accredited before repository creation.
Connection cannot create repositories or dispatch workflows. Manual dispatch
may be required later; do not dispatch before the publication gate report.
The K1 HTTP form driver is not browser/Android proof. Unclassified AS error HTML
is explicitly inconclusive and may require a narrowly scoped observer correction.
No external license/account is acquired. If the AS requires one, stop before it.
