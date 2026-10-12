# Minimal workflow startup correction — 2026-10-12

Base: `d6ba4b286b0dd53c513c5a4d15356fe333a2fcb4`.
Direction reported manual run #4 stopped before jobs with
`Unrecognized named-value: 'job'` at `job.services.postgres.id`.
Classification: **FUSIONAUTH PROOF BLOCKED — WORKFLOW_STARTUP_DEFECT**.
This is not a FusionAuth failure. K1 remains NOT_RUN.

## Exact correction

- Remove job-level `env.PROOF_POSTGRES_ID`.
- Provide `PROOF_SERVICE_NETWORK: ${{ job.services.postgres.network }}` only in
  the execution step's `env`, where the `job` context is supported.
- Use that exact network for the harness-created FusionAuth container. Reject
  missing/empty network; no container lookup, network guessing or discovery.
- Remove PostgreSQL ID access, `docker inspect` and PostgreSQL deletion from
  the harness. GitHub Actions owns its declared PostgreSQL service/network and
  runner lifecycle. No PostgreSQL absence is claimed by harness cleanup.
- Own cleanup continues to remove only the exact FusionAuth container name and
  private directory. No Docker-wide prune. The always-cleanup step is preserved.
- README/safety cleanup description corrected; inventory regenerated.

The PostgreSQL service block, image and digest are unchanged. FusionAuth 1.69.3,
its image/digest, setup, dependency pins/lock/artifact hashes, dependency gate,
K1 cases, O20-PKCE and N01–N54/K1–K6 are byte-for-byte unchanged.
The prior dependency evidence is preserved without rerunning it.

## Static verification

- YAML parsed successfully using existing PyYAML 6.0.3 BaseLoader (preserves `on`).
- Explicit context checks detect the old job-level defect and accept the new
  step-level expression; all other expressions (`github`, `inputs`, `always()`)
  are unchanged and valid at their existing locations.
- Python AST syntax PASS. No `PROOF_POSTGRES_ID`, container inspection or
  PostgreSQL deletion remains in the runner.
- Service block compared structurally to the base: identical.
- All existing files outside the four explicitly edited workflow/runner/docs
  files compared by SHA-256: unchanged (inventory regenerated separately).
- Publication inventory/secret-pattern checks PASS; manual review of the delta
  finds no secrets or private data. No new dependency or external service.

Primary GitHub context reference (read 2026-10-12):
https://docs.github.com/en/actions/reference/workflows-and-actions/contexts

The availability table excludes `job` from `jobs.<job_id>.env` and includes it
in `jobs.<job_id>.steps.env`. The job reference documents
`job.services.<service_id>.network` as the service network ID.

These are static checks, not a hosted Actions startup PASS. No Actions, Docker
services, dependency installation or K1 was executed for this correction.
Workflow remains exclusively workflow_dispatch, standard public ubuntu-24.04,
read-only repository permission, same PostgreSQL service, no paid services or secrets.
Direction must approve the new SHA before manual execution.

NEW AUTH CAPABILITIES: OFF. Private Frida and all other systems untouched.
