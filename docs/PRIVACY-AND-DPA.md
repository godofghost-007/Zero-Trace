# Privacy, retention, and DPA notes

This document describes the data a self-hosted ZeroTrace deployment can hold.
It is a technical inventory, not legal advice. An operator that processes
personal data for other people needs its own privacy review and, where
applicable, a data-processing agreement.

## Data inventory

| Data | Where | Purpose | Default retention |
|---|---|---|---|
| Operator account, email, password hash | PostgreSQL / SQLite BFF | Authentication | Life of account |
| TOTP secret, encrypted | PostgreSQL / SQLite BFF | MFA | Life of account |
| Session metadata: IP, user agent, timestamps | PostgreSQL / SQLite BFF | Session inventory and revocation | Session TTL |
| Auth audit events | PostgreSQL / SQLite BFF | Security evidence | 365 days recommended |
| Scope targets and authorization | PostgreSQL / SQLite | Bounded scan authorization | Until expired plus 30 days |
| Scan results, assets, services | PostgreSQL / SQLite | Operator evidence | 90 days recommended |
| Guard inspection counters | PostgreSQL / SQLite | Abuse detection | 30 days |
| Guard audit JSONL, if enabled | Host filesystem | Security evidence | 90 days recommended |
| Intel feed snapshots | PostgreSQL / SQLite | Vulnerability enrichment | Replaced on refresh |
| Encrypted backups | Off-host storage | Recovery | 30 days, 7 minimum copies |
| Application logs | Container stdout / log driver | Operations | Per log driver |

## What ZeroTrace does not collect by default

- No public signups, billing records, or per-tenant quotas in v1.
- No end-user prompt or response content in the Guard audit log. The audit
  publisher records metadata such as model, upstream, client, and block reason.
- No telemetry phone-home. The self-hosted deployment does not send usage data
  to the project maintainers.
- No scan traffic to a target outside an approved, unexpired scope.

## Residency

The operator chooses the VPS, the PostgreSQL provider, and the model provider.
Data residency is therefore a deployment decision, not a ZeroTrace default.
Document the region for:

- the BFF and engine host;
- the PostgreSQL primary and backups;
- the object storage or off-host backup destination;
- the Guard upstream provider.

A model provider may process prompts in another region. Do not route personal
data through Guard unless the provider's terms and the operator's DPA allow it.

## Retention and deletion

- `python -m scripts.prune_runtime_data` removes old terminal scans, Guard
  counters, readiness snapshots, and disabled schedules. It defaults to a dry
  run and requires `--apply` to delete.
- The audit hash chain is immutable by design. Do not delete rows from the
  middle of the chain. Rotate the audit database and archive the encrypted
  file instead.
- Backups are pruned with `python -m scripts.backup_database prune`. The newest
  copies are always retained.
- Account deletion is an operator procedure: disable the account, revoke
  sessions, remove OIDC identities and reset tokens, then delete the account
  row after the audit retention period. The current UI does not expose a
  one-click erasure flow.

## Guard and model providers

- The BFF authenticates to Guard; Guard authenticates to the provider.
- The provider key is held only by Guard.
- The BFF should be egress-restricted so it cannot call the provider directly.
- Guard blocks or redacts detected PII in responses. It does not scan every
  prompt for PII by default because prompts may legitimately contain data the
  operator needs the model to process.
- A provider's own retention, training, and subprocessor terms apply. Review
  them before production use.

## Subprocessors

The self-hosted project itself has no subprocessors. The operator's deployment
may use:

- a VPS or cloud host;
- a PostgreSQL provider (for example Supabase);
- an object-storage or backup provider;
- a model provider;
- an email or pager provider for alerts.

List these in the operator's own DPA and privacy notice.

## DPA checklist

- [ ] Identify the controller and processor roles.
- [ ] List the data categories and the purpose of processing.
- [ ] Record the regions for hosting, backups, and model inference.
- [ ] Record retention periods and deletion procedures.
- [ ] List subprocessors and require notice of changes.
- [ ] Define breach notification timing.
- [ ] Define assistance with data-subject requests.
- [ ] Define return or deletion of data at contract end.
- [ ] Record the security measures: TLS, MFA, RBAC, audit, encryption at rest,
      encrypted backups, and loopback-only engine access.

## Honest gaps

- No automated data-subject export or erasure endpoint.
- No per-tenant isolation, so a multi-tenant DPA is out of scope for v1.
- No live DPA or legal template was reviewed by counsel.
- No production deployment has exercised the retention job against a real
  PostgreSQL instance.
