# Spec: Recon Scope Authorization Verification

## Objective

Add a fail-closed authorization gate for Recon targets. An operator may submit
a domain only after ZeroTrace has a durable, expiring authorization record.
Development and synthetic fixtures remain available without public network
access; real network profiles require a verified domain-control challenge or a
human-approved isolated-lab record.

This slice proves control of a target. It does not crawl web paths, exploit
services, generate remediation, or broaden scanner capabilities.

## Approved authorization methods

### Domain-control challenge

1. Create a one-time random challenge for a normalized domain.
2. Verify it through an exact DNS TXT record at
   `_zerotrace-challenge.<domain>`.
3. Store only a digest of the challenge, verification method, verified domain,
   owner, creation time, and expiry.
4. Consume the challenge so it cannot be replayed.

The verifier must use an injected DNS resolver boundary in tests. Production
resolution supports the configured system resolver by default and an opt-in
allowlisted DNS-over-HTTPS endpoint. It must not accept redirects, arbitrary
URLs, or credentials.

### Explicit lab authorization

An operator may create a synthetic or isolated-lab authorization record when a
human has confirmed ownership or written permission. The record contains the
target, owner, permitted profile IDs, environment, approval reference, and
expiry. No authorization document, credentials, or sensitive evidence is
stored in source code or scan payloads.

## Contract

- Domains are normalized before challenge creation or comparison.
- Credentials, paths, query strings, fragments, IP literals, and malformed
  hostnames are rejected by this domain-verification flow.
- Challenges expire after a bounded lifetime and are single-use.
- Verification is exact-domain by default; child-domain access requires an
  explicit scope rule and must not be inferred from a parent domain.
- A scan requires an active authorization matching the authenticated owner,
  target, profile, environment, and expiry.
- Failed verification never creates an active authorization.
- Verification and authorization errors expose generic public messages.
- No scanner is executed by the authorization verifier.

## Threat model and controls

| Threat | Control |
|---|---|
| User claims a third-party domain | DNS TXT proof or human-approved lab record |
| Challenge replay | Random challenge digest, expiry, and single-use consumption |
| Cross-scope scanning | Exact target/profile/owner/expiry checks before adapter invocation |
| SSRF through verification | DNS-only resolver interface; no user-controlled HTTP fetch |
| Sensitive authorization leakage | Store metadata and digests only; generic errors |
| Unbounded verification attempts | Per-domain and per-owner bounded attempt policy |

## Commands

Focused tests:

```powershell
py -m unittest tests.test_scope_authorization -v
```

Full regression:

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```

## Project structure

- `app/recon_authorization.py` — challenge and authorization contracts.
- `tests/test_scope_authorization.py` — synthetic resolver and negative tests.
- `docs/SPEC-scope-authorization.md` — approved authorization boundary.
- `tasks/plan.md` and `tasks/todo.md` — implementation and gate tracking.

## Testing strategy

Use Python `unittest` with synthetic DNS responses only. Cover normalization,
challenge expiry, replay rejection, wrong-record rejection, malformed target
rejection, explicit lab authorization, owner/profile/expiry enforcement, and
no-adapter-invocation on failed authorization. No public DNS or external site
is contacted by automated tests.

## Boundaries

- **Always:** normalize and validate input; use bounded, expiring,
  single-use challenges; enforce owner/profile/expiry before scanning; keep
  errors generic; use synthetic resolver fixtures.
- **Ask first:** production DNS provider integration, persistent authorization
  migration, child-domain authorization rules, or any real network check.
- **Never:** treat a submitted URL as proof of ownership; fetch arbitrary URLs
  to verify control; scan before authorization; store credentials or raw
  authorization documents.

## Success criteria

- The focused authorization suite passes with all negative cases.
- An authorization cannot be replayed or used after expiry.
- A scan target cannot be used by a different owner or unapproved profile.
- Failed verification causes no adapter invocation and no active scope.
- Full Phase 0–6 regression remains green.

## Open questions

- Which allowlisted DoH endpoint should be enabled in deployment configuration?
- Should the application support explicit child-domain authorization, or exact
  domains only?
- Which persistent table should hold authorization metadata when PostgreSQL
  integration is enabled?
