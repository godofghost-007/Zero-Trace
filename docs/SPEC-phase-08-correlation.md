# Phase 8 Specification — Correlation Completeness

## Purpose

Phase 8 turns normalized Recon services and Intel vulnerability facts into
reviewable findings without treating uncertain matches as confirmed exposure.
The phase is limited to deterministic correlation and evidence; it does not
perform scanning, remediation, or model inference.

## Contract

- Exact normalized CPE matches are `exact_cpe` with confidence `1.0`.
- Vendor/product/version matches are `vendor_product_version` with confidence
  `0.8` only when exactly one candidate exists.
- Ambiguous, incomplete, or stale matches are retained as uncertain evidence or
  rejected from confirmed findings; they must not silently become exposure.
- Every finding carries CVE, service, asset, match method, confidence, evidence,
  freshness, priority formula version, and source revision.
- Missing CVSS, EPSS, or KEV values remain explicit and are not converted to
  zero without a documented policy.
- Scope and tenant ownership are enforced before a finding is returned.
- Pagination is bounded and deterministic.

## Acceptance criteria

1. Exact, unique fallback, ambiguous, stale, and missing-version cases have
   focused tests.
2. Correlation output is deterministic for the same facts and services.
3. Uncertain matches are reviewable and distinct from confirmed findings.
4. PostgreSQL persistence preserves evidence and source provenance.
5. API responses use the shared error envelope, scope isolation, and bounded
   pagination.

## Verification

```powershell
py -m unittest discover -s tests -v
py -m compileall -q app scripts
docker compose --profile core config --quiet
docker compose --profile full config --quiet
docker compose --profile dev config --quiet
git diff --check
```

## Out of scope

- Arbitrary public-target scanning.
- Universal authorization bypasses.
- Automatic remediation.
- XGBoost or LLM-based matching.
