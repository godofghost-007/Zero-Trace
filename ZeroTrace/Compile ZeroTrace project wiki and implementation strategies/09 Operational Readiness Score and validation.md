# Operational Readiness Score and validation

[← Wiki index](index.md) · Related: [Architecture](architecture.md) · [Intel](trace-intel.md) · [Guard](trace-guard.md)

## Governing equation

The v2.0 source defines three **negative exposure indexes**, each on a 0–100 scale:

```text
Score = clamp(100 - (0.40 × AEI + 0.40 × VUI + 0.20 × AIET), 0, 100)
```

- `AEI` — Asset Exposure Index = exposed services / total services × 100.
- `VUI` — Vulnerability Urgency Index = Σ(ML exploit probability × CVSS severity) / total assets × 100.
- `AIET` — AI Threat Exposure Index = unblocked attack attempts / total LLM requests × 100.

Clamp prevents out-of-range values. Define zero-denominator behavior explicitly: if no services or no LLM requests exist, report the component as `unknown` (and show coverage) rather than quietly assuming 0 risk. Normalize CVSS to 0–1 before multiplying by probability, or specify the exact scale; the source formula as written does not fully specify the units/scaling of VUI. Recommended: publish a formula version and keep component values, denominators and missingness alongside each snapshot.

The source corrected “AI Threat Block Rate” to “AI Threat Exposure Index” because better blocking should improve, not reduce, readiness. All inputs are adverse factors, so higher adverse indexes lower the score.

## Important source arithmetic inconsistency

For indexes `(20, 35, 25)`, the displayed equation gives `100 − (8 + 14 + 5) = 73`; the source table prints 71. The printed one-critical-CVE row `(0,35,0)` yields 86 and is consistent; the one-exposed-service row `(20,0,0)` yields 92; the unblocked-attack row `(0,0,25)` yields 95. The full-cycle sequence has further values not derivable from the supplied formula. The implementation should treat the equation as authoritative and correct fixture expectations to 73 unless the product owner formally revises the formula. The score is not an empirically calibrated probability.

## Interpretation bands (source)

| Score | Status | Operational meaning |
|---|---|---|
| 90–100 | Secure | Maintain posture; inspect component coverage |
| 70–89 | Moderate | Review queue and exposed services |
| 50–69 | Elevated | Prompt remediation and investigate active AI events |
| 0–49 | Critical | Incident response; isolate/patch as appropriate |

Bands communicate posture, not a guarantee of safety. Show the three component indexes, last-updated time, denominator/coverage and open critical findings alongside the headline score.

## Unit and property tests

| Scenario | AEI | VUI | AIET | Expected using equation | Validates |
|---|---:|---:|---:|---:|---|
| Fully secure baseline | 0 | 0 | 0 | 100 | Maximum score |
| One exposed MySQL port | 20 | 0 | 0 | 92 | Asset term |
| One critical CVE | 0 | 35 | 0 | 86 | Vulnerability term |
| One unblocked jailbreak | 0 | 0 | 25 | 95 | AI exposure term |
| All three combined | 20 | 35 | 25 | **73** | Weighted compound (source says 71; corrected by arithmetic) |
| After CVE is patched | 20 | 0 | 25 | 87 | Remediation recovery |
| After close port + patch | 0 | 0 | 25 | 95 | Recovery |

Properties: deterministic for identical versioned inputs; monotone non-increasing when any adverse component rises and others stay fixed; monotone recovery when a component improves; output bounded in `[0,100]`; scores reproducible from stored snapshot and formula version. Test rounding only at presentation layer.

## Evaluation test matrix

| Layer | Test | Pass target from source |
|---|---|---|
| Recon | Subdomain recall / precision | ≥90% / ≥95% |
| Recon | Nmap parity / S3 FP / FN / TLS expiry | 100% parity / ≤5% / ≤10% / 100% |
| Recon | 10 planted Shadow IT items / 50-subdomain scan duration | 10/10 / ≤10 min |
| Intel | XGBoost vs CVSS top-20 on 200 known-outcome CVEs | ≥15 exploited in top 20; compare to EPSS top-20 |
| Intel | CPE match / 48-hour NVD completeness | ≥90% / ≥99% |
| Intel | 30 auto-fix scripts success / safety | ≥70% syntactic test success / ≥95% safe |
| Intel | Top-20 patch queue vs KEV | ≥60% overlap |
| Guard | JailbreakBench regex / ONNX / combined catch | ≥60% / ≥85% / ≥92% |
| Guard | ShareGPT false positive rate | ≤5% |
| Guard | Seeded PII recall / clean PII false positives | ≥90% / ≤10% |
| Guard | End-to-end overhead; regex; ONNX | ≤50 ms; ≤5 ms; ≤20 ms |
| Guard | 100 requests / 10 seconds from one client | ≤10 processed |
| Score | Monotonicity, recovery, sensitivity, determinism | Decreases with adverse events, rises on remediation, proportional, zero variance |
| Integration | Recon→Intel; Intel→Guard; Guard→score; full cycle | CVE matched within 60 s; endpoint priority elevated; score responds; verify using equation and corrected fixtures |

The PDF specifies a 20 GB Dell/WSL2 test setup in its evaluation section while calling 16 GB the minimum elsewhere. Run a minimum-spec 16 GB profile in addition to source hardware; report RAM use, CPU model, model profile, tool versions, sample size and test seed.
