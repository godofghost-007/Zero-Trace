# ZeroTrace Flask Connectivity — Outcomes

This is a local integration demo. It uses synthetic data only; it is not a production cyber-defense service.

## Outcome 1 — Flask control API and frontend connection
- [ ] Implement a Python Flask app factory and `/api/v1` JSON API for health, readiness, shared demo state, reset/step actions, event list, asset inventory, Intel match/queue, Guard status/events/audit verification, and readiness summary/history.
- [ ] Keep React as the UI and connect all five routes through same-origin API calls; Vite development proxy routes `/api/v1` to Flask, and the production container serves the UI and API together.
- [ ] Show backend loading/connection/error status and truthful persisted/outbox states; do not silently fall back to browser fixtures when the API is unavailable.

## Outcome 2 — Persisted relational state and event delivery
- [ ] PostgreSQL is the Compose canonical store for demo scenario, shared asset/service/finding records, Guard metadata, score snapshots, and outbox events. SQLite is the no-Docker development fallback selected by `DATABASE_URL`.
- [ ] Recon → Intel → Guard scenario mutations persist shared stable IDs and correlation ID in the backend so every view displays the same asset, finding, event and score.
- [ ] Persist each domain state change and its event-outbox row in one database transaction. Relay events to Valkey/Redis Streams when configured; if the bus is unavailable, leave records pending and provide an explicit retry/status path—never claim they were consumed.
- [ ] Keep PostgreSQL and Valkey ports internal to Compose; bind the app to `127.0.0.1` on the host by default.

## Outcome 3 — Independent Guard audit chain
- [ ] Append simulated Guard decision metadata to a separate SQLite file using sequence number, event ID, asset ID, finding ID, correlation ID, timestamp, previous hash, and SHA-256 hash.
- [ ] Provide a chain-integrity verification API and surface its result in Trace Guard. Do not write raw prompts, responses, secrets or API keys to the audit record.
- [ ] Explain that hash chaining detects record changes relative to the chain/checkpoint but does not prevent privileged whole-file deletion.

## Outcome 4 — Safe engine behavior and explicit limits
- [ ] Recon and Intel button actions create deterministic synthetic backend records only; no Subfinder, Nmap, DNS, NVD, EPSS, KEV, XGBoost or Ollama calls occur.
- [ ] Guard records a simulated policy decision only; do not enable a real LLM upstream proxy, ONNX inference, API-key issuance, prompt/response retention, or outbound request.
- [ ] Remediation remains proposal-only; no generated script or host change is executed.
- [ ] Keep the score equation/version, component coverage and zero-denominator semantics explicit; preserve the documented discrepancy where the source prints 71 but the stated equation yields 73 for `(20,35,25)`.

## Outcome 5 — Local developer and Compose handoff
- [ ] Provide pinned Python dependencies, backend tests, Vite proxy configuration, a Flask production entrypoint, and a Docker Compose file for Flask + PostgreSQL + Valkey.
- [ ] Preserve the existing project Preview port 3000 and static WebDev feature settings; do not enable managed Server/Database, publish, or place backend secrets in frontend configuration.
- [ ] Verify backend API integration against SQLite in this Sandbox; document that Compose/PostgreSQL/Valkey cannot be run here if Docker remains unavailable.
