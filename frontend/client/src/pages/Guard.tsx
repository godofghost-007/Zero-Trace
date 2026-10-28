import { useState } from "react";
import { ArrowRight, Check, CircleAlert, Fingerprint, Hash, LockKeyhole, ScanText, Shield, ShieldCheck, TriangleAlert } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import type { GuardInspection } from "@/lib/liveEngine";
import { demoPrompt, useZeroTraceDemo } from "@/lib/zeroTraceDemo";

type GuardEventList = { items: Array<{ id: string; action: string; outcome: string; auditSequence: number; auditHash: string }> };
type AuditVerification = { store: string; valid: boolean; entries: number; broken_at: number | null; last_hash: string };
type GuardStatus = { mode: string; proxyEnabled: boolean; regex: string; onnx: string; upstream: string; piiScanner: string };

export default function Guard() {
  const { stage, audit, events, readiness, isProcessing, runGuard, isConnected, backend } = useZeroTraceDemo();
  const [showFullHash, setShowFullHash] = useState(false);
  const [guardText, setGuardText] = useState(demoPrompt);
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardResult, setGuardResult] = useState<GuardInspection | null>(null);
  const [guardError, setGuardError] = useState<string | null>(null);
  const eventKey = `${stage}:${events.length}`;
  const guardEvents = useApiResource<GuardEventList>("/guard/events", eventKey);
  const auditStatus = useApiResource<AuditVerification>("/guard/audit/verify", eventKey);
  const serviceStatus = useApiResource<GuardStatus>("/guard/status", eventKey);
  const blocked = stage >= 3;
  const enabled = stage >= 2 && isConnected;
  const last = audit.at(-1);
  const attackEvent = guardEvents.data?.items[0] ?? events.find((event) => event.type === "attack_blocked");
  const chainValid = auditStatus.data?.valid ?? backend.audit.valid;
  const inspectPrompt = async () => {
    setGuardBusy(true);
    setGuardError(null);
    setGuardResult(null);
    try {
      const result = await apiRequest<GuardInspection>("/engine/guard/inspect", {
        method: "POST",
        body: JSON.stringify({ text: guardText }),
      });
      setGuardResult(result);
    } catch (error) {
      setGuardError(error instanceof Error ? error.message : "The Guard inspection failed.");
    } finally {
      setGuardBusy(false);
    }
  };
  const pipeline = [
    ["01", "Client key + schema", "Synthetic local fixture; no real key accepted", enabled, "PASS"],
    ["02", "Regex / heuristic filter", "Instruction override signature", blocked, blocked ? "MATCH" : "READY"],
    ["03", "ONNX DistilBERT", "Illustrative confidence only · model not loaded", blocked, blocked ? "HIGH RISK" : "STAGED"],
    ["04", "Upstream proxy", "No upstream is configured or contacted", blocked, blocked ? "SKIPPED" : "WAITING"],
    ["05", "Response PII scan", "No response returned for blocked request", blocked, blocked ? "N/A" : "STAGED"],
    ["06", "SQLite audit append", "Separate local file · hash-chain checked by API", blocked, blocked ? "APPENDED" : "WAITING"],
  ] as const;
  return <>
    <PageHeading eyebrow="ENGINE / 04 · LLM TRAFFIC CONTROL" title="Trace Guard" description="Inspect a prompt with the live local detector, then review the simulated policy and audit scenario. No upstream model is contacted by the inspection." actions={<button className="button button-primary" onClick={() => void runGuard()} disabled={!enabled || blocked || isProcessing}><Shield size={16} />{blocked ? "Attack blocked" : isProcessing ? "Recording decision…" : enabled ? "Simulate prompt attack" : "Waiting for API / Intel"}</button>} />

    <Panel title="Live Guard inspection" subtitle="Runs the real prompt-injection and PII detectors. The prompt is inspected locally and is not forwarded." tag="INSPECT ONLY">
      <div className="field">
        <label htmlFor="guard-live-input">Prompt to inspect</label>
        <textarea id="guard-live-input" value={guardText} onChange={(event) => setGuardText(event.target.value)} rows={5} spellCheck={false} />
        <small>Up to 8,000 characters. The detector checks instruction override, jailbreak patterns, and PII.</small>
      </div>
      <div className="form-actions">
        <button className="button button-primary" type="button" onClick={() => void inspectPrompt()} disabled={guardBusy || !guardText.trim()}>
          <ShieldCheck size={15} />{guardBusy ? "Inspecting…" : "Inspect prompt"}
        </button>
      </div>
      {guardError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{guardError}</span></div>}
      {guardResult && <div className={`console-alert ${guardResult.blocked ? "" : "success"}`} role="status">
        {guardResult.blocked ? <Shield size={15} /> : <ShieldCheck size={15} />}
        <span>
          <b>{guardResult.blocked ? "Blocked" : "Allowed"}</b>
          {guardResult.reason ? ` · ${guardResult.reason}` : ""}
          {guardResult.details ? ` · ${guardResult.details}` : ""}
          {guardResult.pii.blocked ? " · PII detected" : " · No PII detected"}
        </span>
        <CodeLabel>{guardResult.mode}</CodeLabel>
      </div>}
    </Panel>

    <Panel title="Guard position" subtitle="Guard sits between the site or application AI and the user prompt. The live detector decides before any upstream call." tag="BETWEEN USER AND MODEL">
      <div className="kv-list">
        <div className="kv-row"><span>PATH</span><b>User prompt → Guard → allowlisted upstream</b><small>Blocked prompts never reach the model; allowed responses can be PII-scanned.</small></div>
        <div className="kv-row"><span>UPSTREAM</span><b>{serviceStatus.data?.upstream ?? "not configured"}</b><small>Self-hosters set an OpenAI-compatible model API through `.env.guard` or a secret manager. Keys never enter this page.</small></div>
        <div className="kv-row"><span>PROXY</span><b>{serviceStatus.data?.proxyEnabled ? "enabled" : "not running"}</b><small>Loopback-only Guard endpoint. The BFF holds the Guard credential server-side.</small></div>
        <div className="kv-row"><span>DETECTOR</span><b>{serviceStatus.data?.mode ?? "checking"} · ONNX {serviceStatus.data?.onnx ?? "not loaded"}</b><small>PII scanner: {serviceStatus.data?.piiScanner ?? "unknown"}.</small></div>
      </div>
    </Panel>

    <div className="guard-alert"><TriangleAlert size={18} /><span><b>Simulated policy outcome</b><small>This scenario does not contact the upstream. Only the decision metadata is sent to Flask; the test prompt is not sent.</small></span><StateTag tone={blocked ? "red" : "amber"}>{blocked ? "BLOCKED · DB + SQLITE" : enabled ? "READY · SIMULATED" : "WAITING FOR INTEL"}</StateTag></div>

    <div className="two-column guard-top-grid">
      <Panel title="Request under inspection" subtitle="OpenAI-compatible shape · harmless UI fixture; not forwarded." tag="SIMULATED REQUEST">
        <div className="request-meta"><span><LockKeyhole size={14} /> Client auth</span><b>{enabled ? "Synthetic key state · fixture" : "Not submitted"}</b><span>Endpoint</span><b>{enabled ? "endpoint_demo_01" : "Unlinked"}</b></div>
        <div className="prompt-card"><div><span>USER CONTENT</span><CodeLabel>TEST STRING · UI ONLY</CodeLabel></div><p>“{demoPrompt}”</p><small>Displayed locally for the example; it is not posted to the backend or an LLM.</small></div>
        {blocked && <div className="block-result"><ShieldCheck size={17} /><div><b>Request blocked before upstream</b><small>Reason: high-confidence instruction override pattern · simulated policy version 0.1-demo · {attackEvent?.id}</small></div><StateTag tone="red">BLOCKED · MOCK</StateTag></div>}
      </Panel>
      <Panel title="Detection pipeline" subtitle="The live detector runs locally. The proxy forwards only allowed prompts to the configured OpenAI-compatible upstream." tag={blocked ? "DECISION RECORDED" : "LIVE DETECTOR"}>
        <div className="guard-pipeline">{pipeline.map(([number, title, detail, complete, result], index) => <div className={`guard-step ${complete ? "guard-step-done" : ""}`} key={number}><span className="guard-step-number">{complete ? <Check size={13} /> : number}</span><div className="guard-step-copy"><b>{title}</b><small>{detail}</small></div><span className={`guard-result result-${result.toLowerCase().replaceAll(" ", "-")}`}>{result}</span>{index < pipeline.length - 1 && <span className="guard-step-line" />}</div>)}</div>
        <div className="api-detail">API status: {serviceStatus.data?.mode ?? "checking"} · proxy {serviceStatus.data?.proxyEnabled ? "enabled" : "not running"} · upstream {serviceStatus.data?.upstream ?? "not configured"} · PII {serviceStatus.data?.piiScanner ?? "unknown"} · ONNX {serviceStatus.data?.onnx ?? "not loaded"}</div>
      </Panel>
    </div>

    <div className="two-column guard-bottom-grid">
      <Panel title="Tamper-evident audit chain" subtitle="A dedicated SQLite file stores only decision metadata and correlation IDs." tag={`SEPARATE SQLITE · ${chainValid ? "VALID" : "TAMPER DETECTED"}`}>
        {last ? <div className="chain-card"><div className="chain-head"><div className="chain-icon"><Hash size={18} /></div><div><CodeLabel>SEQ {String(last.sequence).padStart(6, "0")}</CodeLabel><b>attack_blocked</b><small>{new Date(last.at).toLocaleString()} · persisted audit metadata</small></div><StateTag tone={chainValid ? "green" : "red"}>{chainValid ? "CHAIN VALID" : "CHAIN BROKEN"}</StateTag></div><div className="audit-correlation">{[["EVENT", last.eventId], ["ASSET", last.assetId], ["FINDING", last.findingId], ["CORRELATION", last.correlation]].map(([label, value]) => <div key={label}><span>{label}</span><code>{value}</code></div>)}</div><div className="hash-row"><span>PREVIOUS</span><code>{showFullHash ? last.previousHash : `${last.previousHash.slice(0, 20)}…`}</code></div><div className="hash-row"><span>SHA-256</span><code>{showFullHash ? last.hash : `${last.hash.slice(0, 24)}…`}</code></div><button className="text-button" onClick={() => setShowFullHash((value) => !value)}>{showFullHash ? "Collapse hashes" : "View full hashes"}</button><p className="small-warning"><CircleAlert size={14} />{auditStatus.data?.entries ?? backend.audit.entries} record(s) · data file can still be deleted by a privileged user; hashes are not a substitute for protected backups.</p></div> : <div className="empty-demo compact"><Fingerprint size={21} /><b>No audit row yet</b><p>After Intel is complete, the simulated blocked request will append a SHA-256-linked metadata row to the separate SQLite file.</p></div>}
      </Panel>
      <Panel title="Readiness effect" subtitle="Unknown components stay unknown until their denominator is observed." tag="EVENT → SNAPSHOT">
        <div className="readiness-effect"><div className="effect-icon"><ShieldCheck size={20} /></div><div><span>AI Threat Exposure Index (AIET)</span><b>{readiness.aiet ?? "—"}<small> / 100 · {readiness.aiet === null ? "unknown" : "simulated"}</small></b><p>The blocked sample is excluded from unblocked-attempt count. The API records a new snapshot; pre-Guard AIET stays unknown because there is no request denominator.</p></div></div><div className="event-chip"><span className="event-chip-dot" /><CodeLabel>attack_blocked</CodeLabel><ArrowRight size={14} /><span>PostgreSQL / SQLite score snapshot</span></div><div className="guard-note"><ScanText size={15} /><span>Response PII scanning is not invoked: this demo never obtains a model response. A production scanner runs only on allowed responses.</span></div>
      </Panel>
    </div>
    {stage < 2 && <div className="next-engine"><span><b>Sequence:</b> Recon first, then Intel matching, then this Guard simulation.</span><Link href={stage === 0 ? "/recon" : "/intel"} className="text-link">{stage === 0 ? "Open Trace Recon" : "Open Trace Intel"} <ArrowRight size={15} /></Link></div>}
  </>;
}
