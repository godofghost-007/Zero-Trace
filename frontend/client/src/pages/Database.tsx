import { useState } from "react";
import { ArrowRight, Database as DatabaseIcon, FileKey2, GitBranch, HardDrive, Layers, Workflow } from "lucide-react";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { useZeroTraceDemo } from "@/lib/zeroTraceDemo";

type EventItem = { id: string; type: string; entityType?: string; entity: string; source: string; correlation: string; at: string; status: "pending" | "published"; lastError?: string | null; redisEntryId?: string | null };
type EventResponse = { items: EventItem[]; pending: number; bus: { state: string; configured: boolean; connected: boolean } };
type HistoryResponse = { items: Array<{ id: string; stage: number; score: number | null; aei: number | null; vui: number | null; aiet: number | null; formulaVersion: string; calculatedAt: string }> };

const plannedEvents = [
  { type: "asset_created", source: "Recon → Intel", description: "Asset record is committed with the same stable ID.", stage: 1 },
  { type: "vuln_matched", source: "Intel → Guard", description: "Synthetic service-vulnerability evidence is linked.", stage: 2 },
  { type: "attack_blocked", source: "Guard → Readiness", description: "Decision metadata is saved; prompt text is excluded.", stage: 3 },
  { type: "score_snapshot", source: "Readiness → shared views", description: "Formula-versioned exposure indexes are snapshotted after each step.", stage: 1 },
  { type: "vuln_patched", source: "Future workflow", description: "Approved remediation and verification rescan are not implemented.", stage: 4 },
];
const tableRows = [
  ["demo_scenario", "stage · correlation_id · updated_at", "Shared"],
  ["assets", "asset_id · hostname · scope_id · services JSON", "Recon"],
  ["vulnerabilities", "finding_id · CVSS · EPSS fixture · CPE", "Intel"],
  ["service_vulnerabilities", "asset_id · finding_id · evidence · review_state", "Intel"],
  ["score_snapshots", "AEI · VUI · AIET · formula_version", "Shared"],
  ["event_outbox", "event_id · type · schema · status · correlation", "Shared"],
  ["guard_events", "outcome · asset/finding IDs · audit pointer", "Guard"],
];

type Tab = "records" | "events" | "score";
export default function Database() {
  const [tab, setTab] = useState<Tab>("records");
  const { stage, events, audit, readiness, backend, asset, finding } = useZeroTraceDemo();
  const refreshKey = `${stage}:${events.length}`;
  const eventQuery = useApiResource<EventResponse>("/events?limit=100", refreshKey);
  const historyQuery = useApiResource<HistoryResponse>("/readiness/history", refreshKey);
  const displayedEvents = eventQuery.data?.items ?? events;
  const latestEvent = eventQuery.data ? eventQuery.data.items[0] : events.at(-1);
  const pendingCount = eventQuery.data?.pending ?? backend.eventBus.pending;
  const latestSnapshot = historyQuery.data?.items.at(-1);
  const scoreBand = readiness.score === null ? "AWAITING COVERAGE" : readiness.score >= 90 ? "SECURE BAND" : readiness.score >= 70 ? "MODERATE BAND" : "ELEVATED";

  return <>
    <PageHeading eyebrow="DATA PLANE / 01" title="One source of truth. Separate evidence." description="The API persists shared operational state in the active database, queues events transactionally, and stores Guard's hash chain in a separate SQLite file." actions={<StateTag tone={backend.databaseConnected ? "green" : "red"}>{backend.database.toUpperCase()} · API {backend.databaseConnected ? "CONNECTED" : "OFFLINE"}</StateTag>} />
    <div className="data-banner"><DatabaseIcon size={18} /><span><b>PostgreSQL is the Docker Compose target · {backend.database.toUpperCase()} is active now</b><small>Valkey/Redis carries notifications from a durable outbox. Guard's audit file remains outside PostgreSQL and is verified separately.</small></span></div>

    <div className="tab-bar" role="tablist" aria-label="Database demo views">
      {(["records", "events", "score"] as const).map((item) => <button className={`tab-button ${tab === item ? "selected" : ""}`} key={item} onClick={() => setTab(item)} role="tab" aria-selected={tab === item}>{item === "records" ? <><Layers size={15} /> Shared records</> : item === "events" ? <><Workflow size={15} /> Event bus</> : <><GitBranch size={15} /> Readiness score</>}</button>)}
    </div>

    {tab === "records" && <div className="database-layout">
      <Panel title="Logical entity map" subtitle="Active SQL rows are marked; some conceptual platform tables remain future scope." tag={backend.database.toUpperCase()}>
        <div className="erd-map">
          <div className="erd-row"><Entity name="ASSET" fields="asset_id · scope_id · services JSON" active={!!asset} /><ArrowRight /><Entity name="SERVICE_VULNERABILITY" fields="asset · finding · confidence" active={stage >= 2} /><ArrowRight /><Entity name="VULNERABILITY" fields="synthetic CVSS · EPSS · CPE" active={!!finding} /></div>
          <div className="erd-branch"><span className="branch-line" /><span className="branch-label">events and snapshots share correlation_id</span></div>
          <div className="erd-row erd-row-secondary"><Entity name="DEMO_SCENARIO" fields="stage · correlation_id" active /><Entity name="SCORE_SNAPSHOT" fields="AEI · VUI · AIET · formula version" active={!!latestSnapshot} /><Entity name="EVENT_OUTBOX" fields="payload · pending/published" active={events.length > 0} /><Entity name="GUARD_EVENT" fields="result · SQLite audit pointer" active={stage >= 3} /></div>
        </div>
      </Panel>
      <Panel title="Table inventory" subtitle="What the connected prototype actually persists." tag="MODEL MAP">
        <div className="record-list">{tableRows.map(([name, columns, owner]) => <div className="record-row" key={name}><CodeLabel>{name}</CodeLabel><span>{columns}</span><StateTag tone={owner === "Recon" ? "blue" : owner === "Intel" ? "amber" : owner === "Guard" ? "red" : "green"}>{owner}</StateTag></div>)}</div>
      </Panel>
      <Panel title="Separate audit store" subtitle="Guard audit chain is not an ordinary SQL table." tag="SQLITE / LOCAL FILE" className="wide-panel">
        <div className="audit-separation"><div className="audit-icon"><HardDrive size={20} /></div><div><b>guard-audit.sqlite · {backend.audit.entries} record(s)</b><p>Flask appends sequence, event/asset/finding/correlation IDs, outcome, previous hash and SHA-256 row hash. The verifier reports {backend.audit.valid ? "a valid chain" : `a chain break at row ${backend.audit.broken_at}`}.</p></div><StateTag tone={backend.audit.valid ? "green" : "red"}>{audit.length ? "PERSISTED RECORD" : "NO RECORD YET"}</StateTag></div>
      </Panel>
    </div>}

    {tab === "events" && <div className="events-layout">
      <Panel title="Transactional outbox" subtitle={`Database rows persist first; the configured event bus is ${eventQuery.data?.bus.state ?? backend.eventBus.state}.`} tag={`${displayedEvents.length} EVENTS · ${pendingCount} PENDING`}>
        <div className="event-stream">{plannedEvents.map((event, index) => { const item = event.type === "score_snapshot" ? displayedEvents.filter((entry) => entry.type === event.type).at(-1) : displayedEvents.find((entry) => entry.type === event.type); const active = !!item; const status = !item ? (event.stage === 4 ? "NOT IMPLEMENTED" : "WAITING") : item.status === "published" ? "PUBLISHED · VALKEY" : "DB COMMITTED · BUS PENDING"; return <div className={`event-row ${active ? "event-active" : ""}`} key={event.type}><span className="event-index">0{index + 1}</span><div className="event-main"><div><CodeLabel>{event.type}</CodeLabel><small>{item?.source ?? event.source}</small></div><p>{event.description}</p>{item && <div className="event-meta"><span>{item.id}</span><span>{item.entity}</span><span>{item.correlation}</span></div>}</div><StateTag tone={active ? item?.status === "published" ? "green" : "amber" : "neutral"}>{status}</StateTag></div>; })}</div>
        <div className="contract-note"><FileKey2 size={16} /><span>Envelope: event_id · event_type · schema_version · entity_id · occurred_at · correlation_id · bounded payload. No prompt or credentials are included.</span></div>
      </Panel>
      <Panel title="Current persisted event" subtitle="Fictional, bounded metadata; the API omits raw Guard prompt content." tag="JSON / SAMPLE">
        <pre className="code-block">{JSON.stringify({ event_id: latestEvent?.id ?? "EVT-DEMO-PENDING", event_type: latestEvent?.type ?? "awaiting_scenario", schema_version: 1, entity_id: latestEvent?.entity ?? null, correlation_id: latestEvent?.correlation ?? "corr_demo_7a20", outbox_status: latestEvent?.status ?? "waiting", readiness: { snapshot_id: latestSnapshot?.id ?? null, score: readiness.score, aei: readiness.aei, vui: readiness.vui, aiet: readiness.aiet, formula_version: readiness.formulaVersion }, links: { asset: asset?.id ?? null, finding: finding?.id ?? null } }, null, 2)}</pre>
      </Panel>
    </div>}

    {tab === "score" && <div className="score-layout">
      <Panel title="Readiness score" subtitle="Three negative exposure indexes. Higher exposure lowers the score; zero denominators remain unknown." tag={readiness.score === null ? "COVERAGE INCOMPLETE" : `SNAPSHOT ${readiness.score.toFixed(0)}`}>
        <div className="score-formula">Score = clamp(100 − <b>0.40 × AEI</b> − <b>0.40 × VUI</b> − <b>0.20 × AIET</b>, 0, 100)</div>
        <div className="score-bars">{[["AEI", "Asset Exposure Index", readiness.aei, readiness.aei === null ? "No asset denominator yet" : "1 exposed / 5 synthetic services"], ["VUI", "Vulnerability Urgency Index", readiness.vui, readiness.vui === null ? "No asset denominator yet" : stage >= 2 ? "Illustrative risk index; not model output" : "0 matched / 1 observed asset"], ["AIET", "AI Threat Exposure Index", readiness.aiet, readiness.aiet === null ? "No request denominator yet" : "0 unblocked / 1 simulated blocked request"]].map(([key, label, value, hint]) => <div className="score-bar-row" key={String(key)}><div><b>{key}</b><span>{label}</span><strong>{value === null ? "—" : Number(value).toFixed(0)}<small>{value === null ? "unknown" : "/100"}</small></strong></div><div className="bar-track"><i style={{ width: `${Math.max(0, Math.min(100, Number(value ?? 0)))}%` }} /></div><small>{hint}</small></div>)}</div>
        <div className="score-result"><span>{latestSnapshot ? `LATEST SNAPSHOT · ${latestSnapshot.id}` : "CURRENT SIMULATED SCORE"}</span><strong>{readiness.score === null ? "—" : readiness.score.toFixed(0)}<small>{readiness.score === null ? "coverage pending" : "/100"}</small></strong><StateTag tone={readiness.score === null ? "neutral" : readiness.score >= 90 ? "green" : readiness.score >= 70 ? "amber" : "red"}>{scoreBand}</StateTag></div>
        <div className="score-history-note">Persisted snapshots: {historyQuery.data?.items.length ?? 0} · formula {readiness.formulaVersion} · current backend {backend.database}</div>
      </Panel>
      <Panel title="Arithmetic note" subtitle="The source's combined-case discrepancy is preserved." tag="SOURCE CAVEAT"><div className="caveat-box"><b>Combined fixture: 20 / 35 / 25</b><p>The documented equation calculates <strong>73</strong>; the original source table prints 71. The equation is shown as governing, and the conflicting printed example is not silently changed.</p><div className="equation-line">100 − (0.4 × 20 + 0.4 × 35 + 0.2 × 25) = 73</div></div><p className="muted-copy">The demo's intermediate indexes are illustrative. Unknown denominators do not silently become zero-risk; the overall score stays unavailable until all inputs exist.</p></Panel>
    </div>}
  </>;
}

function Entity({ name, fields, active }: { name: string; fields: string; active: boolean }) {
  return <div className={`entity-card ${active ? "entity-active" : ""}`}><span>{name}</span><small>{fields}</small><i>{active ? "PERSISTED SAMPLE ROW" : "NO ROW YET"}</i></div>;
}
