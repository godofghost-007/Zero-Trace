import { useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Database as DatabaseIcon,
  Download,
  FileKey2,
  GitBranch,
  Layers,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { downloadJson, safeFilename } from "@/lib/download";
import {
  type EngineScope,
  type FindingList,
  type IntelFinding,
  type Readiness,
  type TargetRecord,
  type TargetRecordList,
  type TargetScanRecord,
  takeoverSignal,
} from "@/lib/liveEngine";
import { useZeroTraceDemo } from "@/lib/zeroTraceDemo";

type EventItem = {
  id: string;
  type: string;
  entityType?: string;
  entity: string;
  source: string;
  correlation: string;
  at: string;
  status: "pending" | "published";
  lastError?: string | null;
  redisEntryId?: string | null;
  scopeId?: string | null;
  target?: string | null;
};
type EventResponse = { items: EventItem[]; pending: number; bus: { state: string; configured: boolean; connected: boolean } };
type HistoryResponse = { items: Array<{ id: string; stage: number; score: number | null; aei: number | null; vui: number | null; aiet: number | null; formulaVersion: string; calculatedAt: string }> };

type Tab = "records" | "events" | "score";
type Category = "nmap" | "subfinder" | "tls" | "synthetic";

const CATEGORY_LABELS: Record<Category, string> = {
  nmap: "Nmap",
  subfinder: "Subfinder",
  tls: "TLS metadata",
  synthetic: "Synthetic inventory",
};

const EXPOSED_PORTS = new Set([80, 443, 8080, 8443]);

function isExposed(service: TargetScanRecord["services"][number]): boolean {
  const product = (service.product ?? "").toLowerCase();
  return EXPOSED_PORTS.has(service.port)
    || product.includes("http")
    || product.includes("https")
    || product.includes("tls")
    || product.includes("ssl");
}

function uniqueServices(scans: TargetScanRecord[]) {
  return [
    ...new Map(
      scans
        .flatMap((scan) => scan.services)
        .map((service) => [
          `${service.asset}|${service.protocol}|${service.port}|${service.product ?? ""}|${service.version ?? ""}`,
          service,
        ] as const),
    ).values(),
  ];
}

function uniqueAssets(scans: TargetScanRecord[]) {
  return [...new Set(scans.flatMap((scan) => scan.assets))];
}

function uniqueTls(scans: TargetScanRecord[]) {
  return [
    ...new Map(
      scans
        .flatMap((scan) => scan.tlsFindings)
        .map((finding) => [
          `${finding.subject}|${finding.issuer}|${finding.expires_at}|${finding.status}`,
          finding,
        ] as const),
    ).values(),
  ];
}

function scansFor(record: TargetRecord | null, category: Category): TargetScanRecord[] {
  if (!record) return [];
  if (category === "nmap") return record.scans.filter((scan) => scan.profileId.startsWith("service_inventory"));
  if (category === "subfinder") return record.scans.filter((scan) => scan.profileId.startsWith("passive_subdomain"));
  if (category === "tls") return record.scans.filter((scan) => scan.profileId === "tls_metadata_v1");
  return record.scans.filter((scan) => scan.profileId === "synthetic_inventory_v1");
}

function bandFor(score: number | null): string {
  if (score === null) return "Coverage pending";
  if (score >= 90) return "Secure band";
  if (score >= 70) return "Moderate band";
  if (score >= 50) return "Elevated band";
  return "Critical band";
}

function scoreFor(record: TargetRecord | null, findings: IntelFinding[], globalAiet: number | null) {
  if (!record) return null;
  const services = uniqueServices(record.scans);
  const assets = uniqueAssets(record.scans);
  const exposed = services.filter(isExposed).length;
  const aei = services.length > 0 ? (exposed / services.length) * 100 : null;

  const risks = new Map<string, number>();
  const assetSet = new Set(assets);
  for (const finding of findings) {
    if (!assetSet.has(finding.asset_id)) continue;
    const cvss = Number(finding.priority.inputs.cvss ?? 0) * 10;
    const epss = Number(finding.priority.inputs.epss ?? 0);
    const risk = epss * (cvss / 10);
    risks.set(finding.asset_id, Math.max(risks.get(finding.asset_id) ?? 0, risk));
  }
  const vui = assets.length > 0
    ? ([...risks.values()].reduce((total, risk) => total + risk, 0) / assets.length) * 100
    : null;
  const aiet = globalAiet;
  const score = aei === null || vui === null || aiet === null
    ? null
    : Math.max(0, Math.min(100, 100 - 0.4 * aei - 0.4 * vui - 0.2 * aiet));
  return {
    score,
    band: bandFor(score),
    aei,
    vui,
    aiet,
    assets: assets.length,
    services: services.length,
    exposed,
    findings: [...risks.keys()].length,
  };
}

export default function DatabasePage({ embedded = false }: { embedded?: boolean }) {
  const [tab, setTab] = useState<Tab>("records");
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<Category>("nmap");
  const [targetPage, setTargetPage] = useState(0);
  const [scorePage, setScorePage] = useState(0);
  const [eventPage, setEventPage] = useState(0);
  const [coveragePage, setCoveragePage] = useState(0);
  const { stage, events, audit, backend, readiness } = useZeroTraceDemo();
  const refreshKey = `${stage}:${events.length}`;
  const recordsQuery = useApiResource<TargetRecordList>("/engine/records", refreshKey);
  const scopesQuery = useApiResource<{ items: EngineScope[] }>("/engine/scopes", refreshKey);
  const eventQuery = useApiResource<EventResponse>("/events?limit=100", refreshKey);
  const historyQuery = useApiResource<HistoryResponse>("/readiness/history", refreshKey);
  const readinessQuery = useApiResource<Readiness>("/engine/readiness", refreshKey);
  const findingsQuery = useApiResource<FindingList>("/engine/intel/findings?page=1&pageSize=100", refreshKey);
  const displayedEvents = (eventQuery.data?.items ?? events) as EventItem[];
  const pendingCount = eventQuery.data?.pending ?? backend.eventBus.pending;
  const latestSnapshot = historyQuery.data?.items.at(-1);
  const liveReadiness = readinessQuery.data ?? null;
  const globalAei = liveReadiness?.components.find((component) => component.name === "AEI")?.value
    ?? (readiness.aei === null ? null : Number(readiness.aei));
  const globalVui = liveReadiness?.components.find((component) => component.name === "VUI")?.value
    ?? (readiness.vui === null ? null : Number(readiness.vui));
  const globalAiet = liveReadiness?.components.find((component) => component.name === "AIET")?.value
    ?? (readiness.aiet === null ? null : Number(readiness.aiet));
  const globalScore = liveReadiness?.score ?? readiness.score;
  const globalBand = liveReadiness?.band ?? (globalScore === null ? null : globalScore >= 90 ? "Secure band" : globalScore >= 70 ? "Moderate band" : globalScore >= 50 ? "Elevated band" : "Critical band");
  const globalCoverage = liveReadiness?.coverage ?? null;
  const unknownComponents = liveReadiness?.unknownComponents ?? [];
  const globalFormula = liveReadiness?.formulaVersion ?? readiness.formulaVersion;
  const findings = findingsQuery.data?.items ?? [];

  const targets = useMemo(() => {
    const records = recordsQuery.data?.items ?? [];
    const scopes = scopesQuery.data?.items ?? [];
    const byKey = new Map<string, TargetRecord>();
    for (const record of records) {
      byKey.set(`${record.scopeId}:${record.target}`, record);
    }
    for (const scope of scopes) {
      for (const target of scope.targets) {
        const key = `${scope.scopeId}:${target}`;
        if (!byKey.has(key)) byKey.set(key, { scopeId: scope.scopeId, target, scans: [] });
      }
    }
    return [...byKey.values()].sort((left, right) => left.target.localeCompare(right.target));
  }, [recordsQuery.data, scopesQuery.data]);

  const targetPages = Math.max(1, Math.ceil(targets.length / 10));
  const safeTargetPage = Math.min(targetPage, targetPages - 1);
  const pagedTargets = targets.slice(safeTargetPage * 10, (safeTargetPage + 1) * 10);
  const scorePages = Math.max(1, Math.ceil(targets.length / 10));
  const safeScorePage = Math.min(scorePage, scorePages - 1);
  const pagedScoreTargets = targets.slice(safeScorePage * 10, (safeScorePage + 1) * 10);
  const eventPages = Math.max(1, Math.ceil(displayedEvents.length / 10));
  const safeEventPage = Math.min(eventPage, eventPages - 1);
  const pagedEvents = displayedEvents.slice(safeEventPage * 10, (safeEventPage + 1) * 10);
  const coveragePages = Math.max(1, Math.ceil(targets.length / 10));
  const safeCoveragePage = Math.min(coveragePage, coveragePages - 1);
  const pagedCoverageTargets = targets.slice(safeCoveragePage * 10, (safeCoveragePage + 1) * 10);
  const scoreBand = globalScore === null ? "AWAITING COVERAGE" : globalScore >= 90 ? "SECURE BAND" : globalScore >= 70 ? "MODERATE BAND" : "ELEVATED";

  const downloadReport = (record: TargetRecord) => {
    const score = scoreFor(record, findings, globalAiet);
    downloadJson(`zerotrace-${safeFilename(record.target)}-report.json`, {
      generatedAt: new Date().toISOString(),
      scope: record.scopeId,
      target: record.target,
      readiness: score,
      nmap: uniqueServices(scansFor(record, "nmap")),
      subfinder: uniqueAssets(scansFor(record, "subfinder")),
      tlsMetadata: uniqueTls(scansFor(record, "tls")),
      syntheticInventory: uniqueAssets(scansFor(record, "synthetic")),
      scans: record.scans.map((scan) => ({
        scanId: scan.scanId,
        profileId: scan.profileId,
        state: scan.state,
        warnings: scan.warnings,
      })),
    });
  };

  const downloadReadiness = (record: TargetRecord) => {
    const score = scoreFor(record, findings, globalAiet);
    downloadJson(`zerotrace-${safeFilename(record.target)}-readiness.json`, {
      generatedAt: new Date().toISOString(),
      scope: record.scopeId,
      target: record.target,
      formulaVersion: "readiness-v1",
      readiness: score,
    });
  };

  const targetForEvent = (event: EventItem) => targets.find((record) => (
    event.entity.includes(record.target) || event.correlation.includes(record.scopeId)
  )) ?? null;

  return <>
    {!embedded && (
      <PageHeading
        eyebrow="DATA PLANE / 01"
        title="Database & events"
        description="Shared records, the event outbox, and target-level readiness. Every target can be opened to inspect its scan evidence or download a report."
        actions={<StateTag tone={backend.databaseConnected ? "green" : "red"}>{backend.database.toUpperCase()} · API {backend.databaseConnected ? "CONNECTED" : "OFFLINE"}</StateTag>}
      />
    )}

    {embedded && (
      <div className="admin-section-head">
        <div>
          <h2>Database & events</h2>
          <p>Shared records, event bus, and readiness for every saved target.</p>
        </div>
        <StateTag tone={backend.databaseConnected ? "green" : "red"}>{backend.database.toUpperCase()} · {backend.databaseConnected ? "CONNECTED" : "OFFLINE"}</StateTag>
      </div>
    )}

    <div className="data-banner">
      <DatabaseIcon size={18} />
      <span>
        <b>PostgreSQL is the Compose target · {backend.database.toUpperCase()} is active now</b>
        <small>Valkey/Redis carries notifications from a durable outbox. Guard&apos;s audit file remains outside PostgreSQL and is verified separately.</small>
      </span>
    </div>

    <div className="tab-bar" role="tablist" aria-label="Database views">
      {(["records", "events", "score"] as const).map((item) => (
        <button className={`tab-button ${tab === item ? "selected" : ""}`} key={item} onClick={() => setTab(item)} role="tab" aria-selected={tab === item} type="button">
          {item === "records" ? <><Layers size={15} /> Shared records</> : item === "events" ? <><Workflow size={15} /> Event bus</> : <><GitBranch size={15} /> Readiness score</>}
        </button>
      ))}
    </div>

    {tab === "records" && <div className="database-layout">
      <Panel title="Targets and evidence" subtitle="Open a target to inspect Nmap, Subfinder, TLS metadata, and synthetic inventory. Download includes the target readiness score." tag={`${targets.length} TARGET(S)`}>
        {recordsQuery.error && <div className="console-alert" role="alert"><DatabaseIcon size={15} /><span>{recordsQuery.error}</span></div>}
        {targets.length === 0 ? (
          <div className="empty-console">
            <DatabaseIcon size={22} />
            <b>No saved targets yet</b>
            <p>Add an authorized target in Admin, then run it from ZeroTrace.</p>
          </div>
        ) : (
          <div className="target-record-list">
            {pagedTargets.map((record) => {
              const key = `${record.scopeId}:${record.target}`;
              const isOpen = expandedTarget === key;
              const score = scoreFor(record, findings, globalAiet);
              return (
                <div className={`target-record ${isOpen ? "target-record-open" : ""}`} key={key}>
                  <button className="target-record-head" type="button" onClick={() => { setExpandedTarget(isOpen ? null : key); setExpandedCategory("nmap"); }}>
                    {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                    <div>
                      <b>{record.target}</b>
                      <small>{record.scopeId} · {record.scans.length} profile record(s)</small>
                    </div>
                    <StateTag tone={score?.score === null || score === null ? "neutral" : score.score >= 70 ? "green" : score.score >= 50 ? "amber" : "red"}>
                      {score?.score === null || score === null ? "SCORE PENDING" : `${score.score.toFixed(0)} / 100`}
                    </StateTag>
                    <span className="target-record-download" role="button" tabIndex={0} onClick={(event) => { event.stopPropagation(); downloadReport(record); }} onKeyDown={(event) => { if (event.key === "Enter") { event.stopPropagation(); downloadReport(record); } }} title={`Download ${record.target} report`}>
                      <Download size={15} /> Report
                    </span>
                  </button>
                  {isOpen && (
                    <div className="target-record-body">
                      <div className="category-grid">
                        {(["nmap", "subfinder", "tls", "synthetic"] as const).map((category) => {
                          const count = category === "nmap"
                            ? uniqueServices(scansFor(record, "nmap")).length
                            : category === "tls"
                              ? uniqueTls(scansFor(record, "tls")).length
                              : uniqueAssets(scansFor(record, category)).length;
                          return (
                            <button className={`category-card ${expandedCategory === category ? "category-card-active" : ""}`} key={category} type="button" onClick={() => setExpandedCategory(category)}>
                              <span>{CATEGORY_LABELS[category]}</span>
                              <b>{count}</b>
                              <small>{count === 1 ? "record" : "records"}</small>
                            </button>
                          );
                        })}
                      </div>
                      <CategoryData record={record} category={expandedCategory} />
                      <div className="target-record-footer">
                        <div>
                          <span>READINESS</span>
                          <b>{score === null || score.score === null ? "Coverage pending" : `${score.score.toFixed(0)} / 100 · ${score.band}`}</b>
                          <small>{score ? `AEI ${score.aei?.toFixed(0) ?? "—"} · VUI ${score.vui?.toFixed(0) ?? "—"} · AIET ${score.aiet?.toFixed(0) ?? "—"} (shared Guard)` : "No scan evidence yet"}</small>
                        </div>
                        <button className="button button-ghost button-small" type="button" onClick={() => downloadReport(record)}>
                          <Download size={14} /> Download report
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
        {targetPages > 1 && <div className="form-actions">
          <button className="button button-ghost button-small" type="button" onClick={() => setTargetPage(Math.max(0, safeTargetPage - 1))} disabled={safeTargetPage === 0}>Previous</button>
          <span className="pagination-label">{safeTargetPage + 1} / {targetPages}</span>
          <button className="button button-ghost button-small" type="button" onClick={() => setTargetPage(Math.min(targetPages - 1, safeTargetPage + 1))} disabled={safeTargetPage === targetPages - 1}>Next</button>
        </div>}
      </Panel>

      <Panel title="Store status" subtitle="What the connected installation actually persists." tag="MODEL MAP">
        <div className="kv-list">
          <div className="kv-row"><span>TARGETS</span><b>{targets.length} saved target(s)</b></div>
          <div className="kv-row"><span>SCAN RECORDS</span><b>{targets.reduce((total, record) => total + record.scans.length, 0)} profile result(s)</b></div>
          <div className="kv-row"><span>INTEL FINDINGS</span><b>{findings.length} finding(s) in the first bounded page</b></div>
          <div className="kv-row"><span>EVENT OUTBOX</span><b>{displayedEvents.length} event(s) · {pendingCount} pending</b></div>
          <div className="kv-row"><span>GUARD AUDIT</span><b>{backend.audit.entries} record(s) · chain {backend.audit.valid ? "valid" : "FAILED"}</b></div>
          <div className="kv-row"><span>DATABASE</span><b>{backend.database.toUpperCase()}</b></div>
        </div>
        <div className="contract-note"><FileKey2 size={16} /><span>Reports are generated from bounded, persisted scan records. Raw scanner output and prompt text are not included.</span></div>
      </Panel>
    </div>}

    {tab === "events" && <div className="events-layout">
      <Panel title="Transactional outbox" subtitle={`Database rows persist first; the configured event bus is ${eventQuery.data?.bus.state ?? backend.eventBus.state}.`} tag={`${displayedEvents.length} EVENTS · ${pendingCount} PENDING`}>
        <div className="event-stream">
          {displayedEvents.length === 0 ? (
            <div className="empty-console"><Workflow size={22} /><b>No events yet</b><p>Run a target from ZeroTrace to populate the outbox.</p></div>
          ) : pagedEvents.map((event, index) => {
            const target = targetForEvent(event);
            const scopeId = event.scopeId ?? target?.scopeId ?? "shared";
            const targetName = event.target ?? target?.target ?? "shared";
            return (
              <div className={`event-row ${event.status === "published" ? "event-active" : ""}`} key={event.id}>
                <span className="event-index">{String(safeEventPage * 10 + index + 1).padStart(2, "0")}</span>
                <div className="event-main">
                  <div><CodeLabel>{event.type}</CodeLabel><small>{event.source}</small></div>
                  <p>{event.entity}</p>
                  <div className="event-meta">
                    <span>{event.id}</span>
                    <span>scope: {scopeId}</span>
                    <span>target: {targetName}</span>
                    <span>{event.correlation}</span>
                  </div>
                </div>
                <StateTag tone={event.status === "published" ? "green" : "amber"}>{event.status === "published" ? "PUBLISHED · VALKEY" : "DB COMMITTED · PENDING"}</StateTag>
              </div>
            );
          })}
        </div>
        {eventPages > 1 && <div className="form-actions">
          <button className="button button-ghost button-small" type="button" onClick={() => setEventPage(Math.max(0, safeEventPage - 1))} disabled={safeEventPage === 0}>Previous</button>
          <span className="pagination-label">{safeEventPage + 1} / {eventPages}</span>
          <button className="button button-ghost button-small" type="button" onClick={() => setEventPage(Math.min(eventPages - 1, safeEventPage + 1))} disabled={safeEventPage === eventPages - 1}>Next</button>
        </div>}
        <div className="contract-note"><FileKey2 size={16} /><span>Envelope: event_id · event_type · schema_version · entity_id · occurred_at · correlation_id · bounded payload. No prompt or credentials are included.</span></div>
      </Panel>
      <Panel title="Target coverage" subtitle="Events are correlated back to saved targets when the entity or correlation ID matches." tag="SCOPE / TARGET">
        {targets.length === 0 ? <div className="empty-console"><Layers size={22} /><b>No saved targets</b><p>Add a target in Admin to correlate events.</p></div> : (
          <>
            <div className="kv-list">
              {pagedCoverageTargets.map((record) => {
                const count = displayedEvents.filter((event) => targetForEvent(event)?.target === record.target).length;
                return <div className="kv-row" key={`${record.scopeId}:${record.target}`}><span>{record.scopeId}</span><b>{record.target} · {count} event(s)</b></div>;
              })}
            </div>
            {coveragePages > 1 && <div className="form-actions">
              <button className="button button-ghost button-small" type="button" onClick={() => setCoveragePage(Math.max(0, safeCoveragePage - 1))} disabled={safeCoveragePage === 0}>Previous</button>
              <span className="pagination-label">{safeCoveragePage + 1} / {coveragePages}</span>
              <button className="button button-ghost button-small" type="button" onClick={() => setCoveragePage(Math.min(coveragePages - 1, safeCoveragePage + 1))} disabled={safeCoveragePage === coveragePages - 1}>Next</button>
            </div>}
          </>
        )}
      </Panel>
    </div>}

    {tab === "score" && <div className="score-layout">
      <Panel title="Readiness score" subtitle="Per-target readiness uses target AEI/VUI and the shared Guard AIET. Download only the readiness record with the button on each row." tag={globalScore === null ? "GLOBAL COVERAGE INCOMPLETE" : `GLOBAL SNAPSHOT ${globalScore.toFixed(0)}`}>
        <div className="score-formula">Score = clamp(100 − <b>0.40 × AEI</b> − <b>0.40 × VUI</b> − <b>0.20 × AIET</b>, 0, 100)</div>
        {targets.length === 0 ? <div className="empty-console"><GitBranch size={22} /><b>No target scores yet</b><p>Run a target from ZeroTrace to calculate readiness.</p></div> : (
          <div className="target-score-list">
            {pagedScoreTargets.map((record) => {
              const score = scoreFor(record, findings, globalAiet);
              const key = `${record.scopeId}:${record.target}`;
              const open = expandedTarget === key;
              return (
                <div className={`target-score ${open ? "target-score-open" : ""}`} key={key}>
                  <button className="target-score-head" type="button" onClick={() => setExpandedTarget(open ? null : key)}>
                    {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    <div><b>{record.target}</b><small>{record.scopeId}</small></div>
                    <strong>{score?.score === null || score === null ? "—" : score.score.toFixed(0)}<small>/100</small></strong>
                    <StateTag tone={score?.score === null || score === null ? "neutral" : score.score >= 70 ? "green" : score.score >= 50 ? "amber" : "red"}>{score?.band ?? "Coverage pending"}</StateTag>
                  </button>
                  {open && (
                    <div className="target-score-body">
                      <div className="category-grid">
                        {(["nmap", "subfinder", "tls", "synthetic"] as const).map((category) => {
                          const count = category === "nmap"
                            ? uniqueServices(scansFor(record, "nmap")).length
                            : category === "tls"
                              ? uniqueTls(scansFor(record, "tls")).length
                              : uniqueAssets(scansFor(record, category)).length;
                          return (
                            <button className={`category-card ${expandedCategory === category ? "category-card-active" : ""}`} key={category} type="button" onClick={() => setExpandedCategory(category)}>
                              <span>{CATEGORY_LABELS[category]}</span>
                              <b>{count}</b>
                              <small>{count === 1 ? "record" : "records"}</small>
                            </button>
                          );
                        })}
                      </div>
                      <CategoryData record={record} category={expandedCategory} />
                      <div className="score-bars">
                        <ScoreBar label="AEI" name="Asset Exposure Index" value={score?.aei ?? null} hint={`${score?.exposed ?? 0} exposed / ${score?.services ?? 0} service(s)`} />
                        <ScoreBar label="VUI" name="Vulnerability Urgency Index" value={score?.vui ?? null} hint={`${score?.findings ?? 0} asset(s) with matched findings`} />
                        <ScoreBar label="AIET" name="AI Threat Exposure Index" value={score?.aiet ?? null} hint="Shared Guard component; no per-target prompt stream" />
                      </div>
                      <div className="target-score-actions">
                        <span>{score?.assets ?? 0} asset(s) · {score?.services ?? 0} service(s)</span>
                        <button className="button button-ghost button-small" type="button" onClick={() => downloadReadiness(record)}>
                          <Download size={14} /> Download readiness
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
        {scorePages > 1 && <div className="form-actions">
          <button className="button button-ghost button-small" type="button" onClick={() => setScorePage(Math.max(0, safeScorePage - 1))} disabled={safeScorePage === 0}>Previous</button>
          <span className="pagination-label">{safeScorePage + 1} / {scorePages}</span>
          <button className="button button-ghost button-small" type="button" onClick={() => setScorePage(Math.min(scorePages - 1, safeScorePage + 1))} disabled={safeScorePage === scorePages - 1}>Next</button>
        </div>}
        <div className="score-history-note">Persisted global snapshots: {historyQuery.data?.items.length ?? 0} · formula {globalFormula} · latest {latestSnapshot?.id ?? "none"}</div>
      </Panel>
      <Panel title="Global readiness" subtitle="The engine-wide score remains the source of truth for shared Guard coverage." tag={scoreBand}>
        <div className="result-grid result-grid-two">
          <div className="result-card"><span>GLOBAL SCORE</span><b>{globalScore === null ? "UNKNOWN" : globalScore.toFixed(0)}</b><small>{globalBand ?? "Not enough complete traces"}</small></div>
          <div className="result-card"><span>COVERAGE</span><b>{globalCoverage === null ? "—" : `${globalCoverage.toFixed(1)}%`}</b><small>{unknownComponents.length ? `Unknown: ${unknownComponents.join(", ")}` : "All components known"}</small></div>
        </div>
        <div className="kv-list">
          <div className="kv-row"><span>AEI</span><b>{globalAei === null ? "UNKNOWN" : `${Number(globalAei).toFixed(2)}%`}</b></div>
          <div className="kv-row"><span>VUI</span><b>{globalVui === null ? "UNKNOWN" : `${Number(globalVui).toFixed(2)}%`}</b></div>
          <div className="kv-row"><span>AIET</span><b>{globalAiet === null ? "UNKNOWN" : `${Number(globalAiet).toFixed(2)}%`}</b></div>
          <div className="kv-row"><span>FORMULA</span><b>{globalFormula}</b></div>
        </div>
        <div className="small-warning"><ShieldCheck size={15} /><span>Per-target AIET uses the shared Guard denominator. If Guard has no request denominator, the target score stays unknown instead of being treated as zero risk.</span></div>
      </Panel>
    </div>}
  </>;
}

function CategoryData({ record, category }: { record: TargetRecord; category: Category }) {
  const [page, setPage] = useState(0);
  const pageSize = 10;
  const scans = scansFor(record, category);
  const items = category === "nmap"
    ? uniqueServices(scans)
    : category === "tls"
      ? uniqueTls(scans)
      : uniqueAssets(scans);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, pages - 1);
  const paged = items.slice(safePage * pageSize, (safePage + 1) * pageSize);

  return (
    <div className="category-data">
      <div className="category-data-head">
        <div><CodeLabel>{CATEGORY_LABELS[category]}</CodeLabel><b>{items.length} record(s)</b></div>
        <small>{scans.map((scan) => scan.state).join(" · ") || "No scan yet"}</small>
      </div>
      {items.length === 0 ? <div className="empty-console compact"><b>No {CATEGORY_LABELS[category]} data</b><p>Run this profile from ZeroTrace to populate the record.</p></div> : (
        <>
          <div className="kv-list">
            {category === "nmap" && (paged as TargetScanRecord["services"]).map((service, index) => (
              <div className="kv-row" key={`${service.asset}-${service.protocol}-${service.port}-${index}`}>
                <span>{service.protocol.toUpperCase()} / {service.port}</span>
                <b>{service.asset} · {service.product ?? "unknown"}{service.version ? ` ${service.version}` : ""}</b>
                <small>{service.tlsStatus ?? "open service"}</small>
              </div>
            ))}
            {category === "subfinder" && (paged as string[]).map((asset) => (
              <div className="kv-row" key={asset}><span>HOST</span><b>{asset}</b><small>{takeoverSignal(asset) ?? "passive host"}</small></div>
            ))}
            {category === "tls" && (paged as TargetScanRecord["tlsFindings"]).map((finding) => (
              <div className="kv-row" key={`${finding.subject}-${finding.expires_at}-${finding.status}`}>
                <span>TLS</span><b>{finding.subject}</b><small>{finding.status} certificate</small>
              </div>
            ))}
            {category === "synthetic" && (paged as string[]).map((asset) => (
              <div className="kv-row" key={asset}><span>ASSET</span><b>{asset}</b><small>synthetic inventory</small></div>
            ))}
          </div>
          {pages > 1 && <div className="form-actions">
            <button className="button button-ghost button-small" type="button" onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0}>Previous</button>
            <span>{safePage + 1} / {pages}</span>
            <button className="button button-ghost button-small" type="button" onClick={() => setPage(Math.min(pages - 1, safePage + 1))} disabled={safePage === pages - 1}>Next</button>
          </div>}
        </>
      )}
    </div>
  );
}

function ScoreBar({ label, name, value, hint }: { label: string; name: string; value: number | null; hint: string }) {
  return (
    <div className="score-bar-row">
      <div><b>{label}</b><span>{name}</span><strong>{value === null ? "—" : value.toFixed(0)}<small>{value === null ? "unknown" : "/100"}</small></strong></div>
      <div className="bar-track"><i style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%` }} /></div>
      <small>{hint}</small>
    </div>
  );
}
