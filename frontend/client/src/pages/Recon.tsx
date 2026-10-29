import { useState } from "react";
import {
  ArrowRight,
  Check,
  Clock3,
  Crosshair,
  Globe2,
  Radar,
  RefreshCcw,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { useSelectedTarget } from "@/lib/selectedTarget";
import {
  PROFILE_SHORT_LABELS,
  RECON_SERVICE_LABELS,
  scanTone,
  takeoverSignal,
  type EngineStatus,
  type TargetRecord,
  type TargetRecordList,
  type TargetScanRecord,
} from "@/lib/liveEngine";

const PAGE_SIZE = 10;

function scanFor(record: TargetRecord | null, prefix: string): TargetScanRecord | null {
  if (!record) return null;
  return [...record.scans].reverse().find((scan) => scan.profileId.startsWith(prefix)) ?? null;
}

function uniqueServices(record: TargetRecord | null) {
  if (!record) return [];
  return [
    ...new Map(
      record.scans.flatMap((scan) => scan.services).map((service) => [
        `${service.asset}|${service.protocol}|${service.port}|${service.product ?? ""}|${service.version ?? ""}`,
        service,
      ] as const),
    ).values(),
  ];
}

function uniqueAssets(record: TargetRecord | null) {
  if (!record) return [];
  return [...new Set(record.scans.flatMap((scan) => scan.assets))];
}

function uniqueTls(record: TargetRecord | null) {
  if (!record) return [];
  return [
    ...new Map(
      record.scans.flatMap((scan) => scan.tlsFindings).map((finding) => [
        `${finding.subject}|${finding.issuer}|${finding.expires_at}|${finding.status}`,
        finding,
      ] as const),
    ).values(),
  ];
}

function stateOf(scan: TargetScanRecord | null): string {
  return scan?.state ?? "not_run";
}

export default function Recon() {
  const { selection, revision } = useSelectedTarget();
  const [refresh, setRefresh] = useState(0);
  const [assetPage, setAssetPage] = useState(0);
  const [servicePage, setServicePage] = useState(0);
  const [tlsPage, setTlsPage] = useState(0);
  const [warningPage, setWarningPage] = useState(0);
  const recordsQuery = useApiResource<TargetRecordList>("/engine/records", revision + refresh);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", revision + refresh);
  const status = statusQuery.data;
  const records = recordsQuery.data?.items ?? [];
  const record = selection
    ? records.find((item) => item.target === selection.target && item.scopeId === selection.scopeId)
      ?? records.find((item) => item.target === selection.target)
      ?? null
    : null;
  const assets = uniqueAssets(record);
  const services = uniqueServices(record);
  const tlsFindings = uniqueTls(record);
  const nmap = scanFor(record, "service_inventory");
  const subfinder = scanFor(record, "passive_subdomain");
  const tls = scanFor(record, "tls_metadata");
  const synthetic = scanFor(record, "synthetic_inventory");
  const warnings = record?.scans.flatMap((scan) => scan.warnings) ?? [];
  const assetPages = Math.max(1, Math.ceil(assets.length / PAGE_SIZE));
  const servicePages = Math.max(1, Math.ceil(services.length / PAGE_SIZE));
  const tlsPages = Math.max(1, Math.ceil(tlsFindings.length / PAGE_SIZE));
  const warningPages = Math.max(1, Math.ceil(warnings.length / PAGE_SIZE));
  const safeAssetPage = Math.min(assetPage, assetPages - 1);
  const safeServicePage = Math.min(servicePage, servicePages - 1);
  const safeTlsPage = Math.min(tlsPage, tlsPages - 1);
  const safeWarningPage = Math.min(warningPage, warningPages - 1);
  const pagedAssets = assets.slice(safeAssetPage * PAGE_SIZE, (safeAssetPage + 1) * PAGE_SIZE);
  const pagedServices = services.slice(safeServicePage * PAGE_SIZE, (safeServicePage + 1) * PAGE_SIZE);
  const pagedTls = tlsFindings.slice(safeTlsPage * PAGE_SIZE, (safeTlsPage + 1) * PAGE_SIZE);
  const pagedWarnings = warnings.slice(safeWarningPage * PAGE_SIZE, (safeWarningPage + 1) * PAGE_SIZE);

  const pipeline = [
    { id: "scope", title: "Scope approval", detail: selection?.scopeId ?? "No scope", state: selection ? "completed" : "not_run", icon: ShieldCheck },
    { id: "nmap", title: "Nmap services", detail: nmap ? PROFILE_SHORT_LABELS[nmap.profileId] ?? nmap.profileId : "Not run", state: stateOf(nmap), icon: ScanLine },
    { id: "subfinder", title: "Subfinder hosts", detail: subfinder ? PROFILE_SHORT_LABELS[subfinder.profileId] ?? subfinder.profileId : "Not run", state: stateOf(subfinder), icon: Globe2 },
    { id: "tls", title: "TLS metadata", detail: tls ? "TLS read" : "Not run", state: stateOf(tls), icon: ShieldCheck },
    { id: "synthetic", title: "Synthetic inventory", detail: synthetic ? "Synthetic fixture" : "Not run", state: stateOf(synthetic), icon: Server },
    { id: "intel", title: "Intel handoff", detail: status?.intel.findings ? `${status.intel.findings} finding(s)` : "Awaiting evidence", state: status?.intel.findings ? "completed" : "queued", icon: Radar },
  ] as const;

  return <>
    <PageHeading
      eyebrow="TRACE RECON / 01 · SURFACE"
      title="Trace Recon"
      description="The recon pipeline and discovered assets for the target selected in ZeroTrace. Everything here is read from persisted, bounded scan records."
      actions={
        <div className="form-actions">
          <StateTag tone={record ? "green" : "neutral"}>{record ? "TARGET LOADED" : "NO TARGET"}</StateTag>
          <button className="button button-ghost button-small" type="button" onClick={() => setRefresh((value) => value + 1)}>
            <RefreshCcw size={14} /> Refresh
          </button>
        </div>
      }
    />

    {!selection ? (
      <Panel title="No target selected" subtitle="Run a saved target from ZeroTrace first." tag="START AT 00">
        <div className="empty-console">
          <Crosshair size={22} />
          <b>Trace Recon is waiting for a target</b>
          <p>ZeroTrace writes the selected target, scope, and services into the shared session state.</p>
          <Link href="/" className="button button-primary">Open ZeroTrace <ArrowRight size={15} /></Link>
        </div>
      </Panel>
    ) : (
      <>
        <div className="data-banner">
          <ShieldCheck size={18} />
          <span>
            <b>{selection.target} · {selection.scopeId}</b>
            <small>{selection.services.map((serviceId) => RECON_SERVICE_LABELS[serviceId]).join(" → ")}. The pipeline reads the latest persisted record for each profile.</small>
          </span>
          <CodeLabel>LOOPBACK ENGINE</CodeLabel>
        </div>

        {recordsQuery.error && <div className="console-alert" role="alert"><ShieldAlert size={15} /><span>{recordsQuery.error}</span></div>}

        <Panel title="Recon pipeline" subtitle="Each stage is a bounded read. A missing stage is shown as not run, never as success." tag="PIPELINE">
          <div className="pipeline-grid">
            {pipeline.map(({ id, title, detail, state, icon: Icon }) => (
              <div className={`pipeline-step pipeline-${state}`} key={id}>
                <div className="pipeline-icon"><Icon size={18} /></div>
                <div>
                  <b>{title}</b>
                  <small>{detail}</small>
                </div>
                <StateTag tone={scanTone(state)}>{state.replaceAll("_", " ").toUpperCase()}</StateTag>
              </div>
            ))}
          </div>
        </Panel>

        <div className="metric-row recon-metrics">
          <div className="metric-card"><span>DISCOVERED ASSETS</span><strong>{assets.length}</strong><em>unique hostnames</em></div>
          <div className="metric-card"><span>OPEN SERVICES</span><strong>{services.length}</strong><em>service records</em></div>
          <div className="metric-card"><span>TLS RECORDS</span><strong>{tlsFindings.length}</strong><em>metadata only</em></div>
          <div className="metric-card"><span>WARNINGS</span><strong>{warnings.length}</strong><em>bounded output</em></div>
        </div>

        <div className="two-column">
          <Panel title="Discovered assets" subtitle="Hostnames from passive profiles. Suffix labels are review-only; no DNS or HTTP probe is sent." tag={`${assets.length} ASSETS`}>
            {assets.length === 0 ? (
              <div className="empty-console"><Globe2 size={22} /><b>No assets recorded</b><p>Run Subfinder or synthetic inventory from ZeroTrace.</p></div>
            ) : (
              <>
                <div className="kv-list">
                  {pagedAssets.map((asset) => (
                    <div className="kv-row" key={asset}><span>HOST</span><b>{asset}</b><small>{takeoverSignal(asset) ?? "passive host"}</small></div>
                  ))}
                </div>
                <Pagination page={safeAssetPage} pages={assetPages} onPrevious={() => setAssetPage(Math.max(0, safeAssetPage - 1))} onNext={() => setAssetPage(Math.min(assetPages - 1, safeAssetPage + 1))} />
              </>
            )}
          </Panel>

          <Panel title="Open services" subtitle="Port, protocol, and detected product. Ten per page." tag={`${services.length} SERVICES`}>
            {services.length === 0 ? (
              <div className="empty-console"><ScanLine size={22} /><b>No open services recorded</b><p>Run Nmap from ZeroTrace. Normal scans use the bounded critical-port profile.</p></div>
            ) : (
              <>
                <div className="kv-list">
                  {pagedServices.map((service, index) => (
                    <div className="kv-row" key={`${service.asset}-${service.protocol}-${service.port}-${index}`}>
                      <span>{service.protocol.toUpperCase()} / {service.port}</span>
                      <b>{service.asset} · {service.product ?? "unknown"}{service.version ? ` ${service.version}` : ""}</b>
                      <small>open service</small>
                    </div>
                  ))}
                </div>
                <Pagination page={safeServicePage} pages={servicePages} onPrevious={() => setServicePage(Math.max(0, safeServicePage - 1))} onNext={() => setServicePage(Math.min(servicePages - 1, safeServicePage + 1))} />
              </>
            )}
          </Panel>
        </div>

        <div className="two-column">
          <Panel title="TLS metadata" subtitle="Subject, issuer, expiry, and validation status. No certificate contents are stored." tag={`${tlsFindings.length} RECORDS`}>
            {tlsFindings.length === 0 ? <div className="empty-console"><ShieldCheck size={22} /><b>No TLS record</b><p>Run the TLS metadata profile from ZeroTrace.</p></div> : (
              <>
                <div className="kv-list">
                  {pagedTls.map((finding) => (
                    <div className="kv-row" key={`${finding.subject}-${finding.expires_at}`}>
                      <span>TLS</span><b>{finding.subject}</b><small>{finding.status} certificate</small>
                    </div>
                  ))}
                </div>
                <Pagination page={safeTlsPage} pages={tlsPages} onPrevious={() => setTlsPage(Math.max(0, safeTlsPage - 1))} onNext={() => setTlsPage(Math.min(tlsPages - 1, safeTlsPage + 1))} />
              </>
            )}
          </Panel>

          <Panel title="Run state" subtitle="Warnings and profile states from the latest persisted scans." tag="EVIDENCE">
            <div className="kv-list">
              <div className="kv-row"><span>NMAP</span><b>{stateOf(nmap)}</b><small>{nmap?.scanId ?? "no scan"}</small></div>
              <div className="kv-row"><span>SUBFINDER</span><b>{stateOf(subfinder)}</b><small>{subfinder?.scanId ?? "no scan"}</small></div>
              <div className="kv-row"><span>TLS</span><b>{stateOf(tls)}</b><small>{tls?.scanId ?? "no scan"}</small></div>
              <div className="kv-row"><span>SYNTHETIC</span><b>{stateOf(synthetic)}</b><small>{synthetic?.scanId ?? "no scan"}</small></div>
            </div>
            {warnings.length > 0 ? (
              <>
                <div className="warning-list">
                  {pagedWarnings.map((warning, index) => <div className="small-warning" key={`${warning}-${index}`}><Clock3 size={14} /><span>{warning}</span></div>)}
                </div>
                <Pagination page={safeWarningPage} pages={warningPages} onPrevious={() => setWarningPage(Math.max(0, safeWarningPage - 1))} onNext={() => setWarningPage(Math.min(warningPages - 1, safeWarningPage + 1))} />
              </>
            ) : <div className="small-warning"><Check size={14} /><span>No scan warnings on the latest records.</span></div>}
          </Panel>
        </div>

        <Panel title="Next: Intel Guard" subtitle="The same asset IDs are correlated against NVD, EPSS, and KEV." tag="HANDOFF">
          <div className="workflow-strip">
            <div><span>01</span><b>Assets</b><small>{assets.length} hostname(s)</small></div>
            <ArrowRight size={16} />
            <div><span>02</span><b>Vulnerabilities</b><small>Matched CVEs per service</small></div>
            <ArrowRight size={16} />
            <div><span>03</span><b>Priority</b><small>CVSS · EPSS · KEV</small></div>
            <ArrowRight size={16} />
            <Link href="/intel" className="button button-primary">Open Intel Guard <ArrowRight size={15} /></Link>
          </div>
        </Panel>
      </>
    )}
  </>;
}

function Pagination({ page, pages, onPrevious, onNext }: { page: number; pages: number; onPrevious: () => void; onNext: () => void }) {
  if (pages <= 1) return null;
  return <div className="form-actions">
    <button className="button button-ghost button-small" type="button" onClick={onPrevious} disabled={page === 0}>Previous</button>
    <span className="pagination-label">{page + 1} / {pages}</span>
    <button className="button button-ghost button-small" type="button" onClick={onNext} disabled={page === pages - 1}>Next</button>
  </div>;
}
