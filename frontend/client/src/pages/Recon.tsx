import { ArrowRight, BadgeCheck, Check, Clock3, Globe2, KeyRound, Radar, RefreshCcw, ScanLine, Server, ShieldAlert, ShieldCheck } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { demoAsset, useZeroTraceDemo, type DemoAsset } from "@/lib/zeroTraceDemo";

type AssetList = { items: Array<DemoAsset & { createdAt?: string }> };
type ScanList = { items: Array<{ id: string; scope: string; status: string; partial: boolean; warnings: string[] }> };

export default function Recon() {
  const { stage, runRecon, isConnected, isProcessing, backend } = useZeroTraceDemo();
  const complete = stage >= 1;
  const assetQuery = useApiResource<AssetList>("/assets", stage);
  const scanQuery = useApiResource<ScanList>("/recon/scans", stage);
  const storedAsset = assetQuery.data?.items[0] ?? null;
  const currentAsset = storedAsset ?? demoAsset;
  const steps = [
    ["01", "Scope approval", "scope_demo_lab_01 · explicit allowlist", complete, "AUTHORIZED SAMPLE"],
    ["02", "Passive discovery", "Certificate/DNS adapter fixture", complete, "FIXTURE"],
    ["03", "Service inventory", "TCP/443 HTTPS · TCP/22 SSH", complete, "TOP-100 PROFILE (MOCK)"],
    ["04", "TLS + cloud checks", "TLS fixture valid · S3 not queried", complete, complete ? "PARTIAL · S3 UNKNOWN" : "NO CLOUD ACCESS"],
    ["05", "Inventory delta", "New unmanaged candidate → local database", complete, "SAMPLE CHANGE"],
    ["06", "Commit + outbox", "asset_created → pending event outbox", complete, "SIMULATED"],
  ] as const;
  return <>
    <PageHeading eyebrow="ENGINE / 02 · ATTACK SURFACE" title="Trace Recon" description="Discover authorized assets and exposed services, retain provenance, and hand normalized observations to Intel. The connected demo writes a fixed fixture; it never launches a scanner." actions={<button className="button button-primary" onClick={() => void runRecon()} disabled={!isConnected || complete || isProcessing}><Radar size={16} />{isProcessing ? "Saving fixture…" : complete ? "Sample discovered" : isConnected ? "Run sample discovery" : "Waiting for API"}</button>} />
    <div className="safety-banner"><ShieldCheck size={18} /><span><b>Scope locked to a fictional `.test` hostname.</b><small>No Subfinder, Nmap, DNS, TLS, or S3 request is made. Flask writes only the preset fixture shown below.</small></span><CodeLabel>scope_demo_lab_01</CodeLabel></div>
    <div className="engine-summary-grid"><div className="engine-summary"><span>SCAN RUN</span><b>{scanQuery.data?.items[0]?.id ?? "RUN-DEMO-0081"}</b><small>{complete ? `${scanQuery.data?.items[0]?.status ?? "Completed"} · simulated` : "Ready · no process started"}</small></div><div className="engine-summary"><span>TARGET</span><b>portal.zt-lab.test</b><small>Reserved demo domain · authorized fixture</small></div><div className="engine-summary"><span>RESULTS</span><b>{complete ? "1 asset · 2 services" : "Waiting"}</b><small>{complete ? `Persisted in ${backend.database.toUpperCase()}` : "Click Run sample discovery"}</small></div><div className="engine-summary"><span>PROVENANCE</span><b>Fixture set A</b><small>{complete ? "Database provenance recorded" : "No scanner process invoked"}</small></div></div>

    <div className="two-column engine-main-grid">
      <Panel title="Recon pipeline" subtitle="Stages are recorded through the Flask API; cloud checks remain explicitly partial." tag={complete ? "COMPLETE · PARTIAL" : "IDLE · MOCK"}>
        <div className="pipeline-list">{steps.map(([number, title, detail, done, badge]) => <div className={`pipeline-row ${done ? "pipeline-done" : ""} ${badge.startsWith("PARTIAL") ? "pipeline-partial" : ""}`} key={number}><span className="pipeline-num">{done ? <Check size={14} /> : number}</span><div className="pipeline-copy"><b>{title}</b><small>{detail}</small></div><span className="pipeline-badge">{done ? badge : "WAITING"}</span></div>)}</div>
        <div className="pipeline-caption"><RefreshCcw size={14} /> Future scanner workers need approved scope, hard timeouts, cancellation, bounded output and durable partial-failure records.</div>
      </Panel>
      <Panel title="Discovered asset" subtitle="Current persisted record; written before its `asset_created` outbox event." tag={backend.database.toUpperCase()}>
        {complete ? <>
          <div className="asset-title"><div className="asset-icon"><Globe2 size={19} /></div><div><CodeLabel>{currentAsset.id}</CodeLabel><h3>{currentAsset.hostname}</h3><small>{currentAsset.environment} · {currentAsset.scope}</small></div><StateTag tone="amber">UNMANAGED CANDIDATE</StateTag></div>
          <div className="service-table"><div className="service-header"><span>PORT</span><span>PROTO</span><span>SERVICE</span><span>OBSERVATION</span></div>{currentAsset.services.map((service) => <div className="service-line" key={service.port}><b>{service.port}</b><span>{service.protocol}</span><span>{service.name}</span><small>{service.version}</small></div>)}</div>
          <div className="asset-notes"><div><BadgeCheck size={15} /><span>TLS certificate</span><b>Valid · fixture</b></div><div><ShieldAlert size={15} /><span>Cloud bucket checks</span><b>Unknown · not queried</b></div><div><Clock3 size={15} /><span>Last seen</span><b>{storedAsset?.createdAt ? new Date(storedAsset.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "Demo fixture"}</b></div></div>
          <div className="partial-result-note"><ShieldAlert size={15} /><span><b>Partial result:</b> optional cloud/S3 adapter is not configured; this field remains unknown and no bucket was contacted.</span></div>
        </> : <div className="empty-demo"><ScanLine size={22} /><b>No sample run yet</b><p>Run the sample discovery to persist a fictional asset and create its correlated outbox event.</p></div>}
      </Panel>
    </div>
    <Panel title="Engine safeguards" subtitle="Controls that belong in a real scanner adapter — not merely in the UI." tag="DESIGN CONTRACT">
      <div className="safeguard-grid"><div><KeyRound size={17} /><b>Explicit scope</b><p>Reject targets outside operator-approved domains/CIDRs before any process starts.</p></div><div><Server size={17} /><b>Argument arrays</b><p>Invoke scanner processes without shell interpolation or arbitrary user-supplied flags.</p></div><div><Clock3 size={17} /><b>Bounded work</b><p>Timeout, cancel, rate-limit, cap output, and retain structured partial/failure state.</p></div></div>
    </Panel>
    <div className="next-engine"><span><b>Next trace:</b> Intel reads the committed asset from the Flask API.</span><Link href="/intel" className="text-link">Open Trace Intel <ArrowRight size={15} /></Link></div>
  </>;
}
