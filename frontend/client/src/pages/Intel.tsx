import { ArrowRight, BrainCircuit, CalendarClock, Check, CircleAlert, Database, FileSearch, Gauge, ShieldCheck } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { demoAsset, demoFinding, useZeroTraceDemo, type DemoAsset, type DemoFinding } from "@/lib/zeroTraceDemo";

type MatchList = { items: Array<{ id: string; assetId: string; findingId: string; identifier: string; title: string; method: string; confidence: string; evidence: string[]; reviewState: string; synthetic: boolean }> };
type ProposalList = { items: Array<{ id: string; findingId: string; identifier: string; status: string; reviewRequired: boolean; executionAllowed: boolean; dueWindowHours: number; safeNextAction: string }> };
type IntelStatus = { mode: string; feeds: Record<string, string>; model: string; lastSync: string | null; matchCount: number };

export default function Intel() {
  const { stage, runIntel, isConnected, isProcessing, asset, finding } = useZeroTraceDemo();
  const matched = stage >= 2;
  const matchQuery = useApiResource<MatchList>("/matches", stage);
  const proposalQuery = useApiResource<ProposalList>("/patch-proposals", stage);
  const statusQuery = useApiResource<IntelStatus>("/intel/status", stage);
  const currentAsset: DemoAsset = asset ?? demoAsset;
  const currentFinding: DemoFinding = finding ?? demoFinding;
  const match = matchQuery.data?.items[0];
  const proposal = proposalQuery.data?.items[0];
  return <>
    <PageHeading eyebrow="ENGINE / 03 · VULNERABILITY INTELLIGENCE" title="Trace Intel" description="Correlate observed service facts with a finding and persist an analyst-owned proposal. This connected demo stores synthetic data only." actions={<button className="button button-primary" onClick={() => void runIntel()} disabled={!isConnected || stage < 1 || matched || isProcessing}><FileSearch size={16} />{isProcessing ? "Saving match…" : matched ? "Correlation complete" : stage < 1 ? "Waiting for Recon" : "Correlate sample asset"}</button>} />
    <div className="intel-callout"><BrainCircuit size={18} /><span><b>Feed and model connections are deliberately disabled.</b><small>No NVD, EPSS, KEV, XGBoost, or Ollama request is made. The database stores an illustrative finding match and analyst proposal only.</small></span><StateTag tone="amber">{statusQuery.data?.mode ?? "SIMULATED"}</StateTag></div>
    <div className="intel-source-strip"><span><i className="source-dot blue" /> NVD · not queried</span><span><i className="source-dot amber" /> EPSS · sample value</span><span><i className="source-dot red" /> CISA KEV · not queried</span><span className="source-updated">Model: {statusQuery.data?.model ?? "not loaded"} · no sync</span></div>

    <div className="two-column intel-top-grid">
      <Panel title="Asset-to-vulnerability match" subtitle="Deterministic fixture evidence is persisted; ambiguity stays reviewable." tag={matched ? "MATCHED · DB" : "AWAITING ASSET"}>
        <div className="match-flow"><div className={`match-card ${stage >= 1 ? "match-active" : ""}`}><small>RECON SERVICE</small><b>{stage >= 1 ? `${currentAsset.hostname}:443` : "No observation"}</b><span>HTTPS · {stage >= 1 ? "nginx fixture" : "waiting for Recon"}</span></div><ArrowRight size={17} /><div className={`match-card ${matched ? "match-active" : ""}`}><small>INTEL CANDIDATE</small><b>{matched ? (match?.identifier ?? currentFinding.identifier) : "No match"}</b><span>{matched ? "Synthetic record · not a real CVE" : "Run Recon sample first"}</span></div></div>
        {matched && <div className="evidence-box"><div><Check size={14} /><span>Product/version alias matched to a demo CPE</span></div><div><Check size={14} /><span>Observed service and synthetic version range overlap</span></div><div><CircleAlert size={14} /><span>Confidence {match?.confidence ?? currentFinding.confidence} is illustrative; operator review still required</span></div><code>{currentFinding.cpe}</code></div>}
        {!matched && <div className="empty-demo compact"><Database size={20} /><b>Correlation is staged</b><p>First run Recon. Intel then persists a synthetic finding association against the same asset record.</p></div>}
      </Panel>
      <Panel title="Priority factors" subtitle="Signals shown independently; CVSS severity is not exploit probability." tag="MODEL · SIMULATED">
        <div className="risk-summary"><div className="risk-score"><span>SYNTHETIC PRIORITY</span><strong>{matched ? "P1" : "—"}</strong><StateTag tone={matched ? "red" : "neutral"}>{matched ? "URGENT REVIEW" : "NOT SCORED"}</StateTag></div><div className="risk-factors"><Risk label="CVSS-like severity" value={matched ? `${currentFinding.cvss.toFixed(1)} / 10` : "—"} width={matched ? currentFinding.cvss * 10 : 0} tone="red" /><Risk label="EPSS-like probability" value={matched ? `${currentFinding.epss.toFixed(2)} (demo)` : "—"} width={matched ? currentFinding.epss * 100 : 0} tone="blue" /><Risk label="Exploit model" value={matched ? "Not invoked" : "Offline"} width={0} tone="amber" /></div></div>
        <div className="sla-box"><CalendarClock size={17} /><div><b>48-hour analyst-action window</b><small>Operational triage SLA · starts at queue entry; not an EPSS forecast</small></div><StateTag tone="amber">{proposal?.status?.toUpperCase() ?? "REVIEW ONLY"}</StateTag></div>
      </Panel>
    </div>

    <Panel title="Remediation queue" subtitle="Proposal is stored in local application state; execution is disabled." tag="HUMAN REVIEW REQUIRED">
      <div className="queue-item"><div className="queue-rank">01</div><div className="queue-main"><div><CodeLabel>{matched ? (proposal?.identifier ?? currentFinding.identifier) : "WAITING_FOR_MATCH"}</CodeLabel><StateTag tone={matched ? "red" : "neutral"}>{matched ? "P1 · SAMPLE" : "QUEUED"}</StateTag></div><b>{matched ? `${currentAsset.hostname} · TCP/443` : "Recon has not supplied a service observation"}</b><small>{matched ? `Synthetic evidence only · ${match?.confidence ?? currentFinding.confidence} · persisted as ${proposal?.id ?? "demo proposal"}` : "Run the previous trace to populate this item."}</small></div><div className="queue-window"><span>ANALYST WINDOW</span><b>{proposal?.dueWindowHours ? `${proposal.dueWindowHours}h` : matched ? "48h" : "—"}</b></div><div className="queue-state"><ShieldCheck size={15} /><span>Proposal only<br />No changes applied</span></div></div>
      {matched && <div className="proposal-note"><Gauge size={16} /><span>Safe next action: {proposal?.safeNextAction ?? "verify the software version and consult the vendor advisory."} No commands run, no host modified.</span></div>}
    </Panel>
    <div className="next-engine"><span><b>Next trace:</b> Guard can consume this persisted finding as endpoint context.</span><Link href="/guard" className="text-link">Open Trace Guard <ArrowRight size={15} /></Link></div>
  </>;
}

function Risk({ label, value, width, tone }: { label: string; value: string; width: number; tone: "red" | "blue" | "amber" }) {
  return <div className="risk-factor"><div><span>{label}</span><b>{value}</b></div><div className={`bar-track bar-${tone}`}><i style={{ width: `${width}%` }} /></div></div>;
}
