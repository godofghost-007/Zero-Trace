import { ArrowDown, ArrowRight, ArrowUpRight, Cpu, Database, HardDrive, Network, Radar, Shield, Workflow } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useZeroTraceDemo } from "@/lib/zeroTraceDemo";

const destinations = [
  { href: "/recon", name: "Trace Recon", role: "Surface discovery", icon: Radar, tone: "blue" },
  { href: "/intel", name: "Trace Intel", role: "Risk correlation", icon: Workflow, tone: "amber" },
  { href: "/guard", name: "Trace Guard", role: "LLM protection", icon: Shield, tone: "red" },
] as const;

export default function Architecture() {
  const { stage, readiness, events, backend, isConnected } = useZeroTraceDemo();
  const scoreLabel = readiness.score === null ? "—" : readiness.score.toFixed(0);
  const dbName = backend.database.toUpperCase();
  const busState = backend.eventBus.state.toUpperCase().replaceAll("_", " ");
  return <>
    <PageHeading eyebrow="SYSTEM MAP / 00" title="One platform. Three traces." description="The Flask API, database and audit file are connected locally; engine work is intentionally fixture-only until scanner, feed and model adapters are implemented." actions={<StateTag tone={isConnected ? "green" : "red"}>{isConnected ? `${dbName} API CONNECTED` : "API OFFLINE"}</StateTag>} />

    <div className="metric-row">
      <div className="metric-card"><span>READINESS SNAPSHOT</span><strong>{scoreLabel}<small>{readiness.score === null ? "coverage pending" : "/100"}</small></strong><em>Formula {readiness.formulaVersion} · {stage === 0 ? "no observation" : stage < 3 ? "partial coverage" : "all demo components present"}</em></div>
      <div className="metric-card"><span>ENGINE STATUS</span><strong className="metric-word">3 <small>modules</small></strong><em>Fixture actions · no live scanners/models</em></div>
      <div className="metric-card"><span>OUTBOX EVENTS</span><strong>{events.length.toString().padStart(2, "0")}</strong><em>{backend.eventBus.pending} pending · bus {busState.toLowerCase()}</em></div>
      <div className="metric-card"><span>DEPLOYMENT TARGET</span><strong className="metric-word">Laptop</strong><em>9 GB is a target, not a measurement</em></div>
    </div>

    <Panel title="Platform topology" subtitle="Engine actions write sample records through Flask. Compose targets PostgreSQL + Valkey; the current preview store is reported below." tag="LOCAL / COMPOSE">
      <div className="topology">
        <div className="topology-ingress"><span className="topology-kicker">OPERATOR / CLIENT</span><div className="infra-node"><div className="infra-icon"><Network size={18} /></div><div><b>Dashboard + LLM client</b><small>Local browser · same-origin Flask API</small></div></div><div className="connector-down"><ArrowDown size={16} /><span>scoped simulated actions / requests</span></div></div>
        <div className="engine-grid">
          {destinations.map(({ href, name, role, icon: Icon, tone }, index) => <div className="engine-wrap" key={href}>
            <Link href={href} className={`engine-node engine-${tone}`}><div className="engine-topline"><span>ENGINE / 0{index + 1}</span><ArrowUpRight size={14} /></div><div className="engine-icon"><Icon size={20} /></div><b>{name}</b><small>{role}</small><span className="engine-status"><i />{stage > index ? "SAMPLE STATE STORED" : "WAITING · SIMULATED"}</span></Link>
            {index < 2 && <div className="engine-separator"><ArrowRight size={16} /></div>}
          </div>)}
        </div>
        <div className="store-grid">
          <div className="store-node store-primary"><Database size={18} /><div><b>PostgreSQL target · {dbName}</b><small>Current durable state · assets, findings, scores, outbox</small></div><CodeLabel>DATABASE</CodeLabel></div>
          <div className="store-node store-bus"><Workflow size={18} /><div><b>Valkey / Redis · {busState}</b><small>{backend.eventBus.pending} transactional outbox events waiting to publish</small></div><CodeLabel>EVENT BUS</CodeLabel></div>
          <div className="store-node store-audit"><HardDrive size={18} /><div><b>Guard audit · SQLite</b><small>{backend.audit.entries} row(s) · chain {backend.audit.valid ? "valid" : "FAILED"}</small></div><CodeLabel>SEPARATE FILE</CodeLabel></div>
        </div>
        <div className="topology-footnote"><Cpu size={15} /><span>Flask + React; Compose supplies PostgreSQL/Valkey · no real scanner, NVD/EPSS feed, model or upstream proxy is invoked</span></div>
      </div>
    </Panel>

    <div className="two-column">
      <Panel title="The cycle" subtitle="Shared IDs and outbox events connect the three modules." tag="CLICK THROUGH">
        <div className="cycle-list">
          {[
            ["01", "Recon records an asset", "asset_created", stage >= 1],
            ["02", "Intel correlates a finding", "vuln_matched", stage >= 2],
            ["03", "Guard blocks a test attack", "attack_blocked", stage >= 3],
            ["04", "Readiness snapshot recorded", "score_snapshot", events.some((event) => event.type === "score_snapshot")],
          ].map(([number, title, event, done]) => <div className={`cycle-item ${done ? "done" : ""}`} key={String(event)}><span className="cycle-number">{number}</span><div><b>{title}</b><small><CodeLabel>{event}</CodeLabel></small></div><span className={`cycle-check ${done ? "checked" : ""}`}>{done ? "✓" : "—"}</span></div>)}
        </div>
      </Panel>
      <Panel title="Deployment notes" subtitle="Intent, not a benchmark report." tag="TARGET PROFILE">
        <div className="deployment-note"><div className="deployment-stamp">ZT<br /><span>LOCAL</span></div><div><b>16 GB laptop target</b><p>The documentation aims for roughly 9 GB active use. Peak memory with Docker, scanner concurrency, and any model has not been measured.</p><div className="inline-tags"><StateTag tone="amber">9 GB — UNVERIFIED</StateTag><StateTag tone="blue">CPU-FIRST</StateTag></div></div></div>
        <div className="profile-strip"><span><i className="profile-dot green" /> FLASK API</span><span><i className="profile-dot amber" /> SIMULATED ENGINES</span><span><i className="profile-dot blue" /> LOCAL DATA</span></div>
      </Panel>
    </div>
  </>;
}
