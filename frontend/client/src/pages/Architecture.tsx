import { useState } from "react";
import {
  ArrowRight,
  Cpu,
  Database,
  HardDrive,
  Laptop,
  MemoryStick,
  Monitor,
  Network,
  Radar,
  RefreshCcw,
  Shield,
  Workflow,
} from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { useApiResource } from "@/lib/api";
import { useZeroTraceDemo } from "@/lib/zeroTraceDemo";
import type { SystemInfo } from "@/lib/liveEngine";

function uptimeLabel(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

const destinations = [
  { href: "/recon", name: "Trace Recon", role: "Surface discovery", icon: Radar, tone: "blue" },
  { href: "/intel", name: "Intel Guard", role: "Risk correlation", icon: Workflow, tone: "amber" },
  { href: "/guard", name: "Trace Guard", role: "LLM protection", icon: Shield, tone: "red" },
] as const;

export default function Architecture({ embedded = false }: { embedded?: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const query = useApiResource<SystemInfo>("/system/info", refresh);
  const { readiness, backend, isConnected } = useZeroTraceDemo();
  const info = query.data;

  return <>
    {!embedded && (
      <PageHeading
        eyebrow="SYSTEM MAP / 00 · HOST"
        title="Architecture"
        description="What ZeroTrace is running on, what the local stack connects to, and where each boundary sits."
        actions={
          <div className="form-actions">
            <StateTag tone={isConnected ? "green" : "red"}>{isConnected ? `${backend.database.toUpperCase()} API CONNECTED` : "API OFFLINE"}</StateTag>
            <button className="button button-ghost button-small" type="button" onClick={() => setRefresh((value) => value + 1)}>
              <RefreshCcw size={14} /> Refresh
            </button>
          </div>
        }
      />
    )}

    {embedded && (
      <div className="admin-section-head">
        <div>
          <h2>Architecture</h2>
          <p>This device, the local engine, and the data plane. The view is read-only.</p>
        </div>
        <button className="button button-ghost button-small" type="button" onClick={() => setRefresh((value) => value + 1)}>
          <RefreshCcw size={14} /> Refresh
        </button>
      </div>
    )}

    {query.error && <div className="console-alert" role="alert"><Monitor size={15} /><span>{query.error}</span></div>}

    <div className="metric-row device-metric-row">
      <div className="metric-card">
        <span>RUNNING ON</span>
        <strong className="metric-word">{info?.deviceType ?? "Detecting"}</strong>
        <em>{info?.hostname ?? "Reading host information"}</em>
      </div>
      <div className="metric-card">
        <span>OPERATING SYSTEM</span>
        <strong className="metric-word">{info?.platform ?? "—"}</strong>
        <em>{info?.os ?? "Waiting for the local API"}</em>
      </div>
      <div className="metric-card">
        <span>CPU / MEMORY</span>
        <strong>{info ? `${info.cpu.logical}` : "—"}<small> threads</small></strong>
        <em>{info ? `${info.memory.totalGb} GB RAM · ${info.cpu.physical} physical cores` : "Not measured"}</em>
      </div>
      <div className="metric-card">
        <span>UPTIME</span>
        <strong className="metric-word">{info ? uptimeLabel(info.uptimeSeconds) : "—"}</strong>
        <em>{info?.battery ? `Battery ${info.battery.percent}% · ${info.battery.plugged ? "plugged in" : "on battery"}` : "Desktop / workstation power"}</em>
      </div>
    </div>

    <div className="two-column">
      <Panel title="This device" subtitle="Read from the local host by the Flask API. No cloud metadata is queried." tag={info?.deviceType?.toUpperCase() ?? "HOST"}>
        {info ? (
          <div className="device-grid">
            <div className="device-card">
              <div className="device-card-head"><DeviceIcon device={info} /><div><span>DEVICE</span><b>{info.deviceType}</b></div></div>
              <small>{info.hostname}</small>
            </div>
            <div className="device-card">
              <div className="device-card-head"><Cpu size={18} /><div><span>PROCESSOR</span><b>{info.cpu.logical} logical / {info.cpu.physical} physical</b></div></div>
              <small>{info.processor}{info.cpu.frequencyMhz ? ` · ${Math.round(info.cpu.frequencyMhz)} MHz` : ""}</small>
            </div>
            <div className="device-card">
              <div className="device-card-head"><MemoryStick size={18} /><div><span>MEMORY</span><b>{info.memory.totalGb} GB</b></div></div>
              <small>{info.memory.availableGb} GB available</small>
            </div>
            <div className="device-card">
              <div className="device-card-head"><HardDrive size={18} /><div><span>DISK</span><b>{info.disk.totalGb} GB</b></div></div>
              <small>{info.disk.freeGb} GB free on {info.disk.path}</small>
            </div>
          </div>
        ) : (
          <div className="empty-console">
            <Monitor size={22} />
            <b>{query.loading ? "Reading host configuration" : "Host information unavailable"}</b>
            <p>The Admin API reads CPU, memory, disk, and platform details from this machine.</p>
          </div>
        )}
        {info && (
          <div className="kv-list device-kv">
            <div className="kv-row"><span>HOSTNAME</span><b>{info.hostname}</b></div>
            <div className="kv-row"><span>OS</span><b>{info.os}</b></div>
            <div className="kv-row"><span>ARCHITECTURE</span><b>{info.machine}</b></div>
            <div className="kv-row"><span>PYTHON</span><b>{info.pythonVersion}</b></div>
            <div className="kv-row"><span>BOOTED</span><b>{new Date(info.bootTime).toLocaleString()}</b></div>
            <div className="kv-row"><span>BATTERY</span><b>{info.battery ? `${info.battery.percent}% · ${info.battery.plugged ? "charging" : "discharging"}` : "Not present"}</b></div>
          </div>
        )}
      </Panel>

      <Panel title="Local topology" subtitle="Browser, Flask BFF, loopback engine, and the evidence stores." tag="LOOPBACK">
        <div className="topology compact-topology">
          <div className="topology-ingress">
            <span className="topology-kicker">OPERATOR / CLIENT</span>
            <div className="infra-node"><div className="infra-icon"><Network size={18} /></div><div><b>Dashboard + LLM client</b><small>Local browser · same-origin Flask API</small></div></div>
            <div className="connector-down"><ArrowRight size={16} /><span>same-origin /api/v1</span></div>
          </div>
          <div className="engine-grid">
            {destinations.map(({ href, name, role, icon: Icon, tone }, index) => (
              <div className="engine-wrap" key={href}>
                <Link href={href} className={`engine-node engine-${tone}`}>
                  <div className="engine-topline"><span>ENGINE / 0{index + 1}</span><ArrowRight size={14} /></div>
                  <div className="engine-icon"><Icon size={20} /></div>
                  <b>{name}</b><small>{role}</small>
                  <span className="engine-status"><i />LOOPBACK READY</span>
                </Link>
                {index < 2 && <div className="engine-separator"><ArrowRight size={16} /></div>}
              </div>
            ))}
          </div>
          <div className="store-grid">
            <div className="store-node store-primary"><Database size={18} /><div><b>PostgreSQL / active store</b><small>{backend.database.toUpperCase()} · shared records and scores</small></div><CodeLabel>DATABASE</CodeLabel></div>
            <div className="store-node store-bus"><Workflow size={18} /><div><b>Event outbox</b><small>{backend.eventBus.pending} pending event(s)</small></div><CodeLabel>EVENT BUS</CodeLabel></div>
            <div className="store-node store-audit"><HardDrive size={18} /><div><b>Guard audit</b><small>{backend.audit.entries} row(s) · chain {backend.audit.valid ? "valid" : "failed"}</small></div><CodeLabel>SEPARATE FILE</CodeLabel></div>
          </div>
        </div>
      </Panel>
    </div>

    <Panel title="Deployment posture" subtitle="Local demo first. Public deployment remains a separate, gated operation." tag="LOCAL ONLY">
      <div className="deployment-note">
        <div className="deployment-stamp">ZT<br /><span>LOCAL</span></div>
        <div>
          <b>Loopback-only installation</b>
          <p>The engine and Guard endpoints stay on 127.0.0.1. The browser talks only to Flask. Public exposure, OIDC, and production backup/restore are not part of this local setup.</p>
          <div className="inline-tags">
            <StateTag tone="amber">NOT PUBLIC</StateTag>
            <StateTag tone="blue">CPU-FIRST</StateTag>
            <StateTag tone={readiness.score === null ? "neutral" : "green"}>{readiness.score === null ? "COVERAGE PENDING" : `READINESS ${readiness.score.toFixed(0)}`}</StateTag>
          </div>
        </div>
      </div>
    </Panel>
  </>;
}

function DeviceIcon({ device }: { device: SystemInfo }) {
  return device.battery ? <Laptop size={18} /> : <Monitor size={18} />;
}
