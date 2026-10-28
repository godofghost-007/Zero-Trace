import { useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  BrainCircuit,
  Check,
  CircleAlert,
  Copy,
  Crosshair,
  Database,
  Download,
  FileCode2,
  Gauge,
  Play,
  RefreshCcw,
  ShieldCheck,
  Terminal,
  Workflow,
} from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import { downloadJson, safeFilename } from "@/lib/download";
import { useSelectedTarget } from "@/lib/selectedTarget";
import {
  type EngineStatus,
  type FindingList,
  type IntelFinding,
  type TargetRecord,
  type TargetRecordList,
} from "@/lib/liveEngine";

const PAGE_SIZE = 10;
const QUEUE_KEY = "zerotrace.remediation.v1";

type RemediationItem = {
  id: string;
  target: string;
  scopeId: string;
  port: number;
  protocol: string;
  cve: string;
  serviceId: string;
  script: string;
  status: "queued" | "simulated";
  createdAt: string;
  note?: string;
};

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

function loadQueue(): RemediationItem[] {
  try {
    const raw = window.localStorage.getItem(QUEUE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as RemediationItem[];
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item?.cve === "string") : [];
  } catch {
    return [];
  }
}

function persistQueue(items: RemediationItem[]) {
  try {
    window.localStorage.setItem(QUEUE_KEY, JSON.stringify(items));
  } catch {
    // The in-memory queue still works if storage is unavailable.
  }
}

function servicePort(finding: IntelFinding): { port: number; protocol: string } {
  const parts = finding.service_id.split(":");
  const port = Number(parts.at(-1));
  const protocol = parts.at(-2) ?? "tcp";
  return { port: Number.isFinite(port) ? port : 0, protocol };
}

function cvssOf(finding: IntelFinding): number {
  return Number(finding.priority.inputs.cvss ?? 0) * 10;
}

function epssOf(finding: IntelFinding): number {
  return Number(finding.priority.inputs.epss ?? 0);
}

function kevOf(finding: IntelFinding): boolean {
  return Number(finding.priority.inputs.kev ?? 0) >= 1;
}

function buildScript(finding: IntelFinding, target: string): string {
  const { port, protocol } = servicePort(finding);
  return [
    "#!/usr/bin/env bash",
    "# ZeroTrace remediation script — review before use",
    `# Target: ${target}`,
    `# CVE: ${finding.cve_id}`,
    `# Service: ${protocol}/${port}`,
    "# Generated from a matched finding. ZeroTrace does not execute this script.",
    "set -euo pipefail",
    `PORT="${port}"`,
    `PROTO="${protocol}"`,
    'if command -v ufw >/dev/null 2>&1; then',
    '  sudo ufw deny "${PORT}/${PROTO}"',
    'elif command -v firewall-cmd >/dev/null 2>&1; then',
    '  sudo firewall-cmd --permanent --add-rich-rule="rule family=\\"ipv4\\" port port=\\"${PORT}\\" protocol=\\"${PROTO}\\" reject"',
    '  sudo firewall-cmd --reload',
    'elif command -v nft >/dev/null 2>&1; then',
    '  sudo nft add rule inet filter input "${PROTO}" dport "${PORT}" drop',
    'else',
    '  sudo iptables -A INPUT -p "${PROTO}" --dport "${PORT}" -j DROP',
    'fi',
    `echo "Blocked ${protocol}/${port} for ${finding.cve_id}"`,
  ].join("\n");
}

function useFindings(refreshKey: number) {
  const [items, setItems] = useState<IntelFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let active = true;
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const first = await apiRequest<FindingList>("/engine/intel/findings?page=1&pageSize=100");
        const collected = [...first.items];
        const pages = Math.min(first.pagination.totalPages, 5);
        for (let page = 2; page <= pages; page += 1) {
          const next = await apiRequest<FindingList>(`/engine/intel/findings?page=${page}&pageSize=100`);
          collected.push(...next.items);
        }
        if (active) setItems(collected);
      } catch (reason) {
        if (active) setError(messageOf(reason));
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; };
  }, [refreshKey, revision]);

  return { items, loading, error, refresh: () => setRevision((value) => value + 1) };
}

export default function Intel() {
  const { selection, revision } = useSelectedTarget();
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState(0);
  const [assetPage, setAssetPage] = useState(0);
  const [queuePage, setQueuePage] = useState(0);
  const [queue, setQueue] = useState<RemediationItem[]>(() => loadQueue());
  const [selectedQueueId, setSelectedQueueId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const recordsQuery = useApiResource<TargetRecordList>("/engine/records", revision + refresh);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", revision + refresh);
  const findingsState = useFindings(revision + refresh);
  const status = statusQuery.data;
  const records = recordsQuery.data?.items ?? [];
  const record: TargetRecord | null = selection
    ? records.find((item) => item.target === selection.target && item.scopeId === selection.scopeId)
      ?? records.find((item) => item.target === selection.target)
      ?? null
    : null;
  const assets = useMemo(() => new Set(record?.scans.flatMap((scan) => scan.assets) ?? []), [record]);
  const findings = useMemo(() => {
    if (!selection) return [];
    return findingsState.items.filter((finding) => assets.size === 0
      ? finding.asset_id === selection.target || finding.asset_id.endsWith(`.${selection.target}`)
      : assets.has(finding.asset_id));
  }, [assets, findingsState.items, selection]);
  const grouped = useMemo(() => {
    const map = new Map<string, IntelFinding[]>();
    for (const finding of findings) {
      const list = map.get(finding.asset_id) ?? [];
      list.push(finding);
      map.set(finding.asset_id, list);
    }
    return [...map.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [findings]);
  const pages = Math.max(1, Math.ceil(findings.length / PAGE_SIZE));
  const safePage = Math.min(page, pages - 1);
  const pagedFindings = findings.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const assetPages = Math.max(1, Math.ceil(grouped.length / PAGE_SIZE));
  const safeAssetPage = Math.min(assetPage, assetPages - 1);
  const pagedGrouped = grouped.slice(safeAssetPage * PAGE_SIZE, (safeAssetPage + 1) * PAGE_SIZE);
  const queuePages = Math.max(1, Math.ceil(queue.length / PAGE_SIZE));
  const safeQueuePage = Math.min(queuePage, queuePages - 1);
  const pagedQueue = queue.slice(safeQueuePage * PAGE_SIZE, (safeQueuePage + 1) * PAGE_SIZE);
  const selectedItem = queue.find((item) => item.id === selectedQueueId) ?? queue[0] ?? null;
  const intel = status?.intel;

  const correlate = () => {
    if (!selection) return;
    if (findings.length === 0) {
      setError("No matched findings for this target yet. Wait for Nmap and the Intel feeds, then refresh.");
      return;
    }
    const next = [...queue];
    let added = 0;
    for (const finding of findings) {
      const { port, protocol } = servicePort(finding);
      const id = `${selection.scopeId}:${selection.target}:${protocol}:${port}:${finding.cve_id}`;
      if (next.some((item) => item.id === id)) continue;
      next.push({
        id,
        target: selection.target,
        scopeId: selection.scopeId,
        port,
        protocol,
        cve: finding.cve_id,
        serviceId: finding.service_id,
        script: buildScript(finding, selection.target),
        status: "queued",
        createdAt: new Date().toISOString(),
      });
      added += 1;
    }
    setQueue(next);
    persistQueue(next);
    setSelectedQueueId(next.at(-1)?.id ?? null);
    setNotice(`${added} remediation script(s) queued. Each CVE has its own script.`);
    setError(null);
  };

  const copyScript = async (item: RemediationItem) => {
    try {
      await navigator.clipboard.writeText(item.script);
      setNotice(`Copied the ${item.cve} script.`);
    } catch {
      setError("Clipboard access is unavailable. Select the script text and copy it manually.");
    }
  };

  const runDryRun = (item: RemediationItem) => {
    const next = queue.map((entry) => entry.id === item.id
      ? { ...entry, status: "simulated" as const, note: "Dry run only. ZeroTrace did not execute the script." }
      : entry);
    setQueue(next);
    persistQueue(next);
    setNotice(`Dry run recorded for ${item.cve}. No command was executed.`);
  };

  return <>
    <PageHeading
      eyebrow="INTEL GUARD / 02 · CORRELATION"
      title="Intel Guard"
      description="Asset-to-vulnerability correlation for the selected target. Priority uses only CVE, NVD CVSS, EPSS, and KEV."
      actions={
        <div className="form-actions">
          <StateTag tone={findings.length > 0 ? "green" : "neutral"}>{findings.length} FINDING(S)</StateTag>
          <button className="button button-ghost button-small" type="button" onClick={() => { setRefresh((value) => value + 1); findingsState.refresh(); }}>
            <RefreshCcw size={14} /> Refresh
          </button>
        </div>
      }
    />

    {!selection ? (
      <Panel title="No target selected" subtitle="Run a saved target from ZeroTrace first." tag="START AT 00">
        <div className="empty-console">
          <Crosshair size={22} />
          <b>Intel Guard is waiting for a target</b>
          <p>The selected target and its discovered assets are shared with this page.</p>
          <Link href="/" className="button button-primary">Open ZeroTrace <ArrowRight size={15} /></Link>
        </div>
      </Panel>
    ) : (
      <>
        <div className="data-banner">
          <BrainCircuit size={18} />
          <span>
            <b>{selection.target} · {selection.scopeId}</b>
            <small>{assets.size} discovered asset(s) · {findings.length} matched finding(s). Feeds: NVD {intel?.facts?.toLocaleString() ?? "—"} facts · EPSS {intel?.epssRecords?.toLocaleString() ?? "—"} · KEV {intel?.kevRecords?.toLocaleString() ?? "—"}.</small>
          </span>
          <CodeLabel>NVD · EPSS · KEV</CodeLabel>
        </div>

        {findingsState.error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{findingsState.error}</span></div>}
        {recordsQuery.error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{recordsQuery.error}</span></div>}

        <div className="two-column">
          <Panel title="Asset to vulnerability" subtitle="Every discovered asset with its matched CVE count and exposed ports." tag="ASSET MAP">
            {grouped.length === 0 ? (
              <div className="empty-console">
                <Database size={22} />
                <b>{findingsState.loading ? "Reading correlated findings" : "No findings for this target"}</b>
                <p>Intel correlation runs after Nmap finishes. If feeds are still loading, refresh in a moment.</p>
              </div>
            ) : (
              <>
                <div className="asset-vuln-list">
                {pagedGrouped.map(([asset, list]) => {
                  const ports = [...new Set(list.map((finding) => {
                    const { port, protocol } = servicePort(finding);
                    return `${protocol}/${port}`;
                  }))];
                  return (
                    <div className="asset-vuln-card" key={asset}>
                      <div className="asset-vuln-head">
                        <div><span>ASSET</span><b>{asset}</b></div>
                        <StateTag tone={list.some(kevOf) ? "red" : "amber"}>{list.length} CVE(S)</StateTag>
                      </div>
                      <div className="asset-vuln-ports">
                        {ports.map((port) => <CodeLabel key={port}>{port}</CodeLabel>)}
                      </div>
                      <small>{list.some(kevOf) ? "KEV present" : "No KEV"}</small>
                    </div>
                  );
                })}
                </div>
                {assetPages > 1 && <div className="form-actions">
                  <button className="button button-ghost button-small" type="button" onClick={() => setAssetPage(Math.max(0, safeAssetPage - 1))} disabled={safeAssetPage === 0}>Previous</button>
                  <span className="pagination-label">{safeAssetPage + 1} / {assetPages}</span>
                  <button className="button button-ghost button-small" type="button" onClick={() => setAssetPage(Math.min(assetPages - 1, safeAssetPage + 1))} disabled={safeAssetPage === assetPages - 1}>Next</button>
                </div>}
              </>
            )}
          </Panel>

          <Panel title="Priority factors" subtitle="Only these four factors are shown, as requested." tag="CVSS · EPSS · KEV">
            {findings.length === 0 ? (
              <div className="empty-console"><Gauge size={22} /><b>No priority factors yet</b><p>Findings appear after the Nmap profile completes and feeds are available.</p></div>
            ) : (
              <>
                <div className="priority-list">
                  {pagedFindings.map((finding) => {
                    const { port, protocol } = servicePort(finding);
                    return (
                      <div className="priority-card" key={`${finding.service_id}:${finding.cve_id}`}>
                        <div className="priority-head">
                          <div><span>CVE</span><b>{finding.cve_id}</b></div>
                          <StateTag tone={kevOf(finding) ? "red" : "amber"}>{kevOf(finding) ? "KEV" : "NOT KEV"}</StateTag>
                        </div>
                        <div className="priority-meta"><CodeLabel>{finding.asset_id}</CodeLabel><CodeLabel>{protocol}/{port}</CodeLabel></div>
                        <div className="priority-factors">
                          <div><span>CVE</span><b>{finding.cve_id}</b></div>
                          <div><span>NVD (CVSS)</span><b>{cvssOf(finding).toFixed(1)}</b></div>
                          <div><span>EPSS</span><b>{(epssOf(finding) * 100).toFixed(1)}%</b></div>
                          <div><span>KEV</span><b>{kevOf(finding) ? "Yes" : "No"}</b></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
                {pages > 1 && <div className="form-actions">
                  <button className="button button-ghost button-small" type="button" onClick={() => setPage(Math.max(0, safePage - 1))} disabled={safePage === 0}>Previous</button>
                  <span className="pagination-label">{safePage + 1} / {pages}</span>
                  <button className="button button-ghost button-small" type="button" onClick={() => setPage(Math.min(pages - 1, safePage + 1))} disabled={safePage === pages - 1}>Next</button>
                </div>}
              </>
            )}
          </Panel>
        </div>

        <Panel title="Correlation" subtitle="Build one firewall script per CVE and keep it in the remediation queue. Scripts are generated, never auto-run." tag="REMEDIATION QUEUE">
          <div className="correlation-bar">
            <div>
              <b>{findings.length} matched CVE(s)</b>
              <small>Correlation creates a queue item named by CVE. Multiple CVEs produce multiple scripts.</small>
            </div>
            <button className="button button-primary" type="button" onClick={correlate} disabled={findings.length === 0}>
              <Workflow size={15} /> Correlation
            </button>
          </div>
          {error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{error}</span></div>}
          {notice && <div className="console-alert success" role="status"><Check size={15} /><span>{notice}</span></div>}

          <div className="remediation-layout">
            <div className="remediation-queue">
              <div className="remediation-queue-head"><b>Remediation queue</b><CodeLabel>{queue.length} SCRIPT(S)</CodeLabel></div>
              {queue.length === 0 ? (
                <div className="empty-console compact"><Terminal size={20} /><b>Queue empty</b><p>Click Correlation to generate scripts from the findings above.</p></div>
              ) : pagedQueue.map((item) => (
                <button
                  className={`remediation-item ${selectedItem?.id === item.id ? "remediation-item-active" : ""}`}
                  type="button"
                  key={item.id}
                  onClick={() => setSelectedQueueId(item.id)}
                >
                  <div><span>CVE</span><b>{item.cve}</b><small>{item.target} · {item.protocol}/{item.port}</small></div>
                  <StateTag tone={item.status === "simulated" ? "green" : "amber"}>{item.status === "simulated" ? "DRY RUN" : "QUEUED"}</StateTag>
                </button>
              ))}
              {queuePages > 1 && <div className="form-actions">
                <button className="button button-ghost button-small" type="button" onClick={() => setQueuePage(Math.max(0, safeQueuePage - 1))} disabled={safeQueuePage === 0}>Previous</button>
                <span className="pagination-label">{safeQueuePage + 1} / {queuePages}</span>
                <button className="button button-ghost button-small" type="button" onClick={() => setQueuePage(Math.min(queuePages - 1, safeQueuePage + 1))} disabled={safeQueuePage === queuePages - 1}>Next</button>
              </div>}
            </div>

            <div className="script-viewer">
              {selectedItem ? (
                <>
                  <div className="script-viewer-head">
                    <div><span>SCRIPT</span><b>{selectedItem.cve}</b><small>{selectedItem.target} · {selectedItem.protocol}/{selectedItem.port}</small></div>
                    <div className="form-actions">
                      <button className="button button-ghost button-small" type="button" onClick={() => void copyScript(selectedItem)}><Copy size={14} /> Copy</button>
                      <button className="button button-ghost button-small" type="button" onClick={() => downloadJson(`zerotrace-${safeFilename(selectedItem.cve)}-remediation.json`, selectedItem)}><Download size={14} /> Download</button>
                    </div>
                  </div>
                  <pre className="script-block"><code>{selectedItem.script}</code></pre>
                  <div className="script-run">
                    <div>
                      <b>Run</b>
                      <small>{selectedItem.status === "simulated" ? selectedItem.note : "Local dry-run only. ZeroTrace does not execute the script against the target."}</small>
                    </div>
                    <button className="button button-primary" type="button" onClick={() => runDryRun(selectedItem)} disabled={selectedItem.status === "simulated"}>
                      <Play size={15} />{selectedItem.status === "simulated" ? "Dry run recorded" : "Run dry-run"}
                    </button>
                  </div>
                  <div className="small-warning">
                    <ShieldCheck size={15} />
                    <span>Apply the script on the target host after review. The scanner host cannot close a remote port, and this build never executes remediation automatically.</span>
                  </div>
                </>
              ) : (
                <div className="empty-console"><FileCode2 size={22} /><b>Select a queued CVE</b><p>The generated firewall script appears here with a dry-run button.</p></div>
              )}
            </div>
          </div>
        </Panel>
      </>
    )}
  </>;
}
