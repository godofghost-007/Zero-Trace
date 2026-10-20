import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, Ban, CheckCircle2, Crosshair, FileText, Gauge, Globe2, RefreshCcw, ScanLine, ShieldCheck, TriangleAlert } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import {
  PROFILE_LABELS,
  TERMINAL_SCAN_STATES,
  normalizeTarget,
  scanTone,
  scopeIdFor,
  type EngineScan,
  type EngineScope,
  type EngineStatus,
  type GuardInspection,
  type Readiness,
  type ScanResult,
  type ScanStatus,
} from "@/lib/liveEngine";
import { demoPrompt } from "@/lib/zeroTraceDemo";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

export default function Targets() {
  const [refresh, setRefresh] = useState(0);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", refresh);
  const scopesQuery = useApiResource<{ items: EngineScope[] }>("/engine/scopes", refresh);
  const readinessQuery = useApiResource<Readiness>("/engine/readiness", refresh);
  const scansQuery = useApiResource<{ items: EngineScan[] }>("/engine/scans", refresh);
  const status = statusQuery.data;
  const profiles = status?.profiles ?? [];
  const defaultProfile = profiles.includes("tls_metadata_v1")
    ? "tls_metadata_v1"
    : profiles[0] ?? "synthetic_inventory_v1";

  const [target, setTarget] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [profile, setProfile] = useState("");
  const [expires, setExpires] = useState("24");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const [lastRun, setLastRun] = useState<{ scopeId: string; target: string; profileId: string } | null>(null);

  const [guardText, setGuardText] = useState(demoPrompt);
  const [guardResult, setGuardResult] = useState<GuardInspection | null>(null);
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardError, setGuardError] = useState<string | null>(null);

  const [intelBusy, setIntelBusy] = useState(false);
  const [intelNotice, setIntelNotice] = useState<string | null>(null);
  const [intelError, setIntelError] = useState<string | null>(null);

  const selectedProfile = profile && (profiles.length === 0 || profiles.includes(profile))
    ? profile
    : defaultProfile;

  useEffect(() => {
    if (!scanId) return;
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const next = await apiRequest<ScanStatus>(`/engine/scans/${scanId}`);
        if (!active) return;
        setScanStatus(next);
        if (TERMINAL_SCAN_STATES.has(next.state)) {
          const result = await apiRequest<ScanResult>(`/engine/scans/${scanId}/result`);
          if (!active) return;
          setScanResult(result);
          setPolling(false);
          setRefresh((value) => value + 1);
        } else {
          timer = window.setTimeout(() => void poll(), 1000);
        }
      } catch (reason) {
        if (!active) return;
        setScanError(messageOf(reason));
        setPolling(false);
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId]);

  useEffect(() => {
    if (scanId) return;
    const items = scansQuery.data?.items;
    if (!items || items.length === 0) return;
    const latest = items[items.length - 1];
    setScanId(latest.scanId);
    setScanStatus({ scanId: latest.scanId, state: latest.state });
    setLastRun({
      scopeId: latest.scopeId,
      target: latest.target,
      profileId: latest.profileId,
    });
    setPolling(!TERMINAL_SCAN_STATES.has(latest.state));
  }, [scanId, scansQuery.data]);

  const onTargetChange = (value: string) => {
    setTarget(value);
    setError(null);
    const normalized = normalizeTarget(value);
    if (!normalized.error) setScopeId(scopeIdFor(normalized.host));
  };

  const beginScan = async (scopeIdValue: string, targetValue: string, profileValue: string) => {
    const response = await apiRequest<ScanStatus>("/engine/scans", {
      method: "POST",
      body: JSON.stringify({
        authorized: true,
        scopeId: scopeIdValue,
        target: targetValue,
        profileId: profileValue,
      }),
    });
    setScanId(response.scanId);
    setScanStatus(response);
    setScanResult(null);
    setScanError(null);
    setPolling(true);
    setLastRun({ scopeId: scopeIdValue, target: targetValue, profileId: profileValue });
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const normalized = normalizeTarget(target);
    if (normalized.error) {
      setError(normalized.error);
      return;
    }
    if (!confirmed) {
      setError("Confirm that you own or are authorized to test this target.");
      return;
    }
    const chosenScope = scopeId.trim() || scopeIdFor(normalized.host);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(chosenScope)) {
      setError("Scope ID must start with a letter or number and use only letters, numbers, dots, dashes, or underscores.");
      return;
    }
    setBusy(true);
    try {
      await apiRequest<EngineScope>("/engine/scopes", {
        method: "POST",
        body: JSON.stringify({
          authorized: true,
          scopeId: chosenScope,
          targets: [normalized.host],
          environment: "synthetic",
          profiles: [selectedProfile],
          expiresInHours: Number(expires),
        }),
      });
      setRefresh((value) => value + 1);
      await beginScan(chosenScope, normalized.host, selectedProfile);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setBusy(false);
    }
  };

  const runAgain = async () => {
    if (!lastRun) return;
    if (!confirmed) {
      setError("Confirm that you own or are authorized to test this target.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await beginScan(lastRun.scopeId, lastRun.target, lastRun.profileId);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setBusy(false);
    }
  };

  const syncKev = async () => {
    setIntelBusy(true);
    setIntelNotice(null);
    setIntelError(null);
    try {
      const response = await apiRequest<{ ingestionId: string; state: string; factCount?: number }>("/engine/intel/ingest", {
        method: "POST",
        body: JSON.stringify({ source: "kev" }),
      });
      if (response.state !== "completed") {
        setIntelError(`KEV ingestion ended in state: ${response.state}.`);
      } else {
        setIntelNotice(`CISA KEV loaded: ${response.factCount ?? 0} records parsed.`);
      }
      setRefresh((value) => value + 1);
    } catch (reason) {
      setIntelError(messageOf(reason));
    } finally {
      setIntelBusy(false);
    }
  };

  const inspectPrompt = async () => {
    if (!guardText.trim()) {
      setGuardError("Enter a prompt to inspect.");
      return;
    }
    setGuardBusy(true);
    setGuardError(null);
    setGuardResult(null);
    try {
      const result = await apiRequest<GuardInspection>("/engine/guard/inspect", {
        method: "POST",
        body: JSON.stringify({ text: guardText }),
      });
      setGuardResult(result);
      setRefresh((value) => value + 1);
    } catch (reason) {
      setGuardError(messageOf(reason));
    } finally {
      setGuardBusy(false);
    }
  };

  const scanLabel = scanStatus?.state?.replace("_", " ") ?? "no run";

  return <>
    <PageHeading
      eyebrow="ADMIN / 05 · TARGETS"
      title="Targets & scope"
      description="Create an operator-approved scope, run an allowlisted read against it, and inspect the result. Recon, Intel and Guard all live behind the same loopback engine."
      actions={<StateTag tone={status ? "green" : statusQuery.loading ? "blue" : "red"}>{status ? "ENGINE CONNECTED" : statusQuery.loading ? "CONNECTING" : "ENGINE OFFLINE"}</StateTag>}
    />

    <div className="data-banner">
      <ShieldCheck size={18} />
      <span>
        <b>Real, bounded reads — only for targets you own or are authorized to test.</b>
        <small>The TLS profile opens one connection to port 443 and records certificate metadata. It does not exploit, brute-force, or modify the target. Scope and scan creation both require an explicit authorization confirmation.</small>
      </span>
      <CodeLabel>LOOPBACK ENGINE</CodeLabel>
    </div>

    {statusQuery.error && <div className="console-alert" role="alert">
      <TriangleAlert size={15} />
      <span>{statusQuery.error} <Link href="/settings" className="text-link">Open engine settings <ArrowRight size={13} /></Link></span>
    </div>}

    <div className="engine-summary-grid">
      <div className="engine-summary"><span>ENGINE</span><b>{status ? "CONNECTED" : statusQuery.loading ? "CONNECTING" : "OFFLINE"}</b><small>{status?.service ?? "Start python -m scripts.live_engine"}</small></div>
      <div className="engine-summary"><span>ADAPTERS</span><b>{status?.adapters.length ?? "—"}</b><small>{status?.adapters.join(", ") ?? "No connection"}</small></div>
      <div className="engine-summary"><span>SCOPES</span><b>{status?.scopes ?? "—"}</b><small>Operator-approved targets</small></div>
      <div className="engine-summary"><span>SCANS</span><b>{status?.scans ?? "—"}</b><small>Queued + completed in this process</small></div>
    </div>

    <Panel
      title="Operational readiness"
      subtitle="Recomputed from the persisted Recon inventory, Intel findings, Guard inspections, and engine state. Missing inputs stay unknown instead of being treated as zero."
      tag={readinessQuery.data?.band?.toUpperCase() ?? "WAITING FOR INPUTS"}
    >
      {readinessQuery.error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{readinessQuery.error}</span></div>}
      {readinessQuery.data ? <>
        <div className="result-grid">
          <div className="result-card"><span>SCORE</span><b>{readinessQuery.data.score ?? "UNKNOWN"}</b><small>{readinessQuery.data.band ?? "Not enough complete traces"}</small></div>
          <div className="result-card"><span>COVERAGE</span><b>{readinessQuery.data.coverage.toFixed(1)}%</b><small>{readinessQuery.data.unknownComponents.length ? `Unknown: ${readinessQuery.data.unknownComponents.join(", ")}` : "All components known"}</small></div>
          <div className="result-card"><span>ASSETS / SERVICES</span><b>{readinessQuery.data.inputs.assets} / {readinessQuery.data.inputs.services}</b><small>{readinessQuery.data.inputs.exposedServices} exposed service(s)</small></div>
        </div>
        <div className="kv-list">
          {readinessQuery.data.components.map((component) => <div className="kv-row" key={component.name}>
            <span>{component.name}</span>
            <b>{component.value === null ? "UNKNOWN" : `${component.value.toFixed(2)}%`} — {component.status}</b>
          </div>)}
          <div className="kv-row"><span>INTEL</span><b>{readinessQuery.data.inputs.intelFacts} facts — {readinessQuery.data.inputs.findings} finding(s) — {readinessQuery.data.inputs.uncertainMatches} uncertain</b></div>
          <div className="kv-row"><span>GUARD</span><b>{readinessQuery.data.inputs.guardRequests} inspection(s) — {readinessQuery.data.inputs.unblockedAttacks} unblocked</b></div>
        </div>
        {!readinessQuery.data.inputs.nvdLoaded && <div className="small-warning"><FileText size={15} /><span>The VUI component stays unknown until NVD facts are loaded through the engine&apos;s API-only ingestion endpoint and matched to persisted Recon services.</span></div>}
      </> : <div className="empty-console"><Gauge size={22} /><b>{readinessQuery.loading ? "Calculating readiness" : "Readiness is unavailable"}</b><p>The engine returns a component-by-component result, including unknown inputs.</p></div>}
    </Panel>

    <div className="two-column">
      <Panel title="Add an authorized target" subtitle="The scope is created first; the scan can only use a target inside it." tag="OPERATOR ACTION">
        <form onSubmit={(event) => void submit(event)}>
          <div className="field-grid">
            <div className="field field-wide">
              <label htmlFor="target-input">Target URL, hostname, or IPv4</label>
              <input
                id="target-input"
                value={target}
                onChange={(event) => onTargetChange(event.target.value)}
                placeholder="https://example.com/login"
                spellCheck={false}
                autoComplete="off"
              />
              <small>The engine requires a dotted domain or IPv4 address. A URL is reduced to its hostname; the path is never requested.</small>
            </div>
            <div className="field">
              <label htmlFor="scope-input">Scope ID</label>
              <input id="scope-input" value={scopeId} onChange={(event) => setScopeId(event.target.value)} placeholder="scope-example-com" spellCheck={false} autoComplete="off" />
              <small>Approved scope records are owned by the local engine operator.</small>
            </div>
            <div className="field">
              <label htmlFor="profile-input">Profile</label>
              <select id="profile-input" value={selectedProfile} onChange={(event) => setProfile(event.target.value)}>
                {(profiles.length ? profiles : [defaultProfile]).map((item) => <option key={item} value={item}>{PROFILE_LABELS[item] ?? item}</option>)}
              </select>
              <small>{selectedProfile === "tls_metadata_v1" ? "Connects to the target on 443. No other port or path is touched." : selectedProfile === "synthetic_inventory_v1" ? "Writes a fixed lab fixture; no network request is made." : "Requires the corresponding scanner binary on this machine."}</small>
            </div>
            <div className="field">
              <label htmlFor="expiry-input">Scope lifetime</label>
              <select id="expiry-input" value={expires} onChange={(event) => setExpires(event.target.value)}>
                <option value="1">1 hour</option>
                <option value="6">6 hours</option>
                <option value="24">24 hours</option>
                <option value="72">72 hours</option>
              </select>
              <small>Expired scopes are rejected by the engine.</small>
            </div>
          </div>
          <label className="checkbox-row" htmlFor="authorized">
            <input id="authorized" type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            <span><b>I own this target or have written authorization to test it.</b> I understand this creates a real scope and may open a network connection to the target.</span>
          </label>
          {error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{error}</span></div>}
          <div className="form-actions">
            <button className="button button-primary" type="submit" disabled={busy || !status || !confirmed}>
              <Crosshair size={15} />{busy ? "Starting…" : "Create scope & run scan"}
            </button>
            <button className="button button-ghost" type="button" onClick={() => void runAgain()} disabled={busy || !lastRun || !confirmed || polling}>
              <RefreshCcw size={15} />Run again
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="Live scan" subtitle="The worker runs queued scans in the engine process and records partial failures." tag={scanLabel.toUpperCase()}>
        {scanError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{scanError}</span></div>}
        {!scanId && <div className="empty-console">
          <ScanLine size={22} />
          <b>No live scan yet</b>
          <p>Create a scope and run a scan to see the real engine state, assets, services, and TLS metadata here.</p>
        </div>}
        {scanId && <>
          <div className="engine-state-row">
            <StateTag tone={scanTone(scanStatus?.state ?? "queued")}>{(scanStatus?.state ?? "queued").toUpperCase()}</StateTag>
            <CodeLabel>{scanId}</CodeLabel>
            {polling && <span className="engine-status"><RefreshCcw className="spin" size={12} /> polling engine</span>}
          </div>
          <div className="result-grid">
            <div className="result-card"><span>TARGET</span><b>{lastRun?.target ?? "—"}</b><small>{lastRun?.scopeId ?? ""}</small></div>
            <div className="result-card"><span>PROFILE</span><b>{lastRun?.profileId ?? "—"}</b><small>Allowlisted adapter</small></div>
            <div className="result-card"><span>ASSETS</span><b>{scanResult?.assets.length ?? "—"}</b><small>{scanResult ? `${scanResult.services.length} service record(s)` : "Waiting for completion"}</small></div>
          </div>
          {scanResult?.tlsFindings.map((finding) => <div className="tls-block" key={`${finding.subject}-${finding.expires_at}`}>
            <div className="panel-tag">TLS METADATA</div>
            <div className="kv-list">
              <div className="kv-row"><span>SUBJECT</span><b>{finding.subject}</b></div>
              <div className="kv-row"><span>ISSUER</span><b>{finding.issuer}</b></div>
              <div className="kv-row"><span>EXPIRES</span><b>{finding.expires_at}</b></div>
              <div className="kv-row"><span>STATUS</span><b>{finding.status}</b></div>
            </div>
          </div>)}
          {scanResult && scanResult.assets.length > 0 && <div className="tls-block">
            <div className="panel-tag">ASSETS</div>
            <div className="kv-list">{scanResult.assets.map((asset) => <div className="kv-row" key={asset}><span>ASSET</span><b>{asset}</b></div>)}</div>
          </div>}
          {scanResult && scanResult.services.length > 0 && <div className="tls-block">
            <div className="panel-tag">SERVICES</div>
            <div className="kv-list">{scanResult.services.map((service, index) => <div className="kv-row" key={`${service.asset}-${service.port}-${index}`}><span>{service.protocol.toUpperCase()} / {service.port}</span><b>{service.asset} · {service.product ?? "unknown"}{service.version ? ` ${service.version}` : ""}</b></div>)}</div>
          </div>}
          {scanResult?.warnings.map((warning) => <div className="console-alert info" key={warning}><TriangleAlert size={15} /><span>{warning}</span></div>)}
        </>}
      </Panel>
    </div>

    <div className="two-column">
      <Panel title="Intel engine" subtitle="Live counters and feed endpoints. Ingestion remains an explicit engine API action." tag="REAL COMPONENT">
        {status ? <>
          <div className="result-grid result-grid-two">
            <div className="result-card"><span>FACTS</span><b>{status.intel.facts}</b><small>Parsed vulnerability facts</small></div>
            <div className="result-card"><span>FINDINGS</span><b>{status.intel.findings}</b><small>Service ↔ CVE matches</small></div>
            <div className="result-card"><span>UNCERTAIN</span><b>{status.intel.uncertainMatches}</b><small>Queued for review</small></div>
            <div className="result-card"><span>KEV RECORDS</span><b>{status.intel.kevRecords ?? 0}</b><small>CISA known-exploited entries</small></div>
          </div>
          <div className="form-actions">
            <button className="button button-ghost" onClick={() => void syncKev()} disabled={intelBusy || !status}>
              <RefreshCcw className={intelBusy ? "spin" : undefined} size={15} />{intelBusy ? "Fetching CISA KEV…" : "Sync CISA KEV"}
            </button>
          </div>
          {intelNotice && <div className="console-alert success" role="status"><ShieldCheck size={15} /><span>{intelNotice}</span></div>}
          {intelError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{intelError}</span></div>}
          <div className="kv-list">
            {Object.entries(status.intel.feeds).map(([name, url]) => <div className="kv-row" key={name}><span>{name.toUpperCase()}</span><b>{url}</b></div>)}
          </div>
          <div className="small-warning"><FileText size={15} /><span>Only the CISA KEV feed is exposed by this console. NVD and EPSS ingestion remain available through the engine&apos;s <code>/api/v1/intel/ingestions</code> endpoint.</span></div>
        </> : <div className="empty-console"><FileText size={22} /><b>Intel is offline</b><p>Connect the engine to read its fact and finding counters.</p></div>}
      </Panel>

      <Panel title="Guard inspection" subtitle="Runs the real prompt-injection and PII detectors. No upstream model is contacted." tag="INSPECT ONLY">
        <div className="field">
          <label htmlFor="guard-input">Prompt to inspect</label>
          <textarea id="guard-input" value={guardText} onChange={(event) => setGuardText(event.target.value)} rows={5} spellCheck={false} />
          <small>The detector checks for instruction override, jailbreak patterns, and PII. It never forwards the prompt.</small>
        </div>
        <div className="form-actions">
          <button className="button button-primary" onClick={() => void inspectPrompt()} disabled={guardBusy || !status}>
            <Ban size={15} />{guardBusy ? "Inspecting…" : "Inspect prompt"}
          </button>
        </div>
        {guardError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{guardError}</span></div>}
        {guardResult && <div className={`console-alert ${guardResult.blocked ? "" : "success"}`}>
          {guardResult.blocked ? <Ban size={15} /> : <CheckCircle2 size={15} />}
          <span>
            <b>{guardResult.blocked ? "Blocked before the model call" : "No injection pattern matched"}</b>
            <small>{guardResult.blocked ? `Reason: ${guardResult.reason ?? "policy violation"}. ` : ""}{guardResult.pii.blocked ? `PII detected: ${guardResult.pii.reason ?? "match"}.` : "No PII pattern matched."} Detector mode: {guardResult.mode}.</small>
          </span>
        </div>}
        {status?.guard && <div className="kv-list">
          <div className="kv-row"><span>DETECTOR</span><b>{status.guard.detector}</b></div>
          <div className="kv-row"><span>PII SCANNER</span><b>{status.guard.piiScanner ? "enabled" : "disabled"}</b></div>
          <div className="kv-row"><span>UPSTREAM</span><b>{status.guard.upstreamConfigured ? "configured" : "not configured — inspection only"}</b></div>
        </div>}
      </Panel>
    </div>

    <Panel title="Approved scopes" subtitle="Scope records are owned by the local operator and expire automatically." tag={status ? `${status.scopes} ACTIVE` : "OFFLINE"}>
      {scopesQuery.error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{scopesQuery.error}</span></div>}
      {scopesQuery.data?.items.length ? <div className="scope-list">
        {scopesQuery.data.items.map((scope) => <div className="scope-row" key={scope.scopeId}>
          <div><b>{scope.scopeId}</b><small>{scope.targets.join(", ")}</small></div>
          <div><small>{scope.profiles.join(", ")} · {scope.environment}</small><small>Expires {new Date(scope.expiresAt).toLocaleString()}</small></div>
          <StateTag tone={scope.approved ? "green" : "red"}>{scope.approved ? "APPROVED" : "BLOCKED"}</StateTag>
        </div>)}
      </div> : <div className="empty-console"><Globe2 size={22} /><b>No scopes yet</b><p>Add an authorized target above to create the first scope.</p></div>}
    </Panel>

    <div className="next-engine">
      <span><b>Need to change the engine URL or key?</b> The connection is stored and redacted server-side.</span>
      <Link href="/settings" className="text-link">Open engine settings <ArrowRight size={15} /></Link>
    </div>
  </>;
}
