import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ArrowRight, Ban, CheckCircle2, Crosshair, FileText, Gauge, Globe2, RefreshCcw, ScanLine, ShieldCheck, TriangleAlert } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { ApiError, apiRequest, useApiResource } from "@/lib/api";
import {
  LEVEL_PROFILE_IDS,
  PROFILE_LABELS,
  PROFILE_SHORT_LABELS,
  SCAN_LEVELS,
  TERMINAL_SCAN_STATES,
  normalizeTarget,
  profileTimeoutSeconds,
  scanLevelRequiresAuthorization,
  scanTone,
  scopeIdFor,
  type AuthorizationChallenge,
  type EngineScope,
  type EngineStatus,
  type GuardInspection,
  type Readiness,
  type ScanLevel,
  type ScanResult,
  type ScanState,
  type ScanStatus,
  type TargetAuthorization,
} from "@/lib/liveEngine";
import { demoPrompt } from "@/lib/zeroTraceDemo";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

function ageLabel(value: string | null): string {
  if (!value) return "never";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return "unknown";
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function feedTone(feed: { state: string; lastError: string | null }): "green" | "amber" | "red" | "neutral" {
  if (feed.lastError || feed.state === "failed" || feed.state === "degraded") return "red";
  if (feed.state === "truncated") return "amber";
  if (feed.state === "completed") return "green";
  return "neutral";
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

const RETRYABLE_STATUS = new Set([502, 503, 504]);

async function apiGetWithRetry<T>(path: string, attempts = 8): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await apiRequest<T>(path);
    } catch (reason) {
      lastError = reason;
      const retryable = reason instanceof ApiError
        ? RETRYABLE_STATUS.has(reason.status) || reason.status === 429
        : true;
      if (!retryable || attempt === attempts - 1) throw reason;
      await delay(Math.min(2000, 500 * (attempt + 1)));
    }
  }
  throw lastError;
}

type LiveRun = {
  scanId: string | null;
  scopeId: string;
  target: string;
  profileId: string;
  state: ScanState | string;
  result: ScanResult | null;
  error: string | null;
};

type LastRun = {
  scopeId: string;
  target: string;
  profiles: string[];
  requiresDns: boolean;
};

export default function Targets() {
  const [refresh, setRefresh] = useState(0);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", refresh);
  const scopesQuery = useApiResource<{ items: EngineScope[] }>("/engine/scopes", refresh);
  const readinessQuery = useApiResource<Readiness>("/engine/readiness", refresh);
  const status = statusQuery.data;
  const intelSchedule = status?.intel.schedule;
  const profiles = status?.profiles ?? [];

  const availableTools = useMemo(() => {
    const order = [
      "service_inventory_v1",
      "passive_subdomain_v1",
      "tls_metadata_v1",
      "synthetic_inventory_v1",
    ];
    return order.filter((profileId) => profiles.includes(profileId));
  }, [profiles]);

  const defaultProfiles = useMemo(() => {
    const preferred = ["service_inventory_v1", "passive_subdomain_v1"].filter(
      (profileId) => availableTools.includes(profileId),
    );
    if (preferred.length > 0) return preferred;
    if (availableTools.includes("tls_metadata_v1")) return ["tls_metadata_v1"];
    return availableTools.slice(0, 1);
  }, [availableTools]);

  const [target, setTarget] = useState("");
  const [scopeId, setScopeId] = useState("");
  const [expires, setExpires] = useState("24");
  const [nmapLevel, setNmapLevel] = useState<ScanLevel>("normal");
  const [subfinderLevel, setSubfinderLevel] = useState<ScanLevel>("normal");
  const [dnsCheckEnabled, setDnsCheckEnabled] = useState(false);
  const [challenge, setChallenge] = useState<AuthorizationChallenge | null>(null);
  const [authorization, setAuthorization] = useState<TargetAuthorization | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedProfiles, setSelectedProfiles] = useState<string[] | null>(null);
  const [runs, setRuns] = useState<LiveRun[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const [lastRun, setLastRun] = useState<LastRun | null>(null);
  const activeRef = useRef(true);

  const [guardText, setGuardText] = useState(demoPrompt);
  const [guardResult, setGuardResult] = useState<GuardInspection | null>(null);
  const [guardBusy, setGuardBusy] = useState(false);
  const [guardError, setGuardError] = useState<string | null>(null);

  const [intelBusy, setIntelBusy] = useState(false);
  const [intelNotice, setIntelNotice] = useState<string | null>(null);
  const [intelError, setIntelError] = useState<string | null>(null);

  const selectedBaseProfiles = (selectedProfiles ?? defaultProfiles).filter(
    (profileId) => availableTools.includes(profileId),
  );
  const nmapSelected = selectedBaseProfiles.includes("service_inventory_v1");
  const subfinderSelected = selectedBaseProfiles.includes("passive_subdomain_v1");
  const hasDepthTool = nmapSelected || subfinderSelected;
  const effectiveProfiles = useMemo(() => {
    const ids: string[] = [];
    for (const profileId of selectedBaseProfiles) {
      if (profileId === "service_inventory_v1") {
        ids.push(LEVEL_PROFILE_IDS.nmap[nmapLevel]);
      } else if (profileId === "passive_subdomain_v1") {
        ids.push(LEVEL_PROFILE_IDS.subfinder[subfinderLevel]);
      } else {
        ids.push(profileId);
      }
    }
    return ids.filter((profileId) => profiles.includes(profileId));
  }, [selectedBaseProfiles, nmapLevel, subfinderLevel, profiles]);
  const normalizedTarget = normalizeTarget(target);
  const authorizationValidFor = (host: string) => authorization !== null
    && authorization.target === host
    && new Date(authorization.expiresAt).getTime() > Date.now();
  const requiresDns =
    (nmapSelected && scanLevelRequiresAuthorization(nmapLevel))
    || (subfinderSelected && scanLevelRequiresAuthorization(subfinderLevel));
  const dnsRequested = hasDepthTool && (requiresDns || dnsCheckEnabled);
  const dnsAuthorizationValid = dnsRequested && authorizationValidFor(normalizedTarget.host);
  const authorizationSatisfied = !dnsRequested || dnsAuthorizationValid;
  const lastRunAuthorizationSatisfied = lastRun === null
    || !lastRun.requiresDns
    || authorizationValidFor(lastRun.target);

  useEffect(() => {
    activeRef.current = true;
    return () => {
      activeRef.current = false;
    };
  }, []);

  const onTargetChange = (value: string) => {
    setTarget(value);
    setError(null);
    setChallenge(null);
    setAuthorization(null);
    setVerificationError(null);
    const normalized = normalizeTarget(value);
    if (!normalized.error) setScopeId(scopeIdFor(normalized.host));
  };

  const onProfileLevelChange = (tool: "nmap" | "subfinder", level: ScanLevel) => {
    if (tool === "nmap") setNmapLevel(level);
    else setSubfinderLevel(level);
    setChallenge(null);
    setAuthorization(null);
    setVerificationError(null);
    setError(null);
  };

  const onDnsCheckChange = (enabled: boolean) => {
    setDnsCheckEnabled(enabled);
    setChallenge(null);
    setAuthorization(null);
    setVerificationError(null);
    setError(null);
  };

  const startVerification = async () => {
    setVerificationError(null);
    if (normalizedTarget.error) {
      setVerificationError(normalizedTarget.error);
      return;
    }
    setVerifying(true);
    try {
      const response = await apiRequest<AuthorizationChallenge>(
        "/engine/authorizations/challenges",
        {
          method: "POST",
          body: JSON.stringify({ domain: normalizedTarget.host }),
        },
      );
      setChallenge(response);
      setAuthorization(null);
    } catch (reason) {
      setVerificationError(messageOf(reason));
    } finally {
      setVerifying(false);
    }
  };

  const checkVerification = async () => {
    if (!challenge) return;
    setVerificationError(null);
    setVerifying(true);
    try {
      const response = await apiRequest<TargetAuthorization>("/engine/authorizations", {
        method: "POST",
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          profileIds: effectiveProfiles,
        }),
      });
      setAuthorization(response);
      setChallenge(null);
    } catch (reason) {
      setVerificationError(messageOf(reason));
    } finally {
      setVerifying(false);
    }
  };

  const updateRun = (scanId: string, patch: Partial<LiveRun>) => {
    setRuns((current) => current.map((run) => (
      run.scanId === scanId ? { ...run, ...patch } : run
    )));
  };

  const waitForRun = async (run: LiveRun, timeoutSeconds: number) => {
    if (!run.scanId) return;
    const pollMilliseconds = timeoutSeconds > 300 ? 5000 : 1000;
    const attempts = Math.ceil((timeoutSeconds * 1000) / pollMilliseconds) + 30;
    let state = run.state;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (TERMINAL_SCAN_STATES.has(state)) break;
      await delay(pollMilliseconds);
      if (!activeRef.current) return;
      try {
        const next = await apiGetWithRetry<ScanStatus>(`/engine/scans/${run.scanId}`);
        state = next.state;
        updateRun(run.scanId, { state });
      } catch (reason) {
        updateRun(run.scanId, { state: "failed", error: messageOf(reason) });
        return;
      }
    }
    if (!TERMINAL_SCAN_STATES.has(state)) {
      updateRun(run.scanId, {
        state: "timed_out",
        error: `The scan did not finish within ${Math.ceil(timeoutSeconds / 60)} minutes.`,
      });
      return;
    }
    try {
      const result = await apiGetWithRetry<ScanResult>(`/engine/scans/${run.scanId}/result`);
      if (!activeRef.current) return;
      updateRun(run.scanId, { result, state: result.state });
    } catch (reason) {
      updateRun(run.scanId, { error: messageOf(reason) });
    }
  };

  const beginScans = async (
    scopeIdValue: string,
    targetValue: string,
    profileValues: string[],
    requiresDnsValue: boolean,
  ) => {
    setScanError(null);
    setPolling(true);
    setRuns([]);
    setLastRun({
      scopeId: scopeIdValue,
      target: targetValue,
      profiles: profileValues,
      requiresDns: requiresDnsValue,
    });

    const started: LiveRun[] = [];
    for (const profileId of profileValues) {
      try {
        const response = await apiRequest<ScanStatus>("/engine/scans", {
          method: "POST",
          body: JSON.stringify({
            authorized: true,
            scopeId: scopeIdValue,
            target: targetValue,
            profileId,
          }),
        });
        started.push({
          scanId: response.scanId,
          scopeId: scopeIdValue,
          target: targetValue,
          profileId,
          state: response.state,
          result: null,
          error: null,
        });
      } catch (reason) {
        started.push({
          scanId: null,
          scopeId: scopeIdValue,
          target: targetValue,
          profileId,
          state: "failed",
          result: null,
          error: messageOf(reason),
        });
      }
    }

    if (!activeRef.current) return;
    setRuns(started);
    setRefresh((value) => value + 1);
    const batchTimeoutSeconds = profileValues.reduce(
      (total, profileId) => total + profileTimeoutSeconds(profileId),
      0,
    ) + 60;
    await Promise.all(
      started
        .filter((run) => run.scanId !== null)
        .map((run) => waitForRun(run, batchTimeoutSeconds)),
    );
    if (activeRef.current) setPolling(false);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const normalized = normalizeTarget(target);
    if (normalized.error) {
      setError(normalized.error);
      return;
    }
    if (effectiveProfiles.length === 0) {
      setError("Select at least one scan profile.");
      return;
    }
    if (dnsRequested && !dnsAuthorizationValid) {
      setError(
        requiresDns
          ? "High and deep scans require DNS TXT ownership verification before the scope is created."
          : "DNS TXT verification is required because the DNS ownership check is enabled.",
      );
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
          environment: dnsRequested ? "isolated_lab" : "synthetic",
          profiles: effectiveProfiles,
          expiresInHours: Number(expires),
          ...(dnsRequested && authorization
            ? { authorizationId: authorization.authorizationId }
            : {}),
        }),
      });
      setRefresh((value) => value + 1);
      await beginScans(
        chosenScope,
        normalized.host,
        effectiveProfiles,
        dnsRequested,
      );
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setBusy(false);
    }
  };

  const runAgain = async () => {
    if (!lastRun || lastRun.profiles.length === 0) return;
    if (lastRun.requiresDns && !authorizationValidFor(lastRun.target)) {
      setError("Verify DNS TXT ownership for this run before running it again.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await beginScans(
        lastRun.scopeId,
        lastRun.target,
        lastRun.profiles,
        lastRun.requiresDns,
      );
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

  const runFeed = async (source: "nvd" | "epss") => {
    setIntelBusy(true);
    setIntelNotice(null);
    setIntelError(null);
    try {
      const response = await apiRequest<{ results?: Array<{ source: string; state: string; factCount?: number; error?: string | null }> }>(
        `/engine/intel/schedule/run?source=${source}`,
        { method: "POST" },
      );
      const result = response.results?.find((item) => item.source === source);
      if (!result) {
        setIntelError(`${source.toUpperCase()} did not return a scheduler result.`);
      } else if (result.error) {
        setIntelError(`${source.toUpperCase()} failed: ${result.error}`);
      } else if (result.state === "truncated") {
        setIntelNotice(`${source.toUpperCase()} returned a partial page set; the engine saved a checkpoint for the next run.`);
      } else if (result.state !== "completed") {
        setIntelError(`${source.toUpperCase()} ended in state: ${result.state}.`);
      } else {
        setIntelNotice(`${source.toUpperCase()} loaded: ${result.factCount ?? 0} records parsed.`);
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

  const terminalRunCount = runs.filter((run) => TERMINAL_SCAN_STATES.has(run.state)).length;
  const failedRunCount = runs.filter((run) => (
    run.error !== null || run.state === "failed" || run.state === "timed_out"
  )).length;
  const scanLabel = runs.length === 0
    ? "no run"
    : polling
      ? `running ${terminalRunCount}/${runs.length}`
      : `${terminalRunCount}/${runs.length} complete`;
  const batchState = polling ? "running" : failedRunCount > 0 ? "partial" : "completed";
  const assets = [...new Set(runs.flatMap((run) => run.result?.assets ?? []))];
  const services = [
    ...new Map(
      runs
        .flatMap((run) => run.result?.services ?? [])
        .map((service) => [
          `${service.asset}|${service.protocol}|${service.port}|${service.product ?? ""}|${service.version ?? ""}`,
          service,
        ]),
    ).values(),
  ];
  const tlsFindings = [
    ...new Map(
      runs
        .flatMap((run) => run.result?.tlsFindings ?? [])
        .map((finding) => [
          `${finding.subject}|${finding.issuer}|${finding.expires_at}|${finding.status}`,
          finding,
        ]),
    ).values(),
  ];
  const warnings = [...new Set(runs.flatMap((run) => run.result?.warnings ?? []))];

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
        <small>The selected profiles run bounded, read-only checks: Nmap uses a TCP connect scan, Subfinder uses passive discovery, and TLS opens one metadata connection. They do not exploit, brute-force, or modify the target. Scope and scan creation both require an explicit authorization confirmation.</small>
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
      <Panel title="Add an authorized target" subtitle="Choose a level for each tool. High and Deep require DNS TXT ownership verification; Normal and Medium use the bounded operator acknowledgement. The scope is created first, then one scan is queued per selected profile." tag="OPERATOR ACTION">
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
              <small>The engine requires a dotted domain or IPv4 address. A URL is reduced to its hostname; the path is never requested. Use the DNS TXT check for High or Deep scans of internet hosts.</small>
            </div>
            <div className="field">
              <label htmlFor="scope-input">Scope ID</label>
              <input id="scope-input" value={scopeId} onChange={(event) => setScopeId(event.target.value)} placeholder="scope-example-com" spellCheck={false} autoComplete="off" />
              <small>Approved scope records are owned by the local engine operator.</small>
            </div>
            <div className="field field-wide">
              <label>Scan profiles</label>
              <div className="profile-picker">
                {availableTools.map((item) => {
                  const isNmap = item === "service_inventory_v1";
                  const isSubfinder = item === "passive_subdomain_v1";
                  const level = isNmap ? nmapLevel : isSubfinder ? subfinderLevel : null;
                  const levelInfo = SCAN_LEVELS.find((entry) => entry.id === level);
                  const selected = selectedBaseProfiles.includes(item);
                  return (
                    <div className={`profile-choice${selected ? " selected" : ""}`} key={item}>
                      <label className="profile-choice-head">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={(event) => {
                            const checked = event.target.checked;
                            if (!checked && (isNmap || isSubfinder)) {
                              const remaining = selectedBaseProfiles.filter((profileId) => profileId !== item);
                              if (!remaining.some((profileId) => profileId === "service_inventory_v1" || profileId === "passive_subdomain_v1")) {
                                setDnsCheckEnabled(false);
                              }
                            }
                            setSelectedProfiles((current) => {
                              const base = current ?? selectedBaseProfiles;
                              return checked
                                ? Array.from(new Set([...base, item]))
                                : base.filter((profileId) => profileId !== item);
                            });
                            setAuthorization(null);
                            setChallenge(null);
                            setVerificationError(null);
                          }}
                        />
                        <span>
                          <b>{PROFILE_SHORT_LABELS[item] ?? item}</b>
                          <small>{PROFILE_LABELS[item] ?? item}</small>
                        </span>
                      </label>
                      {level && levelInfo && (
                        <label className="profile-level">
                          <span>Scan level</span>
                          <select
                            value={level}
                            onChange={(event) => onProfileLevelChange(
                              isNmap ? "nmap" : "subfinder",
                              event.target.value as ScanLevel,
                            )}
                            disabled={!selected}
                          >
                            {SCAN_LEVELS.map((option) => (
                              <option key={option.id} value={option.id}>
                                {option.label}{option.requiresAuthorization ? " (TXT)" : ""}
                              </option>
                            ))}
                          </select>
                          <small>
                            {isNmap ? levelInfo.nmap : levelInfo.subfinder}
                            {levelInfo.requiresAuthorization ? " · DNS TXT required" : ""}
                          </small>
                        </label>
                      )}
                    </div>
                  );
                })}
              </div>
              <small>Each Nmap and Subfinder card has its own scan level. Normal is the default; High and Deep require DNS TXT.</small>
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
          <label className="checkbox-row public-mode-row" htmlFor="dns-check">
            <input
              id="dns-check"
              type="checkbox"
              checked={dnsRequested}
              disabled={!hasDepthTool || requiresDns}
              onChange={(event) => onDnsCheckChange(event.target.checked)}
            />
            <span><b>DNS TXT ownership check.</b> Required for High and Deep; optional for Normal and Medium. Check this to create a DNS challenge for Nmap or Subfinder.</span>
          </label>
          {dnsRequested && (
            <div className="verification-panel">
              <div className="verification-head">
                <div>
                  <b>{requiresDns ? "DNS ownership verification required" : "Optional DNS ownership verification"}</b>
                  <small>High and Deep require this check; Normal and Medium may use it optionally. Add the record below at your DNS provider, then check it here. The authorization is bound to the selected profiles.</small>
                </div>
                <StateTag tone={dnsAuthorizationValid ? "green" : "amber"}>
                  {dnsAuthorizationValid ? "VERIFIED" : "NOT VERIFIED"}
                </StateTag>
              </div>
              {dnsAuthorizationValid && authorization ? (
                <div className="console-alert success" role="status">
                  <CheckCircle2 size={15} />
                  <span><b>DNS ownership verified.</b> {authorization.target} is authorized until {new Date(authorization.expiresAt).toLocaleString()}.</span>
                </div>
              ) : (
                <>
                  {!challenge && (
                    <button
                      className="button button-ghost"
                      type="button"
                      onClick={() => void startVerification()}
                      disabled={verifying || Boolean(normalizedTarget.error)}
                    >
                      <ShieldCheck size={15} />{verifying ? "Creating record…" : "Create DNS challenge"}
                    </button>
                  )}
                  {challenge && (
                    <div className="verification-record">
                      <small>Create this DNS TXT record, then wait for it to propagate:</small>
                      <div><span>NAME</span><code>{challenge.recordName}</code></div>
                      <div><span>VALUE</span><code>{challenge.token}</code></div>
                      <small>Expires {new Date(challenge.expiresAt).toLocaleString()}. The record is checked against public DNS.</small>
                      <div className="verification-actions">
                        <button
                          className="button button-primary"
                          type="button"
                          onClick={() => void checkVerification()}
                          disabled={verifying || effectiveProfiles.length === 0}
                        >
                          <ShieldCheck size={15} />{verifying ? "Checking DNS…" : "Check DNS and authorize"}
                        </button>
                      </div>
                    </div>
                  )}
                  {verificationError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{verificationError}</span></div>}
                </>
              )}
            </div>
          )}
          {error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{error}</span></div>}
          <div className="form-actions">
            <button className="button button-primary" type="submit" disabled={busy || !status || !authorizationSatisfied || effectiveProfiles.length === 0}>
              <Crosshair size={15} />{busy ? (polling ? "Running selected scans…" : "Starting scans…") : "Create scope & run selected scans"}
            </button>
            <button className="button button-ghost" type="button" onClick={() => void runAgain()} disabled={busy || !lastRun || !lastRunAuthorizationSatisfied || polling}>
              <RefreshCcw size={15} />Run again
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="Live scans" subtitle="Runs one queued scan per selected profile and combines the results below." tag={scanLabel.toUpperCase()}>
        {scanError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{scanError}</span></div>}
        {runs.length === 0 && <div className="empty-console">
          <ScanLine size={22} />
          <b>No live scans yet</b>
          <p>Select Nmap, Subfinder, or another tool above, set each tool's scan level, complete DNS TXT verification when required or when the blue check is enabled, and create the scope. The selected scans run independently and their results are combined here.</p>
        </div>}
        {runs.length > 0 && <>
          <div className="engine-state-row">
            <StateTag tone={scanTone(batchState)}>{batchState.toUpperCase()}</StateTag>
            <CodeLabel>{runs.length} PROFILE(S)</CodeLabel>
            {polling && <span className="engine-status"><RefreshCcw className="spin" size={12} /> polling engine</span>}
          </div>
          <div className="scope-list">
            {runs.map((run) => <div className="scope-row" key={`${run.profileId}-${run.scanId ?? "missing"}`}>
              <div><b>{PROFILE_SHORT_LABELS[run.profileId] ?? run.profileId}</b><small>{run.scanId ?? "scan was not created"}</small></div>
              <div><small>{run.error ?? (run.result ? `${run.result.assets.length} asset(s) / ${run.result.services.length} service(s)` : "Waiting for result")}</small></div>
              <StateTag tone={scanTone(run.state)}>{run.state.toUpperCase()}</StateTag>
            </div>)}
          </div>
          <div className="result-grid">
            <div className="result-card"><span>TARGET</span><b>{lastRun?.target ?? "—"}</b><small>{lastRun?.scopeId ?? ""}</small></div>
            <div className="result-card"><span>PROFILES</span><b>{runs.length}</b><small>{runs.map((run) => PROFILE_SHORT_LABELS[run.profileId] ?? run.profileId).join(", ")}</small></div>
            <div className="result-card"><span>ASSETS / SERVICES</span><b>{assets.length} / {services.length}</b><small>{tlsFindings.length} TLS finding(s)</small></div>
          </div>
          {tlsFindings.map((finding) => <div className="tls-block" key={`${finding.subject}-${finding.expires_at}-${finding.status}`}>
            <div className="panel-tag">TLS METADATA</div>
            <div className="kv-list">
              <div className="kv-row"><span>SUBJECT</span><b>{finding.subject}</b></div>
              <div className="kv-row"><span>ISSUER</span><b>{finding.issuer}</b></div>
              <div className="kv-row"><span>EXPIRES</span><b>{finding.expires_at}</b></div>
              <div className="kv-row"><span>STATUS</span><b>{finding.status}</b></div>
            </div>
          </div>)}
          {assets.length > 0 && <div className="tls-block">
            <div className="panel-tag">ASSETS</div>
            <div className="kv-list">{assets.map((asset) => <div className="kv-row" key={asset}><span>ASSET</span><b>{asset}</b></div>)}</div>
          </div>}
          {services.length > 0 && <div className="tls-block">
            <div className="panel-tag">SERVICES</div>
            <div className="kv-list">{services.map((service, index) => <div className="kv-row" key={`${service.asset}-${service.protocol}-${service.port}-${index}`}><span>{service.protocol.toUpperCase()} / {service.port}</span><b>{service.asset} · {service.product ?? "unknown"}{service.version ? ` ${service.version}` : ""}</b></div>)}</div>
          </div>}
          {warnings.map((warning) => <div className="console-alert info" key={warning}><TriangleAlert size={15} /><span>{warning}</span></div>)}
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
            <div className="result-card"><span>EPSS RECORDS</span><b>{status.intel.epssRecords ?? 0}</b><small>Exploit prediction scores</small></div>
            <div className="result-card"><span>NVD CHECKPOINT</span><b>{status.intel.nvdCheckpoint ?? "complete"}</b><small>Resume point for a truncated page run</small></div>
          </div>
          <div className="form-actions">
            <button className="button button-ghost" onClick={() => void syncKev()} disabled={intelBusy || !status}>
              <RefreshCcw className={intelBusy ? "spin" : undefined} size={15} />{intelBusy ? "Fetching CISA KEV…" : "Sync CISA KEV"}
            </button>
            <button className="button button-ghost" onClick={() => void runFeed("nvd")} disabled={intelBusy || !status}>
              <RefreshCcw className={intelBusy ? "spin" : undefined} size={15} />Run NVD now
            </button>
            <button className="button button-ghost" onClick={() => void runFeed("epss")} disabled={intelBusy || !status}>
              <RefreshCcw className={intelBusy ? "spin" : undefined} size={15} />Run EPSS now
            </button>
          </div>
          {intelNotice && <div className="console-alert success" role="status"><ShieldCheck size={15} /><span>{intelNotice}</span></div>}
          {intelError && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{intelError}</span></div>}
          {intelSchedule && <div className="kv-list">
            <div className="kv-row"><span>SCHEDULER</span><b>{intelSchedule.enabled ? (intelSchedule.running ? "running" : "enabled, stopped") : "disabled"}</b></div>
            {Object.entries(intelSchedule.feeds).map(([name, feed]) => <div className="kv-row intel-feed-row" key={name}>
              <span>{name.toUpperCase()}</span>
              <div>
                <b>{feed.state} | {ageLabel(feed.lastCompleted)} | {feed.lastFactCount} record(s)</b>
                <small>next {feed.nextRun ? new Date(feed.nextRun).toLocaleString() : "not scheduled"}{feed.lastError ? ` | ${feed.lastError}` : ""}</small>
              </div>
              <StateTag tone={feedTone(feed)}>{feed.state.toUpperCase()}</StateTag>
            </div>)}
          </div>}
          <div className="kv-list">
            {Object.entries(status.intel.feeds).map(([name, url]) => <div className="kv-row" key={name}><span>{name.toUpperCase()}</span><b>{url}</b></div>)}
          </div>
          <div className="small-warning"><FileText size={15} /><span>NVD, EPSS, and CISA KEV are refreshed by the engine scheduler. This console exposes manual KEV sync plus on-demand NVD/EPSS scheduler runs; direct ingestion remains available through the engine&apos;s <code>/api/v1/intel/ingestions</code> endpoint.</span></div>
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
