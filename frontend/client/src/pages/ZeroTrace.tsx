import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  BadgeCheck,
  CircleAlert,
  Crosshair,
  Fingerprint,
  Globe2,
  KeyRound,
  Play,
  Radar,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import { useSelectedTarget } from "@/lib/selectedTarget";
import {
  LEVEL_PROFILE_IDS,
  PROFILE_SHORT_LABELS,
  SCAN_LEVELS,
  TERMINAL_SCAN_STATES,
  profileTimeoutSeconds,
  scanLevelRequiresAuthorization,
  scopeIdFor,
  type AuthorizationChallenge,
  type EngineScope,
  type EngineStatus,
  type ScanLevel,
  type ScanStatus,
} from "@/lib/liveEngine";

type TargetAuthorization = { authorizationId: string; target: string; expiresAt: string };
type RunStep = { profileId: string; scanId: string; state: string; error?: string };

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

export default function ZeroTrace() {
  const { selection, select } = useSelectedTarget();
  const [refresh, setRefresh] = useState(0);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", refresh);
  const scopesQuery = useApiResource<{ items: EngineScope[] }>("/engine/scopes", refresh);
  const status = statusQuery.data;
  const scopes = scopesQuery.data?.items ?? [];
  const [scopeId, setScopeId] = useState("");
  const [target, setTarget] = useState("");
  const [nmapLevel, setNmapLevel] = useState<ScanLevel>("normal");
  const [subfinderLevel, setSubfinderLevel] = useState<ScanLevel>("normal");
  const [challenge, setChallenge] = useState<AuthorizationChallenge | null>(null);
  const [authorization, setAuthorization] = useState<TargetAuthorization | null>(null);
  const [authBusy, setAuthBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<RunStep[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const activeRef = useRef(true);

  useEffect(() => {
    activeRef.current = true;
    return () => { activeRef.current = false; };
  }, []);

  useEffect(() => {
    if (!scopeId && scopes.length > 0) {
      setScopeId(scopes[0].scopeId);
      setTarget(scopes[0].targets[0] ?? "");
    }
  }, [scopeId, scopes]);

  useEffect(() => {
    if (selection) {
      setTarget(selection.target);
      setScopeId(selection.scopeId);
      setNmapLevel(selection.nmapLevel);
      setSubfinderLevel(selection.subfinderLevel);
    }
  }, [selection]);

  const selectedScope = scopes.find((scope) => scope.scopeId === scopeId) ?? null;
  const availableProfiles = status?.profiles ?? [];
  const profiles = useMemo(() => {
    const wanted = [
      LEVEL_PROFILE_IDS.nmap[nmapLevel],
      LEVEL_PROFILE_IDS.subfinder[subfinderLevel],
      "tls_metadata_v1",
      "synthetic_inventory_v1",
    ];
    return wanted.filter((profileId) => availableProfiles.includes(profileId));
  }, [availableProfiles, nmapLevel, subfinderLevel]);
  const requiresAuthorization = scanLevelRequiresAuthorization(nmapLevel) || scanLevelRequiresAuthorization(subfinderLevel);
  const ready = Boolean(target && selectedScope && profiles.length > 0 && (!requiresAuthorization || authorization));
  const selectedTargetLabel = target || "No target selected";

  const chooseScope = (nextScopeId: string) => {
    setScopeId(nextScopeId);
    const scope = scopes.find((item) => item.scopeId === nextScopeId);
    setTarget(scope?.targets[0] ?? "");
    setChallenge(null);
    setAuthorization(null);
    setError(null);
    setNotice(null);
  };

  const chooseTarget = (nextTarget: string) => {
    setTarget(nextTarget);
    setChallenge(null);
    setAuthorization(null);
    setError(null);
    setNotice(null);
  };

  const createChallenge = async () => {
    setAuthBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await apiRequest<AuthorizationChallenge>("/engine/authorizations/challenges", {
        method: "POST",
        body: JSON.stringify({ domain: target }),
      });
      setChallenge(created);
      setAuthorization(null);
      setNotice("DNS TXT challenge created. Publish the record, then verify it.");
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setAuthBusy(false);
    }
  };

  const verifyChallenge = async () => {
    if (!challenge) return;
    setAuthBusy(true);
    setError(null);
    setNotice(null);
    try {
      const verified = await apiRequest<TargetAuthorization>("/engine/authorizations", {
        method: "POST",
        body: JSON.stringify({ challengeId: challenge.challengeId, profileIds: profiles }),
      });
      setAuthorization(verified);
      setNotice("DNS TXT verified. High/Deep profiles are authorized for this run.");
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setAuthBusy(false);
    }
  };

  const run = async () => {
    if (!target || !selectedScope) {
      setError("Select a saved target first.");
      return;
    }
    setRunning(true);
    setError(null);
    setNotice(null);
    setSteps(profiles.map((profileId) => ({ profileId, scanId: "", state: "queued" })));
    try {
      const nextScopeId = selectedScope.scopeId;
      await apiRequest<EngineScope>("/engine/scopes", {
        method: "POST",
        body: JSON.stringify({
          authorized: true,
          scopeId: nextScopeId,
          targets: [target],
          environment: requiresAuthorization ? "isolated_lab" : "synthetic",
          profiles,
          expiresInHours: 24,
          ...(requiresAuthorization && authorization ? { authorizationId: authorization.authorizationId } : {}),
        }),
      });

      const created: RunStep[] = [];
      for (const profileId of profiles) {
        const response = await apiRequest<{ scanId: string; state: string }>("/engine/scans", {
          method: "POST",
          body: JSON.stringify({
            authorized: true,
            scopeId: nextScopeId,
            target,
            profileId,
          }),
        });
        created.push({ profileId, scanId: response.scanId, state: response.state });
        setSteps([...created]);
      }

      select({
        target,
        scopeId: nextScopeId,
        profiles,
        nmapLevel,
        subfinderLevel,
        selectedAt: new Date().toISOString(),
      });

      await Promise.all(created.map(async (step) => {
        const deadline = Date.now() + (profileTimeoutSeconds(step.profileId) + 45) * 1000;
        let state = step.state;
        while (!TERMINAL_SCAN_STATES.has(state) && Date.now() < deadline && activeRef.current) {
          await wait(1500);
          if (!activeRef.current) return;
          try {
            const next = await apiRequest<ScanStatus>(`/engine/scans/${step.scanId}`);
            state = next.state;
            setSteps((current) => current.map((item) => (
              item.scanId === step.scanId ? { ...item, state } : item
            )));
          } catch (reason) {
            setSteps((current) => current.map((item) => (
              item.scanId === step.scanId ? { ...item, state: "failed", error: messageOf(reason) } : item
            )));
            return;
          }
        }
        if (!TERMINAL_SCAN_STATES.has(state)) {
          setSteps((current) => current.map((item) => (
            item.scanId === step.scanId ? { ...item, state: "timed_out" } : item
          )));
        }
      }));

      setNotice("Recon finished. Trace Recon and Intel Guard now hold this target's evidence.");
      setRefresh((value) => value + 1);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      if (activeRef.current) setRunning(false);
    }
  };

  return <>
    <PageHeading
      eyebrow="ZEROTRACE / 00 · START"
      title="ZeroTrace"
      description="Select a saved target, choose the Nmap and Subfinder levels, and run one bounded trace. Recon evidence lands in Trace Recon; correlated risk lands in Intel Guard."
      actions={<StateTag tone={status ? "green" : statusQuery.loading ? "blue" : "red"}>{status ? "ENGINE CONNECTED" : statusQuery.loading ? "CONNECTING" : "ENGINE OFFLINE"}</StateTag>}
    />

    <section className="zero-hero">
      <div className="zero-hero-copy">
        <div className="eyebrow">AUTHORIZED TRACE · LOCAL ENGINE</div>
        <h2>One target. Four bounded reads. One evidence chain.</h2>
        <p>ZeroTrace is the starting point. It reads the target list you saved in Admin, opens a short-lived scope, and runs Nmap, Subfinder, TLS metadata, and synthetic inventory. It does not exploit, brute-force, or change the target.</p>
        <div className="inline-tags">
          <StateTag tone="blue">NMAP</StateTag>
          <StateTag tone="blue">SUBFINDER</StateTag>
          <StateTag tone="blue">TLS METADATA</StateTag>
          <StateTag tone="blue">SYNTHETIC INVENTORY</StateTag>
        </div>
      </div>
      <div className="zero-hero-diagram" aria-hidden="true">
        <div className="zero-orbit zero-orbit-one" />
        <div className="zero-orbit zero-orbit-two" />
        <div className="zero-core"><Fingerprint size={34} /><span>00</span></div>
        <div className="zero-satellite satellite-one"><Radar size={16} /><span>Recon</span></div>
        <div className="zero-satellite satellite-two"><Workflow size={16} /><span>Intel</span></div>
        <div className="zero-satellite satellite-three"><ShieldCheck size={16} /><span>Guard</span></div>
      </div>
    </section>

    <div className="two-column zero-run-layout">
      <Panel title="Run a trace" subtitle="The scope is re-created for this run so the selected Nmap and Subfinder levels are explicit." tag="START HERE">
        {statusQuery.error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{statusQuery.error}</span></div>}
        {scopes.length === 0 ? (
          <div className="empty-console">
            <Globe2 size={22} />
            <b>No saved targets</b>
            <p>Add an authorized target in Admin → Targets &amp; scope, then return here.</p>
            <Link href="/admin" className="button button-primary">Open Admin <ArrowRight size={15} /></Link>
          </div>
        ) : (
          <div className="zero-form">
            <div className="field-grid">
              <div className="field">
                <label htmlFor="zero-scope">Saved scope</label>
                <select id="zero-scope" value={scopeId} onChange={(event) => chooseScope(event.target.value)} disabled={running}>
                  {scopes.map((scope) => (
                    <option key={scope.scopeId} value={scope.scopeId}>{scope.scopeId}</option>
                  ))}
                </select>
                <small>{selectedScope ? `${selectedScope.profiles.length} saved profile(s) · expires ${new Date(selectedScope.expiresAt).toLocaleString()}` : "Choose a scope"}</small>
              </div>
              <div className="field">
                <label htmlFor="zero-target">Target</label>
                <select id="zero-target" value={target} onChange={(event) => chooseTarget(event.target.value)} disabled={running}>
                  {(selectedScope?.targets ?? []).map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
                <small>Only targets saved by an operator appear here.</small>
              </div>
              <div className="field">
                <label htmlFor="zero-nmap">Nmap level</label>
                <select id="zero-nmap" value={nmapLevel} onChange={(event) => { setNmapLevel(event.target.value as ScanLevel); setAuthorization(null); setChallenge(null); }} disabled={running}>
                  {SCAN_LEVELS.map((level) => <option key={level.id} value={level.id}>{level.label} — {level.nmap}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="zero-subfinder">Subfinder level</label>
                <select id="zero-subfinder" value={subfinderLevel} onChange={(event) => { setSubfinderLevel(event.target.value as ScanLevel); setAuthorization(null); setChallenge(null); }} disabled={running}>
                  {SCAN_LEVELS.map((level) => <option key={level.id} value={level.id}>{level.label} — {level.subfinder}</option>)}
                </select>
              </div>
            </div>

            <div className="saved-profile-strip">
              <span>RUN PROFILES</span>
              {profiles.length ? profiles.map((profileId) => (
                <CodeLabel key={profileId}>{PROFILE_SHORT_LABELS[profileId] ?? profileId}</CodeLabel>
              )) : <CodeLabel>NO AVAILABLE PROFILES</CodeLabel>}
            </div>

            {requiresAuthorization && (
              <div className="authorization-box">
                <div className="authorization-head"><KeyRound size={16} /><div><b>High/Deep needs a DNS TXT authorization</b><small>The engine checks a TXT record before it accepts the elevated profile.</small></div></div>
                {!challenge ? (
                  <button className="button button-ghost" type="button" onClick={() => void createChallenge()} disabled={authBusy || running || !target}>
                    <KeyRound size={15} />{authBusy ? "Creating challenge…" : "Create DNS challenge"}
                  </button>
                ) : (
                  <div className="authorization-record">
                    <div className="kv-row"><span>RECORD</span><b><code>{challenge.recordName}</code></b></div>
                    <div className="kv-row"><span>VALUE</span><b><code>{challenge.token}</code></b></div>
                    <div className="kv-row"><span>EXPIRES</span><b>{new Date(challenge.expiresAt).toLocaleString()}</b></div>
                    <div className="form-actions">
                      <button className="button button-primary" type="button" onClick={() => void verifyChallenge()} disabled={authBusy || running}>
                        <BadgeCheck size={15} />{authBusy ? "Verifying…" : "Verify DNS and authorize"}
                      </button>
                      <button className="button button-ghost" type="button" onClick={() => void createChallenge()} disabled={authBusy || running}>New challenge</button>
                    </div>
                    {authorization && <div className="console-alert success"><BadgeCheck size={15} /><span>Authorized until {new Date(authorization.expiresAt).toLocaleString()}.</span></div>}
                  </div>
                )}
              </div>
            )}

            {error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{error}</span></div>}
            {notice && <div className="console-alert success" role="status"><Sparkles size={15} /><span>{notice}</span></div>}

            <div className="form-actions zero-run-actions">
              <button className="button button-primary button-run" type="button" onClick={() => void run()} disabled={!ready || running}>
                <Play size={16} />{running ? "Running bounded trace…" : `Run ${selectedTargetLabel}`}
              </button>
              <span className="run-hint">{requiresAuthorization && !authorization ? "Authorize the DNS TXT challenge to continue." : "The run is bounded and read-only."}</span>
            </div>

            {steps.length > 0 && (
              <div className="run-progress">
                {steps.map((step) => (
                  <div className="run-step" key={step.profileId}>
                    <span className={`run-step-dot state-${step.state}`} />
                    <div><b>{PROFILE_SHORT_LABELS[step.profileId] ?? step.profileId}</b><small>{step.error ?? step.state}</small></div>
                    <CodeLabel>{step.scanId.slice(0, 8) || "queued"}</CodeLabel>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Panel>

      <Panel title="How it works" subtitle="The same target ID travels through all three panels." tag="DIRECTIONS">
        <div className="zero-steps">
          <div><span>01</span><div><b>Save the target</b><p>Admin → Targets &amp; scope records the authorization and expiry.</p></div></div>
          <div><span>02</span><div><b>Run the trace</b><p>ZeroTrace re-creates the scope with the selected profiles and starts bounded scans.</p></div></div>
          <div><span>03</span><div><b>Read Trace Recon</b><p>The pipeline and discovered assets appear for the selected target.</p></div></div>
          <div><span>04</span><div><b>Read Intel Guard</b><p>Assets map to CVEs, NVD CVSS, EPSS, and KEV. Correlation builds remediation scripts.</p></div></div>
          <div><span>05</span><div><b>Download evidence</b><p>Admin → Database &amp; events holds per-target reports and readiness.</p></div></div>
        </div>
        <div className="small-warning">
          <ShieldCheck size={15} />
          <span>Only loopback engine URLs are accepted. High/Deep profiles require a DNS TXT record. Nothing is exploited or changed automatically.</span>
        </div>
      </Panel>
    </div>

    <Panel title="Current selection" subtitle="Recon and Intel read this selection until you run another target." tag="SHARED STATE">
      {selection ? (
        <div className="selection-strip">
          <div><span>TARGET</span><b>{selection.target}</b><small>{selection.scopeId}</small></div>
          <div><span>NMAP</span><b>{selection.nmapLevel}</b><small>{LEVEL_PROFILE_IDS.nmap[selection.nmapLevel]}</small></div>
          <div><span>SUBFINDER</span><b>{selection.subfinderLevel}</b><small>{LEVEL_PROFILE_IDS.subfinder[selection.subfinderLevel]}</small></div>
          <div className="selection-links">
            <Link href="/recon" className="button button-ghost button-small">Trace Recon <ArrowRight size={14} /></Link>
            <Link href="/intel" className="button button-ghost button-small">Intel Guard <ArrowRight size={14} /></Link>
          </div>
        </div>
      ) : (
        <div className="empty-console compact"><Crosshair size={20} /><b>No target selected</b><p>Run a saved target above. The selection is shared with Trace Recon and Intel Guard.</p></div>
      )}
    </Panel>
  </>;
}
