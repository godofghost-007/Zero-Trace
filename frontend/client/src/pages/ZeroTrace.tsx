import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  CircleAlert,
  Crosshair,
  Fingerprint,
  Globe2,
  Layers,
  Play,
  Radar,
  ScanLine,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import { useSelectedTarget } from "@/lib/selectedTarget";
import {
  DEFAULT_RECON_SERVICES,
  PROFILE_SHORT_LABELS,
  RECON_SERVICES,
  RECON_SERVICE_LABELS,
  TERMINAL_SCAN_STATES,
  profileIdsForServices,
  profileTimeoutSeconds,
  type EngineScope,
  type EngineStatus,
  type ReconServiceId,
  type ScanStatus,
} from "@/lib/liveEngine";

type RunStep = { profileId: string; scanId: string; state: string; error?: string };

const SERVICE_ICONS = {
  nmap: ScanLine,
  subfinder: Globe2,
  tls: ShieldCheck,
  synthetic: Layers,
} as const;

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
  const [services, setServices] = useState<ReconServiceId[]>([
    ...DEFAULT_RECON_SERVICES,
  ]);
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<RunStep[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const activeRef = useRef(true);

  useEffect(() => {
    activeRef.current = true;
    return () => {
      activeRef.current = false;
    };
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
      setServices(
        selection.services.length > 0
          ? selection.services
          : [...DEFAULT_RECON_SERVICES],
      );
    }
  }, [selection]);

  const selectedScope = scopes.find((scope) => scope.scopeId === scopeId) ?? null;
  const availableProfiles = status?.profiles ?? [];
  const profiles = useMemo(
    () =>
      profileIdsForServices(services).filter((profileId) =>
        availableProfiles.includes(profileId),
      ),
    [availableProfiles, services],
  );
  const ready = Boolean(target && selectedScope && profiles.length > 0);
  const selectedTargetLabel = target || "No target selected";
  const unavailableSelected = RECON_SERVICES.some(
    (service) =>
      services.includes(service.id) &&
      !availableProfiles.includes(service.profileId),
  );
  const runHint =
    services.length === 0
      ? "Select at least one service."
      : unavailableSelected
        ? "Some selected services are unavailable in this engine."
        : `Priority: ${profiles
            .map((profileId) => PROFILE_SHORT_LABELS[profileId] ?? profileId)
            .join(" → ")}.`;

  const chooseScope = (nextScopeId: string) => {
    setScopeId(nextScopeId);
    const scope = scopes.find((item) => item.scopeId === nextScopeId);
    setTarget(scope?.targets[0] ?? "");
    setError(null);
    setNotice(null);
  };

  const chooseTarget = (nextTarget: string) => {
    setTarget(nextTarget);
    setError(null);
    setNotice(null);
  };

  const toggleService = (serviceId: ReconServiceId) => {
    setServices((current) =>
      current.includes(serviceId)
        ? current.filter((item) => item !== serviceId)
        : [...current, serviceId],
    );
    setError(null);
    setNotice(null);
  };

  const run = async () => {
    if (!target || !selectedScope) {
      setError("Select a saved target first.");
      return;
    }
    if (profiles.length === 0) {
      setError("Select at least one available service.");
      return;
    }
    const orderedServices = RECON_SERVICES.filter((service) =>
      services.includes(service.id),
    ).map((service) => service.id);
    setRunning(true);
    setError(null);
    setNotice(null);
    setSteps(profiles.map((profileId) => ({ profileId, scanId: "", state: "queued" })));
    let failures = 0;
    try {
      const nextScopeId = selectedScope.scopeId;
      await apiRequest<EngineScope>("/engine/scopes", {
        method: "POST",
        body: JSON.stringify({
          authorized: true,
          scopeId: nextScopeId,
          targets: [target],
          environment: "synthetic",
          profiles,
          expiresInHours: 24,
        }),
      });

      select({
        target,
        scopeId: nextScopeId,
        profiles,
        services: orderedServices,
        selectedAt: new Date().toISOString(),
      });

      // Create and wait for one scan at a time. This preserves the operator's
      // priority order even if the engine is later configured with more than
      // one concurrent worker.
      for (const profileId of profiles) {
        const response = await apiRequest<{ scanId: string; state: string }>(
          "/engine/scans",
          {
            method: "POST",
            body: JSON.stringify({
              authorized: true,
              scopeId: nextScopeId,
              target,
              profileId,
            }),
          },
        );
        const scanId = response.scanId;
        let state = response.state;
        setSteps((current) =>
          current.map((item) =>
            item.profileId === profileId
              ? { ...item, scanId, state, error: undefined }
              : item,
          ),
        );

        const deadline =
          Date.now() + (profileTimeoutSeconds(profileId) + 45) * 1000;
        while (
          !TERMINAL_SCAN_STATES.has(state) &&
          Date.now() < deadline &&
          activeRef.current
        ) {
          await wait(1500);
          if (!activeRef.current) return;
          try {
            const next = await apiRequest<ScanStatus>(
              `/engine/scans/${scanId}`,
            );
            state = next.state;
            setSteps((current) =>
              current.map((item) =>
                item.profileId === profileId ? { ...item, state } : item,
              ),
            );
          } catch (reason) {
            state = "failed";
            setSteps((current) =>
              current.map((item) =>
                item.profileId === profileId
                  ? { ...item, state, error: messageOf(reason) }
                  : item,
              ),
            );
            break;
          }
        }
        if (!TERMINAL_SCAN_STATES.has(state)) {
          state = "timed_out";
          setSteps((current) =>
            current.map((item) =>
              item.profileId === profileId ? { ...item, state } : item,
            ),
          );
        }
        if (state !== "completed" && state !== "partial") {
          failures += 1;
        }
      }

      setNotice(
        failures > 0
          ? `Recon finished with ${failures} service warning(s). Trace Recon shows the persisted evidence.`
          : "Recon finished. Trace Recon and Intel Guard now hold this target's evidence.",
      );
      setRefresh((value) => value + 1);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      if (activeRef.current) setRunning(false);
    }
  };

  return (
    <>
      <PageHeading
        eyebrow="ZEROTRACE / 00 · START"
        title="ZeroTrace"
        description="Select a saved target, choose any of the four services, and run one bounded trace. Execution follows priority: Nmap, Subfinder, TLS Metadata, then Synthetic Inventory."
        actions={
          <StateTag
            tone={status ? "green" : statusQuery.loading ? "blue" : "red"}
          >
            {status
              ? "ENGINE CONNECTED"
              : statusQuery.loading
                ? "CONNECTING"
                : "ENGINE OFFLINE"}
          </StateTag>
        }
      />

      <section className="zero-hero">
        <div className="zero-hero-copy">
          <div className="eyebrow">AUTHORIZED TRACE · LOCAL ENGINE</div>
          <h2>One target. Four selectable services. One evidence chain.</h2>
          <p>
            ZeroTrace is the starting point. It reads the target list you saved
            in Admin, opens a short-lived scope, and runs the services you
            select in priority order. It does not exploit, brute-force, or
            change the target.
          </p>
          <div className="inline-tags">
            <StateTag tone="blue">NMAP · 1</StateTag>
            <StateTag tone="blue">SUBFINDER · 2</StateTag>
            <StateTag tone="blue">TLS METADATA · 3</StateTag>
            <StateTag tone="blue">SYNTHETIC · 4</StateTag>
          </div>
        </div>
        <div className="zero-hero-diagram" aria-hidden="true">
          <div className="zero-orbit zero-orbit-one" />
          <div className="zero-orbit zero-orbit-two" />
          <div className="zero-core">
            <Fingerprint size={34} />
            <span>00</span>
          </div>
          <div className="zero-satellite satellite-one">
            <Radar size={16} />
            <span>Recon</span>
          </div>
          <div className="zero-satellite satellite-two">
            <Workflow size={16} />
            <span>Intel</span>
          </div>
          <div className="zero-satellite satellite-three">
            <ShieldCheck size={16} />
            <span>Guard</span>
          </div>
        </div>
      </section>

      <div className="two-column zero-run-layout">
        <Panel
          title="Run a trace"
          subtitle="The scope is re-created for this run with only the services you select."
          tag="START HERE"
        >
          {statusQuery.error && (
            <div className="console-alert" role="alert">
              <CircleAlert size={15} />
              <span>{statusQuery.error}</span>
            </div>
          )}
          {scopes.length === 0 ? (
            <div className="empty-console">
              <Globe2 size={22} />
              <b>No saved targets</b>
              <p>
                Add an authorized target in Admin → Targets &amp; scope, then
                return here.
              </p>
              <Link href="/admin" className="button button-primary">
                Open Admin <ArrowRight size={15} />
              </Link>
            </div>
          ) : (
            <div className="zero-form">
              <div className="field-grid">
                <div className="field">
                  <label htmlFor="zero-scope">Saved scope</label>
                  <select
                    id="zero-scope"
                    value={scopeId}
                    onChange={(event) => chooseScope(event.target.value)}
                    disabled={running}
                  >
                    {scopes.map((scope) => (
                      <option key={scope.scopeId} value={scope.scopeId}>
                        {scope.scopeId}
                      </option>
                    ))}
                  </select>
                  <small>
                    {selectedScope
                      ? `${selectedScope.profiles.length} saved service profile(s) · expires ${new Date(selectedScope.expiresAt).toLocaleString()}`
                      : "Choose a scope"}
                  </small>
                </div>
                <div className="field">
                  <label htmlFor="zero-target">Target</label>
                  <select
                    id="zero-target"
                    value={target}
                    onChange={(event) => chooseTarget(event.target.value)}
                    disabled={running}
                  >
                    {(selectedScope?.targets ?? []).map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                  <small>Only targets saved by an operator appear here.</small>
                </div>
              </div>

              <div
                className="service-picker"
                role="group"
                aria-label="Recon services"
              >
                {RECON_SERVICES.map((service) => {
                  const Icon = SERVICE_ICONS[service.id];
                  const selected = services.includes(service.id);
                  const available = availableProfiles.includes(service.profileId);
                  return (
                    <button
                      key={service.id}
                      type="button"
                      className={`service-option${selected ? " selected" : ""}`}
                      aria-pressed={selected}
                      onClick={() => toggleService(service.id)}
                      disabled={running || !available}
                    >
                      <span className="service-priority">{service.priority}</span>
                      <Icon size={17} />
                      <span className="service-copy">
                        <b>{service.label}</b>
                        <small>{service.description}</small>
                      </span>
                      <span className="service-check">
                        {available ? (selected ? "SELECTED" : "OFF") : "UNAVAILABLE"}
                      </span>
                    </button>
                  );
                })}
              </div>

              <div className="saved-profile-strip">
                <span>RUN ORDER</span>
                {profiles.length ? (
                  profiles.map((profileId, index) => (
                    <CodeLabel key={profileId}>
                      {index + 1} · {PROFILE_SHORT_LABELS[profileId] ?? profileId}
                    </CodeLabel>
                  ))
                ) : (
                  <CodeLabel>SELECT AT LEAST ONE AVAILABLE SERVICE</CodeLabel>
                )}
              </div>

              {error && (
                <div className="console-alert" role="alert">
                  <CircleAlert size={15} />
                  <span>{error}</span>
                </div>
              )}
              {notice && (
                <div className="console-alert success" role="status">
                  <Sparkles size={15} />
                  <span>{notice}</span>
                </div>
              )}

              <div className="form-actions zero-run-actions">
                <button
                  className="button button-primary button-run"
                  type="button"
                  onClick={() => void run()}
                  disabled={!ready || running}
                >
                  <Play size={16} />
                  {running ? "Running bounded trace…" : `Run ${selectedTargetLabel}`}
                </button>
                <span className="run-hint">{runHint}</span>
              </div>

              {steps.length > 0 && (
                <div className="run-progress">
                  {steps.map((step) => (
                    <div className="run-step" key={step.profileId}>
                      <span className={`run-step-dot state-${step.state}`} />
                      <div>
                        <b>{PROFILE_SHORT_LABELS[step.profileId] ?? step.profileId}</b>
                        <small>{step.error ?? step.state}</small>
                      </div>
                      <CodeLabel>{step.scanId.slice(0, 8) || "queued"}</CodeLabel>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Panel>

        <Panel
          title="How it works"
          subtitle="The same target ID travels through all three panels."
          tag="DIRECTIONS"
        >
          <div className="zero-steps">
            <div>
              <span>01</span>
              <div>
                <b>Save the target</b>
                <p>Admin → Targets &amp; scope records the authorization and expiry.</p>
              </div>
            </div>
            <div>
              <span>02</span>
              <div>
                <b>Choose the services</b>
                <p>Toggle Nmap, Subfinder, TLS Metadata, or Synthetic Inventory. The engine runs them in priority order.</p>
              </div>
            </div>
            <div>
              <span>03</span>
              <div>
                <b>Read Trace Recon</b>
                <p>The pipeline and discovered assets appear for the selected target.</p>
              </div>
            </div>
            <div>
              <span>04</span>
              <div>
                <b>Read Intel Guard</b>
                <p>Assets map to CVEs, NVD CVSS, EPSS, and KEV. Correlation builds remediation scripts.</p>
              </div>
            </div>
            <div>
              <span>05</span>
              <div>
                <b>Download evidence</b>
                <p>Admin → Database &amp; events holds per-target reports and readiness.</p>
              </div>
            </div>
          </div>
          <div className="small-warning">
            <ShieldCheck size={15} />
            <span>
              Only loopback engine URLs are accepted. Nmap is bounded to the
              fixed high-value port list; Subfinder stays passive. Nothing is
              exploited or changed automatically.
            </span>
          </div>
        </Panel>
      </div>

      <Panel
        title="Current selection"
        subtitle="Recon and Intel read this selection until you run another target."
        tag="SHARED STATE"
      >
        {selection ? (
          <div className="selection-strip">
            <div>
              <span>TARGET</span>
              <b>{selection.target}</b>
              <small>{selection.scopeId}</small>
            </div>
            <div>
              <span>SERVICES</span>
              <b>
                {selection.services
                  .map((serviceId) => RECON_SERVICE_LABELS[serviceId])
                  .join(" → ")}
              </b>
              <small>{selection.services.length} selected · priority order</small>
            </div>
            <div>
              <span>PROFILES</span>
              <b>{selection.profiles.length}</b>
              <small>
                {selection.profiles
                  .map((profileId) => PROFILE_SHORT_LABELS[profileId] ?? profileId)
                  .join(", ")}
              </small>
            </div>
            <div className="selection-links">
              <Link href="/recon" className="button button-ghost button-small">
                Trace Recon <ArrowRight size={14} />
              </Link>
              <Link href="/intel" className="button button-ghost button-small">
                Intel Guard <ArrowRight size={14} />
              </Link>
            </div>
          </div>
        ) : (
          <div className="empty-console compact">
            <Crosshair size={20} />
            <b>No target selected</b>
            <p>
              Run a saved target above. The selection is shared with Trace Recon
              and Intel Guard.
            </p>
          </div>
        )}
      </Panel>
    </>
  );
}
