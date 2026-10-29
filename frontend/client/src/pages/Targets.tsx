import { useMemo, useState, type FormEvent } from "react";
import { ArrowRight, Crosshair, Globe2, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { Link } from "wouter";
import { CodeLabel, PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import {
  PROFILE_SHORT_LABELS,
  normalizeTarget,
  scopeIdFor,
  type EngineScope,
  type EngineStatus,
} from "@/lib/liveEngine";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

const DEFAULT_PROFILES = [
  "service_inventory_v1",
  "passive_subdomain_v1",
  "tls_metadata_v1",
  "synthetic_inventory_v1",
];

export default function Targets({ embedded = false }: { embedded?: boolean }) {
  const [refresh, setRefresh] = useState(0);
  const statusQuery = useApiResource<EngineStatus>("/engine/status", refresh);
  const scopesQuery = useApiResource<{ items: EngineScope[] }>("/engine/scopes", refresh);
  const status = statusQuery.data;
  const scopes = scopesQuery.data?.items ?? [];

  const availableProfiles = useMemo(() => {
    const profiles = status?.profiles ?? [];
    const selected = DEFAULT_PROFILES.filter((profileId) => profiles.includes(profileId));
    if (selected.length > 0) return selected;
    return profiles.slice(0, 4);
  }, [status?.profiles]);

  const [target, setTarget] = useState("");
  const [expires, setExpires] = useState("24");
  const [scopePage, setScopePage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const scopePages = Math.max(1, Math.ceil(scopes.length / 10));
  const safeScopePage = Math.min(scopePage, scopePages - 1);
  const pagedScopes = scopes.slice(safeScopePage * 10, (safeScopePage + 1) * 10);

  const addTarget = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setNotice(null);
    const normalized = normalizeTarget(target);
    if (normalized.error) {
      setError(normalized.error);
      return;
    }
    if (availableProfiles.length === 0) {
      setError("The engine has no allowlisted scan profiles available.");
      return;
    }
    setBusy(true);
    try {
      const scopeId = scopeIdFor(normalized.host);
      await apiRequest<EngineScope>("/engine/scopes", {
        method: "POST",
        body: JSON.stringify({
          authorized: true,
          scopeId,
          targets: [normalized.host],
          environment: "synthetic",
          profiles: availableProfiles,
          expiresInHours: Number(expires),
        }),
      });
      setTarget("");
      setNotice(`${normalized.host} saved as an authorized target.`);
      setRefresh((value) => value + 1);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setBusy(false);
    }
  };

  const removeTarget = async (scope: EngineScope) => {
    setError(null);
    setNotice(null);
    setRemoving(scope.scopeId);
    try {
      await apiRequest<{ scopeId: string; deleted: boolean }>(`/engine/scopes/${encodeURIComponent(scope.scopeId)}`, {
        method: "DELETE",
      });
      setNotice(`${scope.targets.join(", ")} removed from the authorized target list.`);
      setRefresh((value) => value + 1);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setRemoving(null);
    }
  };

  return <>
    {!embedded && (
      <PageHeading
        eyebrow="ADMIN / 05 · TARGETS"
        title="Targets & scope"
        description="Save the domains you are authorized to test. ZeroTrace reads this list when you run a recon trace."
        actions={<StateTag tone={status ? "green" : statusQuery.loading ? "blue" : "red"}>{status ? `${scopes.length} SAVED` : "ENGINE OFFLINE"}</StateTag>}
      />
    )}

    {embedded && (
      <div className="admin-section-head">
        <div>
          <h2>Targets & scope</h2>
          <p>Add or remove authorized targets. Scans are started from the ZeroTrace page.</p>
        </div>
        <StateTag tone={status ? "green" : "red"}>{status ? `${scopes.length} SAVED` : "ENGINE OFFLINE"}</StateTag>
      </div>
    )}

    <div className="data-banner">
      <ShieldCheck size={18} />
      <span>
        <b>Only add targets you own or are explicitly authorized to test.</b>
        <small>The saved record is an operator-approved scope. Removing it stops new scans; existing evidence stays in the Database view.</small>
      </span>
      <CodeLabel>OPERATOR ACTION</CodeLabel>
    </div>

    {statusQuery.error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{statusQuery.error} <Link href="/admin" className="text-link">Open Admin <ArrowRight size={13} /></Link></span></div>}

    <div className="two-column">
      <Panel title="Add an authorized target" subtitle="The engine validates the hostname, creates a scope, and keeps it on this machine." tag="SAVE TARGET">
        <form onSubmit={(event) => void addTarget(event)}>
          <div className="field-grid">
            <div className="field field-wide">
              <label htmlFor="admin-target-input">Target domain</label>
              <input
                id="admin-target-input"
                value={target}
                onChange={(event) => { setTarget(event.target.value); setError(null); }}
                placeholder="example.com"
                spellCheck={false}
                autoComplete="off"
              />
              <small>Enter a domain name. A URL is reduced to its hostname; IP addresses, ports, and paths are not saved. Wildcards and IPv6 are not supported.</small>
            </div>
            <div className="field">
              <label htmlFor="admin-target-expiry">Scope lifetime</label>
              <select id="admin-target-expiry" value={expires} onChange={(event) => setExpires(event.target.value)}>
                <option value="1">1 hour</option>
                <option value="6">6 hours</option>
                <option value="24">24 hours</option>
                <option value="72">72 hours</option>
              </select>
              <small>Expired scopes are rejected by the engine.</small>
            </div>
          </div>
          <div className="saved-profile-strip">
            <span>DEFAULT SERVICES</span>
            {availableProfiles.length ? availableProfiles.map((profileId) => (
              <CodeLabel key={profileId}>{PROFILE_SHORT_LABELS[profileId] ?? profileId}</CodeLabel>
            )) : <CodeLabel>NO PROFILES</CodeLabel>}
          </div>
          {error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{error}</span></div>}
          {notice && <div className="console-alert success" role="status"><ShieldCheck size={15} /><span>{notice}</span></div>}
          <div className="form-actions">
            <button className="button button-primary" type="submit" disabled={busy || !status || availableProfiles.length === 0}>
              <Crosshair size={15} />{busy ? "Saving target…" : "Save authorized target"}
            </button>
            <Link href="/" className="button button-ghost">Open ZeroTrace <ArrowRight size={15} /></Link>
          </div>
        </form>
      </Panel>

      <Panel title="Saved targets" subtitle="One scope per saved target. Remove a target to stop new scans." tag={`${scopes.length} SAVED`}>
        {scopesQuery.error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{scopesQuery.error}</span></div>}
        {scopes.length === 0 ? (
          <div className="empty-console">
            <Globe2 size={22} />
            <b>No authorized targets yet</b>
            <p>Add the first domain above. It will appear in the ZeroTrace selector.</p>
          </div>
        ) : (
          <div className="scope-list saved-target-list">
            {pagedScopes.map((scope) => (
              <div className="scope-row saved-target-row" key={scope.scopeId}>
                <div>
                  <b>{scope.targets.join(", ")}</b>
                  <small>{scope.scopeId} · {scope.environment}</small>
                </div>
                <div>
                  <small>{scope.profiles.map((profileId) => PROFILE_SHORT_LABELS[profileId] ?? profileId).join(", ")}</small>
                  <small>Expires {new Date(scope.expiresAt).toLocaleString()}</small>
                </div>
                <div className="saved-target-actions">
                  <StateTag tone={scope.approved ? "green" : "red"}>{scope.approved ? "AUTHORIZED" : "BLOCKED"}</StateTag>
                  <button
                    className="icon-button danger-icon"
                    type="button"
                    title={`Remove ${scope.targets.join(", ")}`}
                    aria-label={`Remove ${scope.targets.join(", ")}`}
                    onClick={() => void removeTarget(scope)}
                    disabled={removing === scope.scopeId}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
        {scopePages > 1 && <div className="form-actions">
          <button className="button button-ghost button-small" type="button" onClick={() => setScopePage(Math.max(0, safeScopePage - 1))} disabled={safeScopePage === 0}>Previous</button>
          <span className="pagination-label">{safeScopePage + 1} / {scopePages}</span>
          <button className="button button-ghost button-small" type="button" onClick={() => setScopePage(Math.min(scopePages - 1, safeScopePage + 1))} disabled={safeScopePage === scopePages - 1}>Next</button>
        </div>}
      </Panel>
    </div>

    <Panel title="What happens next" subtitle="Targets are only a saved authorization. Nothing is scanned from this panel." tag="WORKFLOW">
      <div className="workflow-strip">
        <div><span>01</span><b>Save target</b><small>Admin creates a bounded scope.</small></div>
        <ArrowRight size={16} />
        <div><span>02</span><b>Run in ZeroTrace</b><small>Choose any of the four services.</small></div>
        <ArrowRight size={16} />
        <div><span>03</span><b>Read evidence</b><small>Recon, Intel, and Database views update.</small></div>
      </div>
    </Panel>
  </>;
}
