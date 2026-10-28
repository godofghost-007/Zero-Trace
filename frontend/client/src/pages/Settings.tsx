import { useEffect, useState } from "react";
import { Cable, KeyRound, PlugZap, Save, ShieldCheck, TriangleAlert } from "lucide-react";
import { Link } from "wouter";
import { PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import { apiRequest, useApiResource } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { EngineSettings, EngineTestResult } from "@/lib/liveEngine";

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "The request failed.";
}

export default function Settings() {
  const { user } = useAuth();
  const canAdmin = user?.role === "admin";
  const query = useApiResource<EngineSettings>("/settings/engine", 0);
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:8765");
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [apiKey, setApiKey] = useState("");
  const [settings, setSettings] = useState<EngineSettings | null>(null);
  const [testResult, setTestResult] = useState<EngineTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!query.data) return;
    setSettings(query.data);
    setBaseUrl(query.data.baseUrl);
    setMode(query.data.mode);
  }, [query.data]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const saved = await apiRequest<EngineSettings>("/settings/engine", {
        method: "PUT",
        body: JSON.stringify({ baseUrl, mode, apiKey }),
      });
      setSettings(saved);
      setBaseUrl(saved.baseUrl);
      setMode(saved.mode);
      setApiKey("");
      setNotice("Connection settings saved.");
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setError(null);
    setTestResult(null);
    try {
      const result = await apiRequest<EngineTestResult>("/engine/test", {
        method: "POST",
        body: "{}",
      });
      setTestResult(result);
    } catch (reason) {
      setError(messageOf(reason));
    } finally {
      setTesting(false);
    }
  };

  return <>
    <PageHeading
      eyebrow="ADMIN / 06 · CONNECTION"
      title="Engine settings"
      description="Point the dashboard at the loopback live engine. The API key is stored server-side and is never returned to this browser."
      actions={<StateTag tone={settings?.mode === "live" ? "green" : "neutral"}>{settings ? settings.mode.toUpperCase() : "LOADING"}</StateTag>}
    />

    <div className="data-banner">
      <ShieldCheck size={18} />
      <span>
        <b>Two modes, one boundary.</b>
        <small>Demo mode keeps every page on fixtures. Live mode is used by Targets &amp; scope to create an approved scope and run allowlisted reads. The engine must be running on this machine.</small>
      </span>
    </div>

    <Panel title="Settings pages" subtitle="Architecture, targets, and database tools live here." tag="SETTINGS">
      <div className="form-actions">
        <Link className="button button-ghost" href="/architecture">Architecture</Link>
        <Link className="button button-ghost" href="/targets">Targets & scope</Link>
        <Link className="button button-ghost" href="/database">Database & events</Link>
      </div>
    </Panel>

    <div className="two-column">
      <Panel
        title="Live engine connection"
        subtitle="The Flask API validates the URL, keeps the key, and proxies requests to the engine."
        tag="LOOPBACK ONLY"
      >
        {query.error && <div className="console-alert"><TriangleAlert size={15} /><span>{query.error}</span></div>}
        <div className="field-grid">
          <div className="field field-wide">
            <label htmlFor="engine-url">Engine base URL</label>
            <input
              id="engine-url"
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              placeholder="http://127.0.0.1:8765"
              spellCheck={false}
              autoComplete="off"
            />
            <small>Only loopback hosts are accepted: 127.0.0.1, ::1, or localhost.</small>
          </div>
          <div className="field">
            <label htmlFor="engine-key">API key</label>
            <input
              id="engine-key"
              type="password"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              placeholder={settings?.apiKeyConfigured ? "Saved key — leave blank to keep" : "Enter the engine API key"}
              autoComplete="new-password"
              spellCheck={false}
            />
            <small>{settings?.apiKeyConfigured ? `Configured (${settings.apiKeyHint ?? "hidden"}).` : "No key saved yet."} Leave blank to keep the current key.</small>
          </div>
          <div className="field">
            <label htmlFor="engine-mode">Dashboard mode</label>
            <select id="engine-mode" value={mode} onChange={(event) => setMode(event.target.value === "live" ? "live" : "demo")}>
              <option value="demo">Demo — fixtures only</option>
              <option value="live">Live — loopback engine</option>
            </select>
            <small>This is a UI preference stored next to the connection settings.</small>
          </div>
        </div>
        <div className="form-actions">
          <button className="button button-primary" onClick={() => void save()} disabled={busy || !canAdmin}>
            <Save size={15} />{busy ? "Saving…" : "Save settings"}
          </button>
          <button className="button button-ghost" onClick={() => void test()} disabled={testing}>
            <PlugZap size={15} />{testing ? "Testing…" : "Test connection"}
          </button>
        </div>
        {!canAdmin && <div className="small-warning">Only an admin can change the engine connection. Operator and viewer sessions can inspect and test it.</div>}
        {notice && <div className="console-alert success" role="status"><ShieldCheck size={15} /><span>{notice}</span></div>}
        {error && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{error}</span></div>}
        {testResult && <div className="console-alert info" role="status">
          {testResult.ok ? <Cable size={15} /> : <TriangleAlert size={15} />}
          <span>
            {testResult.ok
              ? `Connected in ${testResult.latencyMs} ms to ${testResult.service ?? "the live engine"}.`
              : testResult.message ?? "The live engine could not be reached."}
            {testResult.ok && testResult.profiles?.length ? ` Profiles: ${testResult.profiles.join(", ")}.` : ""}
          </span>
        </div>}
      </Panel>

      <Panel title="Connection record" subtitle="What the server currently holds. The raw key is never included." tag="REDACTED">
        <div className="kv-list">
          <div className="kv-row"><span>MODE</span><b>{settings?.mode ?? "—"}</b></div>
          <div className="kv-row"><span>BASE URL</span><b>{settings?.baseUrl ?? "—"}</b></div>
          <div className="kv-row"><span>API KEY</span><b>{settings?.apiKeyConfigured ? `Configured · ${settings.apiKeyHint ?? "hidden"}` : "Not configured"}</b></div>
          <div className="kv-row"><span>UPDATED</span><b>{settings?.updatedAt ? new Date(settings.updatedAt).toLocaleString() : "Using defaults"}</b></div>
          <div className="kv-row"><span>STORAGE</span><b>instance/engine-settings.json · 0600 where supported</b></div>
        </div>
        <div className="small-warning">
          <KeyRound size={15} />
          <span>The browser sends only same-origin requests to Flask. Flask attaches the API key when it calls the engine. The key is never embedded in the built UI or returned by the settings API.</span>
        </div>
      </Panel>
    </div>

    <Panel title="Start the live engine" subtitle="Run this from the repository root. It binds to loopback only and uses the same default key as the dashboard." tag="TERMINAL">
      <div className="kv-list">
        <div className="kv-row"><span>COMMAND</span><b><code>python -m scripts.live_engine</code></b></div>
        <div className="kv-row"><span>DEFAULT URL</span><b><code>http://127.0.0.1:8765</code></b></div>
        <div className="kv-row"><span>OVERRIDE KEY</span><b><code>ZEROTRACE_ENGINE_API_KEY</code> (set it for both processes)</b></div>
        <div className="kv-row"><span>PROFILES</span><b>TLS metadata is always available. Nmap and Subfinder appear only when their binaries are installed.</b></div>
      </div>
      <div className="small-warning">
        <ShieldCheck size={15} />
        <span>The engine authenticates every API call, binds to 127.0.0.1, and only accepts targets inside an operator-created scope. Scans are bounded; there is no exploitation, brute force, or remediation.</span>
      </div>
    </Panel>
  </>;
}
