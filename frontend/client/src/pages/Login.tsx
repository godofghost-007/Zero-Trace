import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, KeyRound, LockKeyhole, ShieldCheck, TriangleAlert } from "lucide-react";
import { apiRequest } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function Login() {
  const { login, error: sessionError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [oidcEnabled, setOidcEnabled] = useState(false);

  useEffect(() => {
    let active = true;
    apiRequest<{ oidcEnabled: boolean }>("/auth/config")
      .then((config) => {
        if (active) setOidcEnabled(Boolean(config.oidcEnabled));
      })
      .catch(() => {
        if (active) setOidcEnabled(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-brand">
        <div className="login-brand-mark"><ShieldCheck size={26} strokeWidth={2} /></div>
        <span className="eyebrow">ZEROTRACE / LOCAL OPERATOR CONSOLE</span>
        <h1>Trace the signal.<br />Protect the surface.</h1>
        <p>A bounded cyber-defense workspace for authorized Recon, Intel, Guard, and readiness review. Every action stays on this machine and inside an approved scope.</p>
        <div className="login-boundaries">
          <span><LockKeyhole size={14} /> Server-side session</span>
          <span><KeyRound size={14} /> CSRF protected</span>
          <span><ShieldCheck size={14} /> Role enforced</span>
        </div>
      </section>

      <section className="login-panel" aria-labelledby="login-title">
        <div className="login-panel-head">
          <span className="login-step">AUTH / 01</span>
          <span className="state-tag state-red"><i />SIGN IN REQUIRED</span>
        </div>
        <h2 id="login-title">Operator sign-in</h2>
        <p>Use an account created by the local administrator. Roles are <code>viewer</code>, <code>operator</code>, and <code>admin</code>.</p>
        <form onSubmit={(event) => void submit(event)}>
          <div className="field">
            <label htmlFor="login-email">Email</label>
            <input
              id="login-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              spellCheck={false}
              required
            />
          </div>
          <div className="field">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          </div>
          {(error || sessionError) && <div className="console-alert" role="alert"><TriangleAlert size={15} /><span>{error ?? sessionError}</span></div>}
          <button className="button button-primary login-submit" type="submit" disabled={busy || !email || !password}>
            <ArrowRight size={16} />{busy ? "Signing in…" : "Enter console"}
          </button>
        </form>
        {oidcEnabled && (
          <a className="button button-secondary login-submit login-sso" href="/api/v1/auth/oidc/login">
            <KeyRound size={16} />Continue with SSO
          </a>
        )}
        <div className="login-foot">
          <span>LOCAL SESSION · HTTPONLY COOKIE</span>
          <span>NO BROWSER-HELD ENGINE KEY</span>
        </div>
      </section>
    </main>
  );
}
