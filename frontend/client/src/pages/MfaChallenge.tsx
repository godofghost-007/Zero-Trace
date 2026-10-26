import { useState, type FormEvent } from "react";
import { KeyRound, LogOut, ShieldCheck, TriangleAlert } from "lucide-react";
import { useAuth } from "@/lib/auth";

export default function MfaChallenge() {
  const { user, verifyMfa, logout, error: sessionError } = useAuth();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyMfa(code);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mfa-page">
      <section className="mfa-panel" aria-labelledby="mfa-title">
        <div className="login-panel-head">
          <span className="login-step">AUTH / 02</span>
          <span className="state-tag state-red"><i />SECOND FACTOR</span>
        </div>
        <div className="login-brand-mark"><ShieldCheck size={24} strokeWidth={2} /></div>
        <h1 id="mfa-title">Verify your session</h1>
        <p>
          Enter the current six-digit code from your authenticator app
          {user?.email ? ` for ${user.email}` : ""}.
        </p>
        <form onSubmit={(event) => void submit(event)}>
          <div className="field">
            <label htmlFor="mfa-code">Authentication code</label>
            <input
              id="mfa-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={8}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
              autoFocus
              required
            />
          </div>
          {(error || sessionError) && (
            <div className="console-alert" role="alert">
              <TriangleAlert size={15} />
              <span>{error ?? sessionError}</span>
            </div>
          )}
          <button
            className="button button-primary login-submit"
            type="submit"
            disabled={busy || code.length < 6}
          >
            <KeyRound size={16} />
            {busy ? "Verifying…" : "Verify and continue"}
          </button>
          <button
            className="button button-secondary login-submit"
            type="button"
            onClick={() => void logout()}
            disabled={busy}
          >
            <LogOut size={16} />
            Sign out
          </button>
        </form>
        <div className="login-foot">
          <span>MFA IS REQUIRED BEFORE CONSOLE ACCESS</span>
          <span>SESSION COOKIE A HTTPONLY</span>
        </div>
      </section>
    </main>
  );
}
