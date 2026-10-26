import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, LogOut, ShieldCheck, TriangleAlert } from "lucide-react";
import { useAuth } from "@/lib/auth";

export default function MfaChallenge() {
  const {
    user,
    verifyMfa,
    activateMfa,
    startMfaEnrollment,
    mfaEnrollmentRequired,
    logout,
    error: sessionError,
  } = useAuth();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [enrollmentError, setEnrollmentError] = useState<string | null>(null);

  useEffect(() => {
    if (!mfaEnrollmentRequired || enrollment) return;
    let active = true;
    startMfaEnrollment()
      .then((result) => {
        if (active) setEnrollment(result);
      })
      .catch((reason) => {
        if (active) {
          setEnrollmentError(reason instanceof Error ? reason.message : "MFA enrollment could not be started.");
        }
      });
    return () => {
      active = false;
    };
  }, [mfaEnrollmentRequired, enrollment, startMfaEnrollment]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mfaEnrollmentRequired) {
        await activateMfa(code);
      } else {
        await verifyMfa(code);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  };

  const title = mfaEnrollmentRequired
    ? "Set up multi-factor authentication"
    : "Verify your session";
  const description = mfaEnrollmentRequired
    ? "Your tenant requires MFA. Add the secret below to an authenticator app, then enter the current six-digit code."
    : "Enter the current six-digit code from your authenticator app";

  return (
    <main className="mfa-page">
      <section className="mfa-panel" aria-labelledby="mfa-title">
        <div className="login-panel-head">
          <span className="login-step">AUTH / 02</span>
          <span className="state-tag state-red"><i />SECOND FACTOR</span>
        </div>
        <div className="login-brand-mark"><ShieldCheck size={24} strokeWidth={2} /></div>
        <h1 id="mfa-title">{title}</h1>
        <p>
          {description}
          {user?.email ? ` for ${user.email}` : ""}.
        </p>
        {mfaEnrollmentRequired && (
          <div className="mfa-enrollment" aria-live="polite">
            {enrollmentError && (
              <div className="console-alert" role="alert">
                <TriangleAlert size={15} />
                <span>{enrollmentError}</span>
              </div>
            )}
            {enrollment ? (
              <>
                <p>Secret for your authenticator app:</p>
                <code className="mfa-secret">{enrollment.secret}</code>
                <a className="button button-secondary login-submit" href={enrollment.otpauthUri}>
                  <KeyRound size={16} />
                  Open in authenticator
                </a>
              </>
            ) : (
              !enrollmentError && <p>Preparing your enrollment secret…</p>
            )}
          </div>
        )}
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
            disabled={busy || code.length < 6 || (mfaEnrollmentRequired && !enrollment)}
          >
            <KeyRound size={16} />
            {busy ? "Verifying…" : mfaEnrollmentRequired ? "Activate and continue" : "Verify and continue"}
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
