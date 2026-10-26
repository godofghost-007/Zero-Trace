import type { ReactNode } from "react";
import Login from "@/pages/Login";
import MfaChallenge from "@/pages/MfaChallenge";
import { useAuth } from "@/lib/auth";

export default function AuthGate({ children }: { children: ReactNode }) {
  const { user, loading, error, mfaRequired, refresh } = useAuth();

  if (loading) {
    return (
      <main className="auth-loading" aria-live="polite">
        <div className="brand-mark"><span className="auth-spinner" /></div>
        <span>CHECKING LOCAL SESSION</span>
      </main>
    );
  }
  if (!user) {
    return (
      <>
        {error && <div className="api-error-banner auth-error-banner" role="alert"><div><b>Authentication service unavailable</b><span>{error}</span></div><button onClick={() => void refresh()}>Retry</button></div>}
        <Login />
      </>
    );
  }
  if (mfaRequired) {
    return <MfaChallenge />;
  }
  return <>{children}</>;
}
