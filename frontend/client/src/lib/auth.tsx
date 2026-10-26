import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, apiRequest, setCsrfToken } from "@/lib/api";

export type AuthRole = "viewer" | "operator" | "admin";
export type AuthUser = { id: string; email: string; role: AuthRole; tenantId: string; active: boolean };
type AuthSession = {
  user: AuthUser;
  csrfToken: string;
  expiresAt: string | null;
  mfaRequired?: boolean;
  mfaVerified?: boolean;
};
type AuthContextValue = {
  user: AuthUser | null;
  loading: boolean;
  error: string | null;
  mfaRequired: boolean;
  login: (email: string, password: string) => Promise<void>;
  verifyMfa: (code: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mfaRequired, setMfaRequired] = useState(false);

  const clear = useCallback(() => {
    setUser(null);
    setMfaRequired(false);
    setCsrfToken("");
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const session = await apiRequest<AuthSession>("/auth/session");
      setUser(session.user);
      setCsrfToken(session.csrfToken);
      setMfaRequired(session.mfaVerified === false);
      setError(null);
    } catch (reason) {
      clear();
      if (reason instanceof ApiError && reason.status !== 401) {
        setError(reason.message);
      }
    } finally {
      setLoading(false);
    }
  }, [clear]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const onExpired = () => clear();
    window.addEventListener("zt-auth-required", onExpired);
    return () => window.removeEventListener("zt-auth-required", onExpired);
  }, [clear]);

  const login = useCallback(async (email: string, password: string) => {
    const session = await apiRequest<AuthSession>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setUser(session.user);
    setCsrfToken(session.csrfToken);
    setMfaRequired(Boolean(session.mfaRequired) || session.mfaVerified === false);
    setError(null);
  }, []);

  const verifyMfa = useCallback(async (code: string) => {
    const result = await apiRequest<{ csrfToken: string }>("/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    setCsrfToken(result.csrfToken);
    setMfaRequired(false);
    setError(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiRequest("/auth/logout", { method: "POST", body: "{}" });
    } finally {
      clear();
    }
  }, [clear]);

  const value = useMemo(
    () => ({ user, loading, error, mfaRequired, login, verifyMfa, logout, refresh }),
    [user, loading, error, mfaRequired, login, verifyMfa, logout, refresh],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used within AuthProvider");
  return value;
}
