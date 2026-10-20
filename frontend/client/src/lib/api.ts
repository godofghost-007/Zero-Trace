import { useEffect, useState } from "react";

export class ApiError extends Error {
  status: number;
  code: string;
  requestId?: string;

  constructor(message: string, status: number, code = "request_failed", requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: "same-origin", cache: "no-store" });
  const payload = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (!response.ok) {
    const err = (payload?.error ?? {}) as Record<string, unknown>;
    throw new ApiError(
      typeof err.message === "string" ? err.message : `API request failed (${response.status}).`,
      response.status,
      typeof err.code === "string" ? err.code : "request_failed",
      typeof payload?.request_id === "string" ? payload.request_id : response.headers.get("X-Request-ID") ?? undefined,
    );
  }
  if (!payload) throw new ApiError("The backend returned a non-JSON response.", response.status, "invalid_response");
  return payload as T;
}

export function useApiResource<T>(path: string, refreshKey: string | number): { data: T | null; loading: boolean; error: string | null } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    apiRequest<T>(path)
      .then((result) => { if (active) setData(result); })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Backend request failed.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [path, refreshKey]);

  return { data, loading, error };
}
