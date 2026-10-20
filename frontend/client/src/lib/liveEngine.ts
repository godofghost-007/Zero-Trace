export type EngineMode = "demo" | "live";

export type EngineSettings = {
  baseUrl: string;
  mode: EngineMode;
  apiKeyConfigured: boolean;
  apiKeyHint: string | null;
  updatedAt: string;
};

export type EngineTestResult = {
  ok: boolean;
  latencyMs: number;
  service?: string;
  mode?: string;
  profiles?: string[];
  guard?: Record<string, unknown>;
  message?: string;
};

export type EngineStatus = {
  service: string;
  mode: string;
  time: string;
  adapters: string[];
  profiles: string[];
  scopes: number;
  scans: number;
  intel: {
    facts: number;
    findings: number;
    uncertainMatches: number;
    kevRecords?: number;
    epssRecords?: number;
    feeds: Record<string, string>;
  };
  guard: {
    mode: string;
    detector: string;
    piiScanner: boolean;
    upstreamConfigured: boolean;
  };
};

export type EngineScope = {
  scopeId: string;
  targets: string[];
  environment: string;
  profiles: string[];
  approved: boolean;
  expiresAt: string;
};

export type ScanState =
  | "queued"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "timed_out"
  | "cancelled";

export type ScanStatus = { scanId: string; state: ScanState | string };

export type ScanResult = {
  scanId: string;
  state: ScanState | string;
  target: string;
  profileId: string;
  assets: string[];
  services: Array<{
    asset: string;
    protocol: string;
    port: number;
    product: string | null;
    version: string | null;
    tlsStatus: string | null;
  }>;
  tlsFindings: Array<{
    subject: string;
    issuer: string;
    expires_at: string;
    status: string;
  }>;
  warnings: string[];
};

export type GuardInspection = {
  blocked: boolean;
  reason: string | null;
  details: string | null;
  pii: { blocked: boolean; reason: string | null };
  mode: string;
};

export const TERMINAL_SCAN_STATES = new Set([
  "completed",
  "partial",
  "failed",
  "timed_out",
  "cancelled",
]);

export const PROFILE_LABELS: Record<string, string> = {
  tls_metadata_v1: "TLS metadata — one real read on port 443",
  synthetic_inventory_v1: "Synthetic inventory — fixture, no network",
  service_inventory_v1: "Nmap top-100 — real TCP service scan",
  passive_subdomain_v1: "Subfinder — real passive discovery",
};

export function normalizeTarget(input: string): { host: string; error: string | null } {
  let value = input.trim().toLowerCase();
  if (!value) return { host: "", error: "Enter a domain or IPv4 address." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(value)) value = `https://${value}`;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return { host: "", error: "Enter a valid URL or hostname." };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { host: "", error: "Only http and https targets are supported." };
  }
  const host = parsed.hostname.replace(/\.$/, "");
  if (!host || host.includes(":") || host.includes("*")) {
    return { host: "", error: "IPv6 addresses and wildcards are not supported." };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    return { host, error: null };
  }
  if (!host.includes(".")) {
    return {
      host: "",
      error: "The engine needs a dotted name. localhost is not supported; use a domain or IPv4 address.",
    };
  }
  const labels = host.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return { host: "", error: "The hostname contains invalid characters." };
  }
  return { host, error: null };
}

export function scopeIdFor(host: string): string {
  const slug = host
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 72);
  return `scope-${slug || "target"}`;
}

export function scanTone(state: string): "neutral" | "red" | "blue" | "green" | "amber" {
  if (state === "completed") return "green";
  if (state === "partial") return "amber";
  if (state === "failed" || state === "timed_out" || state === "cancelled") return "red";
  if (state === "queued" || state === "running") return "blue";
  return "neutral";
}
