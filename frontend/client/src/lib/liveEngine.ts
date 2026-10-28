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
  storage?: string;
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
    nvdCheckpoint?: string | null;
    feeds: Record<string, string>;
    schedule?: IntelSchedule;
  };
  guard: {
    mode: string;
    detector: string;
    piiScanner: boolean;
    upstreamConfigured: boolean;
    inspectionRequests?: number;
    unblockedRequests?: number;
  };
  readiness?: {
    score: number | null;
    band: string | null;
    coverage: number;
    status: string;
  };
};

export type IntelFeedSchedule = {
  source: string;
  state: string;
  lastStarted: string | null;
  lastCompleted: string | null;
  lastError: string | null;
  lastFactCount: number;
  runs: number;
  nextRun: string | null;
  intervalSeconds: number;
};

export type IntelSchedule = {
  enabled: boolean;
  running: boolean;
  initialDelaySeconds: number;
  feeds: Record<string, IntelFeedSchedule>;
};

export type Readiness = {
  formulaVersion: string;
  score: number | null;
  band: string | null;
  coverage: number;
  unknownComponents: string[];
  components: Array<{
    name: string;
    value: number | null;
    numerator: number;
    denominator: number;
    status: string;
  }>;
  inputs: {
    assets: number;
    services: number;
    exposedServices: number;
    intelFacts: number;
    findings: number;
    uncertainMatches: number;
    guardRequests: number;
    unblockedAttacks: number;
    nvdLoaded: boolean;
  };
  readiness: string;
};

export type EngineScope = {
  scopeId: string;
  targets: string[];
  environment: string;
  profiles: string[];
  approved: boolean;
  expiresAt: string;
};

export type AuthorizationChallenge = {
  challengeId: string;
  recordName: string;
  token: string;
  expiresAt: string;
};

export type TargetAuthorization = {
  authorizationId: string;
  target: string;
  expiresAt: string;
};

export type EngineScan = {
  scanId: string;
  scopeId: string;
  target: string;
  profileId: string;
  state: ScanState | string;
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

export type TargetScanRecord = {
  scanId: string;
  scopeId: string;
  target: string;
  profileId: string;
  state: string;
  assets: string[];
  services: ScanResult["services"];
  tlsFindings: ScanResult["tlsFindings"];
  warnings: string[];
};

export type TargetRecord = {
  scopeId: string;
  target: string;
  scans: TargetScanRecord[];
};

export type TargetRecordList = { items: TargetRecord[] };

export type IntelFinding = {
  service_id: string;
  asset_id: string;
  cve_id: string;
  match_method: string;
  confidence: number;
  evidence: string[];
  freshness: string;
  priority: {
    formula_version: string;
    score: number;
    inputs: Record<string, number>;
    missing: string[];
    confidence: number;
  };
};

export type FindingList = {
  items: IntelFinding[];
  pagination: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
  };
};

export type SystemInfo = {
  deviceType: string;
  hostname: string;
  platform: string;
  os: string;
  release: string;
  machine: string;
  processor: string;
  pythonVersion: string;
  cpu: { logical: number; physical: number; frequencyMhz: number | null };
  memory: { totalGb: number; availableGb: number };
  disk: { path: string; totalGb: number; freeGb: number };
  battery: { percent: number; plugged: boolean } | null;
  bootTime: string;
  uptimeSeconds: number;
};

export const TERMINAL_SCAN_STATES = new Set([
  "completed",
  "partial",
  "failed",
  "timed_out",
  "cancelled",
]);

export type ScanLevel = "normal" | "medium" | "high" | "deep";

export type ScanLevelDefinition = {
  id: ScanLevel;
  label: string;
  nmap: string;
  subfinder: string;
  requiresAuthorization: boolean;
};

export const SCAN_LEVELS: ScanLevelDefinition[] = [
  {
    id: "normal",
    label: "Normal",
    nmap: "Top 100 TCP ports",
    subfinder: "Default passive sources",
    requiresAuthorization: false,
  },
  {
    id: "medium",
    label: "Medium",
    nmap: "Top 1,000 ports + versions",
    subfinder: "All passive sources",
    requiresAuthorization: false,
  },
  {
    id: "high",
    label: "High",
    nmap: "All TCP ports + light versions",
    subfinder: "Recursive passive sources",
    requiresAuthorization: true,
  },
  {
    id: "deep",
    label: "Deep",
    nmap: "All TCP ports + full versions",
    subfinder: "Recursive sources, longer collection",
    requiresAuthorization: true,
  },
];

export const LEVEL_PROFILE_IDS: Record<
  "nmap" | "subfinder",
  Record<ScanLevel, string>
> = {
  nmap: {
    normal: "service_inventory_normal_v1",
    medium: "service_inventory_medium_v1",
    high: "service_inventory_high_v1",
    deep: "service_inventory_deep_v1",
  },
  subfinder: {
    normal: "passive_subdomain_normal_v1",
    medium: "passive_subdomain_medium_v1",
    high: "passive_subdomain_high_v1",
    deep: "passive_subdomain_deep_v1",
  },
};

export function scanLevelRequiresAuthorization(level: ScanLevel): boolean {
  return level === "high" || level === "deep";
}

export function profileTimeoutSeconds(profileId: string): number {
  const timeouts: Record<string, number> = {
    synthetic_inventory_v1: 60,
    tls_metadata_v1: 30,
    service_inventory_v1: 300,
    service_inventory_normal_v1: 300,
    service_inventory_medium_v1: 600,
    service_inventory_high_v1: 900,
    service_inventory_deep_v1: 1800,
    passive_subdomain_v1: 300,
    passive_subdomain_normal_v1: 300,
    passive_subdomain_medium_v1: 600,
    passive_subdomain_high_v1: 900,
    passive_subdomain_deep_v1: 1200,
  };
  return timeouts[profileId] ?? 120;
}

export const PROFILE_LABELS: Record<string, string> = {
  tls_metadata_v1: "TLS metadata — one real read on port 443",
  synthetic_inventory_v1: "Synthetic inventory — fixture, no network",
  service_inventory_v1: "Nmap service scan — choose a level in this card",
  passive_subdomain_v1: "Subfinder — choose a level in this card",
  service_inventory_normal_v1: "Nmap normal — top 100 TCP ports",
  service_inventory_medium_v1: "Nmap medium — top 1,000 ports + versions",
  service_inventory_high_v1: "Nmap high — all TCP ports + light versions",
  service_inventory_deep_v1: "Nmap deep — all TCP ports + full versions",
  passive_subdomain_normal_v1: "Subfinder normal — default sources",
  passive_subdomain_medium_v1: "Subfinder medium — all sources",
  passive_subdomain_high_v1: "Subfinder high — recursive sources",
  passive_subdomain_deep_v1: "Subfinder deep — recursive, longer collection",
};

export const PROFILE_SHORT_LABELS: Record<string, string> = {
  tls_metadata_v1: "TLS metadata",
  synthetic_inventory_v1: "Synthetic inventory",
  service_inventory_v1: "Nmap service scan",
  passive_subdomain_v1: "Subfinder passive",
  service_inventory_normal_v1: "Nmap normal",
  service_inventory_medium_v1: "Nmap medium",
  service_inventory_high_v1: "Nmap high",
  service_inventory_deep_v1: "Nmap deep",
  passive_subdomain_normal_v1: "Subfinder normal",
  passive_subdomain_medium_v1: "Subfinder medium",
  passive_subdomain_high_v1: "Subfinder high",
  passive_subdomain_deep_v1: "Subfinder deep",
};

export function normalizeTarget(input: string): { host: string; error: string | null } {
  let value = input.trim().toLowerCase();
  if (!value) return { host: "", error: "Enter a domain name." };
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(value)) value = `https://${value}`;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return { host: "", error: "Enter a valid domain name." };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { host: "", error: "Only http and https targets are supported." };
  }
  const host = parsed.hostname.replace(/\.$/, "");
  if (!host || host.includes(":") || host.includes("*")) {
    return { host: "", error: "IPv6 addresses and wildcards are not supported." };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    return { host: "", error: "Enter a domain name, not an IP address." };
  }
  if (!host.includes(".")) {
    return {
      host: "",
      error: "The engine needs a dotted domain name. localhost is not supported.",
    };
  }
  const labels = host.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return { host: "", error: "The domain contains invalid characters." };
  }
  return { host, error: null };
}

// Suffix-only review labels for passive Subfinder output. These are heuristics,
// not takeover confirmations: no DNS lookup, HTTP request, or cloud API call is
// made by the browser or the passive profile.
const TAKEOVER_REVIEW_SUFFIXES = [
  ".s3.amazonaws.com",
  ".herokuapp.com",
  ".github.io",
  ".gitlab.io",
  ".netlify.app",
  ".vercel.app",
  ".azurewebsites.net",
  ".cloudapp.net",
  ".appspot.com",
  ".firebaseapp.com",
  ".web.app",
  ".pages.dev",
  ".workers.dev",
  ".surge.sh",
  ".bitbucket.io",
  ".readthedocs.io",
  ".ghost.io",
  ".myshopify.com",
  ".wordpress.com",
  ".tumblr.com",
  ".blogspot.com",
  ".pantheonsite.io",
  ".fly.dev",
  ".onrender.com",
  ".glitch.me",
  ".repl.co",
  ".cloudfront.net",
  ".blob.core.windows.net",
  ".trafficmanager.net",
  ".azureedge.net",
  ".fastly.net",
  ".akamaiedge.net",
  ".edgekey.net",
  ".edgesuite.net",
] as const;

export function takeoverSignal(host: string): string | null {
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  if (normalized.split(".").length < 3) return null;
  return TAKEOVER_REVIEW_SUFFIXES.some((suffix) => normalized.endsWith(suffix))
    ? "passive review"
    : null;
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
