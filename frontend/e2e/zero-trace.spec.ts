import { expect, test, type Route } from "@playwright/test";
import { expectConsole, signIn } from "./helpers";

const profiles = [
  "service_inventory_normal_v1",
  "passive_subdomain_normal_v1",
  "tls_metadata_v1",
  "synthetic_inventory_v1",
];

const scope = {
  scopeId: "scope-lab-example-test",
  targets: ["lab.example.test"],
  environment: "synthetic",
  approved: true,
  expiresAt: "2027-01-01T00:00:00+00:00",
  profiles,
};

const record = {
  scopeId: scope.scopeId,
  target: "lab.example.test",
  scans: [
    {
      scanId: "scan-nmap",
      scopeId: scope.scopeId,
      target: "lab.example.test",
      profileId: "service_inventory_normal_v1",
      state: "completed",
      assets: ["lab.example.test"],
      services: [
        {
          asset: "lab.example.test",
          protocol: "tcp",
          port: 443,
          product: "nginx",
          version: "1.25",
          tlsStatus: "valid",
        },
      ],
      tlsFindings: [],
      warnings: [],
    },
    {
      scanId: "scan-subfinder",
      scopeId: scope.scopeId,
      target: "lab.example.test",
      profileId: "passive_subdomain_normal_v1",
      state: "completed",
      assets: ["www.lab.example.test"],
      services: [],
      tlsFindings: [],
      warnings: [],
    },
    {
      scanId: "scan-tls",
      scopeId: scope.scopeId,
      target: "lab.example.test",
      profileId: "tls_metadata_v1",
      state: "completed",
      assets: ["lab.example.test"],
      services: [],
      tlsFindings: [
        {
          subject: "lab.example.test",
          issuer: "Test CA",
          expires_at: "2027-01-01",
          status: "valid",
        },
      ],
      warnings: [],
    },
    {
      scanId: "scan-synthetic",
      scopeId: scope.scopeId,
      target: "lab.example.test",
      profileId: "synthetic_inventory_v1",
      state: "completed",
      assets: ["inventory.lab.example.test"],
      services: [],
      tlsFindings: [],
      warnings: [],
    },
  ],
};

const finding = {
  service_id: `${scope.scopeId}:lab.example.test:tcp:443`,
  asset_id: "lab.example.test",
  cve_id: "CVE-2025-0001",
  match_method: "cpe",
  confidence: 0.94,
  evidence: ["nginx 1.25"],
  freshness: "current",
  priority: {
    formula_version: "priority-v1",
    score: 92,
    inputs: { cvss: 0.95, epss: 0.42, kev: 1 },
    missing: [],
    confidence: 0.9,
  },
};

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

test("ZeroTrace run feeds Trace Recon and Intel Guard correlation", async ({ page }) => {
  let scansStarted = false;

  await page.route("**/api/v1/engine/status", (route) => json(route, {
    service: "zerotrace-engine",
    mode: "live",
    time: new Date().toISOString(),
    adapters: [],
    profiles,
    scopes: 1,
    scans: scansStarted ? 4 : 0,
    intel: {
      facts: 100,
      findings: scansStarted ? 1 : 0,
      uncertainMatches: 0,
      feeds: {},
    },
    guard: {
      mode: "regex",
      detector: "regex",
      piiScanner: true,
      upstreamConfigured: false,
    },
    readiness: {
      score: 88,
      aei: 10,
      vui: 20,
      aiet: 0,
      coverage: 100,
      band: "Moderate band",
      formulaVersion: "readiness-v1",
      components: [],
      unknownComponents: [],
    },
  }));

  await page.route("**/api/v1/engine/scopes", async (route) => {
    if (route.request().method() === "POST") {
      await json(route, scope, 201);
      return;
    }
    await json(route, { items: [scope] });
  });

  await page.route("**/api/v1/engine/records", (route) => json(route, {
    items: scansStarted ? [record] : [],
  }));

  await page.route("**/api/v1/engine/scans", (route) => {
    const body = route.request().postDataJSON() as { profileId: string };
    scansStarted = true;
    return json(route, {
      scanId: `scan-${body.profileId}`,
      state: "queued",
    }, 202);
  });

  await page.route("**/api/v1/engine/scans/**", (route) => {
    const scanId = route.request().url().split("/").at(-1) ?? "scan";
    return json(route, { scanId, state: "completed" });
  });

  await page.route("**/api/v1/engine/intel/findings**", (route) => json(route, {
    items: [finding],
    pagination: { page: 1, pageSize: 100, totalItems: 1, totalPages: 1 },
  }));

  await signIn(page);
  await expectConsole(page);
  await expect(page.getByLabel("Target")).toContainText("lab.example.test");

  await page.getByRole("button", { name: /Run lab\.example\.test/ }).click();
  await expect(page.getByText(/Recon finished/)).toBeVisible({ timeout: 25_000 });

  const navigation = page.getByRole("navigation", { name: "Main navigation" });
  await navigation.getByRole("link", { name: /Trace Recon/ }).click();
  await expect(page.getByRole("heading", { name: "Trace Recon" })).toBeVisible();
  await expect(page.getByText("www.lab.example.test").first()).toBeVisible();
  await expect(page.getByText(/nginx/).first()).toBeVisible();
  await expect(page.getByText("valid certificate").first()).toBeVisible();

  await navigation.getByRole("link", { name: /Intel Guard/ }).click();
  await expect(page.getByRole("heading", { name: "Intel Guard" })).toBeVisible();
  await expect(page.getByText("CVE-2025-0001").first()).toBeVisible();
  await expect(page.getByText("NVD (CVSS)").first()).toBeVisible();
  await expect(page.getByText("EPSS").first()).toBeVisible();
  await expect(page.getByText("KEV").first()).toBeVisible();

  await page.getByRole("button", { name: "Correlation" }).click();
  await expect(page.getByText("1 remediation script(s) queued")).toBeVisible();
  await expect(page.locator(".script-block")).toContainText("ufw deny");
  await expect(page.locator(".script-block")).toContainText("443");
  await page.getByRole("button", { name: "Run dry-run" }).click();
  await expect(page.getByText("Dry run recorded for CVE-2025-0001")).toBeVisible();
});
