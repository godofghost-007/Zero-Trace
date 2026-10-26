import { expect, test, type Page } from "@playwright/test";
import { expectConsole, signIn } from "./helpers";

async function uncheckProfile(page: Page, name: RegExp) {
  const checkbox = page.getByRole("checkbox", { name });
  if ((await checkbox.count()) > 0 && await checkbox.isChecked()) {
    await checkbox.uncheck();
  }
}

test("an operator creates a scope and runs the synthetic profile", async ({ page }) => {
  await signIn(page);
  await expectConsole(page);
  await page.getByRole("link", { name: "Targets & scope" }).click();
  await expect(page.getByRole("heading", { name: "Targets & scope" })).toBeVisible();
  await expect(page.getByText("ENGINE CONNECTED")).toBeVisible();

  await uncheckProfile(page, /Nmap service scan/);
  await uncheckProfile(page, /Subfinder passive/);
  await uncheckProfile(page, /TLS metadata/);

  const synthetic = page.getByRole("checkbox", { name: /Synthetic inventory/ });
  await expect(synthetic).toHaveCount(1);
  await synthetic.check();

  await page.getByLabel("Target URL, hostname, or IPv4").fill("lab.example.test");
  await page.getByRole("button", { name: "Create scope & run selected scans" }).click();

  const liveScans = page.locator(".panel").filter({
    has: page.getByRole("heading", { name: "Live scans" }),
  });
  const scanRows = liveScans.locator(".scope-row");
  await expect(scanRows).toHaveCount(1);
  await expect(scanRows).toContainText("Synthetic inventory");
  await expect(scanRows.getByText("COMPLETED", { exact: true })).toBeVisible();
  await expect(liveScans.locator(".result-card").filter({ hasText: "TARGET" })).toContainText("lab.example.test");
  await expect(liveScans.locator(".result-card").filter({ hasText: "ASSETS / SERVICES" })).toContainText("1 / 1");
});

test("an engine outage is surfaced and keeps scope creation disabled", async ({ page }) => {
  await signIn(page);
  await expectConsole(page);

  await page.route("**/api/v1/engine/status", (route) => route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({
      error: { code: "engine_unavailable", message: "Engine unavailable" },
    }),
  }));

  await page.getByRole("link", { name: "Targets & scope" }).click();
  await expect(page.getByRole("heading", { name: "Targets & scope" })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText(/Engine unavailable/i);
  await expect(page.getByText("ENGINE OFFLINE")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create scope & run selected scans" })).toBeDisabled();
});
