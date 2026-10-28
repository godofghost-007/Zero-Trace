import { expect, test } from "@playwright/test";
import { expectConsole, signIn } from "./helpers";

test("an operator saves and removes an authorized target in Admin", async ({ page }) => {
  await page.route("**/api/v1/engine/records", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ items: [] }),
  }));
  await signIn(page);
  await expectConsole(page);

  const navigation = page.getByRole("navigation", { name: "Main navigation" });
  await navigation.getByRole("link", { name: /Admin/ }).click();
  await page.getByRole("tab", { name: "Targets & scope" }).click();
  await expect(page.getByRole("heading", { name: "Targets & scope" })).toBeVisible();
  await expect(page.getByText("0 SAVED").first()).toBeVisible();

  await page.getByLabel("Target domain").fill("lab.example.test");
  await page.getByRole("button", { name: "Save authorized target" }).click();
  await expect(page.getByRole("status")).toContainText("saved as an authorized target");
  await expect(page.getByText("lab.example.test").first()).toBeVisible();
  await expect(page.getByText("1 SAVED").first()).toBeVisible();

  await navigation.getByRole("link", { name: /ZeroTrace/ }).click();
  await expect(page.getByLabel("Target")).toContainText("lab.example.test");

  await navigation.getByRole("link", { name: /Admin/ }).click();
  await page.getByRole("tab", { name: "Targets & scope" }).click();
  await page.getByRole("button", { name: "Remove lab.example.test" }).click();
  await expect(page.getByRole("status")).toContainText("removed from the authorized target list");
  await expect(page.getByText("No authorized targets yet")).toBeVisible();
});

test("an engine outage is surfaced and keeps target saving disabled", async ({ page }) => {
  await page.route("**/api/v1/engine/records", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ items: [] }),
  }));
  await page.route("**/api/v1/engine/status", (route) => route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({
      error: { code: "engine_unavailable", message: "Engine unavailable" },
    }),
  }));

  await signIn(page);
  await expectConsole(page);
  const navigation = page.getByRole("navigation", { name: "Main navigation" });
  await navigation.getByRole("link", { name: /Admin/ }).click();
  await page.getByRole("tab", { name: "Targets & scope" }).click();
  await expect(page.getByRole("alert")).toContainText(/Engine unavailable/i);
  await expect(page.getByText("ENGINE OFFLINE")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save authorized target" })).toBeDisabled();
});
