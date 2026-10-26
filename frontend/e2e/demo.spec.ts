import { expect, test } from "@playwright/test";
import { expectConsole, signIn } from "./helpers";

test("the deterministic Recon -> Intel -> Guard scenario stays usable", async ({ page }) => {
  await signIn(page);
  await expectConsole(page);

  const reset = page.getByRole("button", { name: "Reset scenario" });
  await expect(reset).toBeEnabled();
  await reset.click();
  await expect(page.locator(".build-stamp small")).toHaveText("READY TO RUN");

  await page.getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: /Trace Recon/ }).click();
  await expect(page.getByRole("heading", { name: "Trace Recon" })).toBeVisible();
  await page.getByRole("button", { name: "Run sample discovery" }).click();
  await expect(page.getByRole("button", { name: "Sample discovered" })).toBeVisible();
  await expect(page.getByText("portal.zt-lab.test").first()).toBeVisible();

  await page.getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: /Trace Intel/ }).click();
  await expect(page.getByRole("heading", { name: "Trace Intel" })).toBeVisible();
  await page.getByRole("button", { name: "Correlate sample asset" }).click();
  await expect(page.getByRole("button", { name: "Correlation complete" })).toBeVisible();

  await page.getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: /Trace Guard/ }).click();
  await expect(page.getByRole("heading", { name: "Trace Guard" })).toBeVisible();
  await page.getByRole("button", { name: "Simulate prompt attack" }).click();
  await expect(page.getByRole("button", { name: "Attack blocked" })).toBeVisible();
  await expect(page.getByText("Request blocked before upstream")).toBeVisible();
  await expect(page.getByText("CHAIN VALID")).toBeVisible();
});
