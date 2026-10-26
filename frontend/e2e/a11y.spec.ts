import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { expectConsole, signIn } from "./helpers";

async function expectNoSeriousA11yViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa"])
    .analyze();
  const serious = results.violations.filter((violation) => (
    violation.impact === "serious" || violation.impact === "critical"
  ));
  expect(
    serious,
    JSON.stringify(
      serious.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        help: violation.help,
        targets: violation.nodes.map((node) => node.target),
      })),
      null,
      2,
    ),
  ).toEqual([]);
}

test("the login screen has no serious accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Operator sign-in" })).toBeVisible();
  await expectNoSeriousA11yViolations(page);
});

test("the operator console has no serious accessibility violations", async ({ page }) => {
  await signIn(page);
  await expectConsole(page);
  await expectNoSeriousA11yViolations(page);
});
