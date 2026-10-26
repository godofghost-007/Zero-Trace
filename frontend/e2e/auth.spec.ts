import {
  expect,
  test,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import {
  bootstrapEmail,
  bootstrapPassword,
  expectConsole,
  signIn,
  totp,
} from "./helpers";

type PostOptions = {
  data?: Record<string, string>;
  headers?: Record<string, string>;
  timeout?: number;
};

async function postWithRetry(
  request: APIRequestContext,
  url: string,
  options: PostOptions,
  attempts = 3,
): Promise<APIResponse> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await request.post(url, options);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
  }
  throw lastError;
}

test("password login reaches the operator console", async ({ page }) => {
  await signIn(page);
  await expectConsole(page);
  await expect(page.getByRole("button", { name: /Continue with SSO/ })).toHaveCount(0);
});

test("invalid credentials show a safe error", async ({ page }) => {
  await signIn(page, bootstrapEmail, "wrong-password");
  await expect(page.getByRole("alert")).toContainText(/Invalid email or password/i);
});

test("an enrolled operator must complete the MFA challenge", async ({ page, request }, testInfo) => {
  const mfaPassword = "Mfa-correct-horse-battery-staple-42!";

  const adminLogin = await postWithRetry(request, "/api/v1/auth/login", {
    data: { email: bootstrapEmail, password: bootstrapPassword },
  });
  expect(adminLogin.ok()).toBeTruthy();
  const adminCsrf = (await adminLogin.json()).csrfToken as string;

  let mfaEmail = "";
  let created: APIResponse | undefined;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    mfaEmail = `mfa-e2e-${testInfo.project.name}-${Date.now()}-${attempt}@zerotrace.local`;
    created = await postWithRetry(request, "/api/v1/auth/users", {
      data: { email: mfaEmail, password: mfaPassword, role: "viewer" },
      headers: { "X-CSRF-Token": adminCsrf },
    });
    if (created.status() === 201 || created.status() !== 409) break;
  }
  expect(created?.status()).toBe(201);

  const userLogin = await postWithRetry(request, "/api/v1/auth/login", {
    data: { email: mfaEmail, password: mfaPassword },
  });
  expect(userLogin.ok()).toBeTruthy();
  const userCsrf = (await userLogin.json()).csrfToken as string;

  const enrollment = await postWithRetry(request, "/api/v1/auth/mfa/enroll", {
    headers: { "X-CSRF-Token": userCsrf },
  });
  expect(enrollment.ok()).toBeTruthy();
  const secret = (await enrollment.json()).secret as string;

  const activation = await postWithRetry(request, "/api/v1/auth/mfa/activate", {
    data: { code: totp(secret) },
    headers: { "X-CSRF-Token": userCsrf },
  });
  expect([200, 409]).toContain(activation.status());

  const logout = await postWithRetry(request, "/api/v1/auth/logout", {
    headers: { "X-CSRF-Token": userCsrf },
  });
  expect(logout.ok()).toBeTruthy();

  await signIn(page, mfaEmail, mfaPassword);
  await expect(page.getByRole("heading", { name: "Verify your session" })).toBeVisible();
  await page.getByLabel("Authentication code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expectConsole(page);
});
