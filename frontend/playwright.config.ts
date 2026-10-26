import { defineConfig, devices } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

const frontendDir = process.cwd();
const rootDir = path.resolve(frontendDir, "..");
const dataDir = process.env.ZEROTRACE_E2E_DATA_DIR
  ?? path.join(frontendDir, ".e2e-data");
const engineDb = path.join(dataDir, "engine.sqlite3");
const bffData = path.join(dataDir, "bff");

fs.mkdirSync(path.dirname(engineDb), { recursive: true });
fs.mkdirSync(bffData, { recursive: true });

const baseEnv = Object.fromEntries(
  Object.entries(process.env).filter((entry): entry is [string, string] => (
    typeof entry[1] === "string"
  )),
);

const python = process.env.ZEROTRACE_E2E_PYTHON
  ?? (process.platform === "win32"
    ? path.join(rootDir, ".venv", "Scripts", "python.exe")
    : "python");

const engineKey = "sk-e2e-engine-1234567890abcdef";
const engineSecret = "e2e-engine-auth-secret-0123456789";
const bootstrapEmail = "e2e@zerotrace.local";
const bootstrapPassword = "E2e-correct-horse-battery-staple-42!";

const sharedEnv = {
  ...baseEnv,
  ZEROTRACE_ENV: "development",
  ZEROTRACE_ENGINE_API_KEY: engineKey,
  ZEROTRACE_ENGINE_AUTH_SECRET: engineSecret,
  ZEROTRACE_INTEL_SCHEDULE_ENABLED: "false",
  ZEROTRACE_TARGET_ALLOWLIST: "lab.example.test",
  ZEROTRACE_MAX_LOGIN_ATTEMPTS: "50",
};

const browserDevices = {
  chromium: devices["Desktop Chrome"],
  firefox: devices["Desktop Firefox"],
  webkit: devices["Desktop Safari"],
};
const requestedBrowsers = (process.env.ZEROTRACE_E2E_BROWSERS ?? "chromium")
  .split(",")
  .map((name) => name.trim())
  .filter((name): name is keyof typeof browserDevices => name in browserDevices);
const browsers = requestedBrowsers.length > 0 ? requestedBrowsers : ["chromium"];

export default defineConfig({
  testDir: "./e2e",
  outputDir: ".e2e-results",
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: browsers.map((name) => ({
    name,
    use: { ...browserDevices[name] },
  })),
  webServer: [
    {
      command: `"${python}" -m scripts.live_engine`,
      cwd: rootDir,
      url: "http://127.0.0.1:8765/ready",
      timeout: 120_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...sharedEnv,
        ZEROTRACE_ENGINE_HOST: "127.0.0.1",
        ZEROTRACE_ENGINE_PORT: "8765",
        ZEROTRACE_LIVE_DB: engineDb,
      },
    },
    {
      command: `"${python}" -m flask --app backend:create_app run --host 127.0.0.1 --port 3000`,
      cwd: frontendDir,
      url: "http://127.0.0.1:3000/api/v1/health",
      timeout: 120_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...sharedEnv,
        FLASK_SECRET_KEY: "e2e-flask-secret-key-0123456789abcdef",
        ZEROTRACE_DATA_DIR: bffData,
        AUTO_CREATE_SCHEMA: "true",
        DEMO_MODE: "true",
        ZEROTRACE_AUTH_REQUIRED: "true",
        ZEROTRACE_COOKIE_SECURE: "false",
        ZEROTRACE_BOOTSTRAP_EMAIL: bootstrapEmail,
        ZEROTRACE_BOOTSTRAP_PASSWORD: bootstrapPassword,
        ZEROTRACE_MFA_ENCRYPTION_KEY: "IVZYZcF0cjwVPvTC3zIc22aCbh4nvRCKt2XkQzeA5Qg=",
        ZEROTRACE_ENGINE_URL: "http://127.0.0.1:8765",
        ZEROTRACE_ENGINE_MODE: "live",
      },
    },
  ],
});
