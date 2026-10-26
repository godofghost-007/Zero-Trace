import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "zerotrace-e2e-"));
const environment = { ...process.env, ZEROTRACE_E2E_DATA_DIR: dataDir };
const cli = path.resolve("node_modules", "@playwright", "test", "cli.js");
const result = spawnSync(process.execPath, [cli, "test", ...process.argv.slice(2)], {
  stdio: "inherit",
  env: environment,
});

try {
  fs.rmSync(dataDir, { recursive: true, force: true });
} catch {
  // Windows can keep SQLite handles briefly after the server exits.
}

process.exit(result.status ?? 1);
