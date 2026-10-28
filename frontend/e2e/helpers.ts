import { expect, type Page } from "@playwright/test";
import crypto from "node:crypto";

export const bootstrapEmail = "e2e@zerotrace.local";
export const bootstrapPassword = "E2e-correct-horse-battery-staple-42!";

export async function openLogin(page: Page) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      // "commit" avoids waiting on a load event that Firefox can occasionally
      // leave pending when a prior test leaves a polling request in flight.
      await page.goto("/", { waitUntil: "commit", timeout: 30_000 });
      break;
    } catch (error) {
      if (attempt === 1) throw error;
    }
  }

  const signInHeading = page.getByRole("heading", { name: "Operator sign-in" });
  try {
    await expect(signInHeading).toBeVisible({ timeout: 20_000 });
  } catch {
    await page.reload({ waitUntil: "commit", timeout: 30_000 });
    await expect(signInHeading).toBeVisible({ timeout: 20_000 });
  }
}

export async function signIn(
  page: Page,
  email = bootstrapEmail,
  password = bootstrapPassword,
) {
  await openLogin(page);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Enter console" }).click();
}

export async function expectConsole(page: Page) {
  await expect(page.getByRole("heading", { name: "ZeroTrace", exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
}

export function totp(secret: string, timestamp = Date.now()): string {
  const key = base32Decode(secret);
  const counter = Math.floor(timestamp / 30_000);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = (
    ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff)
  ) % 1_000_000;
  return value.toString().padStart(6, "0");
}

function base32Decode(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.replace(/=+$/g, "").toUpperCase();
  let bits = 0;
  let accumulator = 0;
  const bytes: number[] = [];
  for (const character of normalized) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid base32 secret");
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((accumulator >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
