import { createHash } from "node:crypto";
export class InputError extends Error {}
export type Obj = Record<string, unknown>;
export function obj(value: unknown, label = "value"): Obj {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new InputError(`${label} must be an object.`);
  return value as Obj;
}
export function arr(value: unknown, label = "array", max = 10000): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max)
    throw new InputError(
      `${label} must be an array with at most ${max} entries.`,
    );
  return value;
}
export function str(value: unknown, fallback = "", max = 1000): string {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "string" || value.length > max)
    throw new InputError(`Expected text of at most ${max} characters.`);
  return value;
}
export function required(value: unknown, label: string): string {
  const s = str(value);
  if (!s.trim()) throw new InputError(`${label} is required.`);
  return s;
}
export function parseJSON(text: string): unknown {
  if (Buffer.byteLength(text) > 8 * 1024 * 1024)
    throw new InputError("Input exceeds the 8 MiB limit.");
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new InputError(
      "Invalid JSON. Export a CycloneDX or SPDX JSON document.",
    );
  }
}
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b, "en"))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
export const digest = (value: unknown): string =>
  createHash("sha256").update(canonical(value)).digest("hex");
export const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");
export function safeURL(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 3000) return null;
  try {
    const u = new URL(value);
    return ["https:", "http:"].includes(u.protocol) &&
      !u.username &&
      !u.password
      ? u.href
      : null;
  } catch {
    return null;
  }
}
export function date(value: unknown, label: string): string {
  const s = required(value, label);
  if (!Number.isFinite(Date.parse(s)))
    throw new InputError(`${label} must be a valid date.`);
  return s;
}
