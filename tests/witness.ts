import { appendFileSync } from "fs";
import { isDeepStrictEqual } from "util";

/**
 * Named witness assertions for the runtime-test mutant gate (docs/tenant-scope.md#mutant-gate,
 * mutants/tenant/manifest.json).
 *
 * A witness test evaluates all of its named checks, then throws one WitnessAssertionError that lists every failed
 * label, so a mutant that must fail both a check-point and an effect assertion shows both in one run.
 *
 * When WITNESS_LOG names a file (the gate sets it), every check and every error a witness test caught is appended to
 * it as one JSON line, whether the check passed or failed. The gate compares the observed values with the exact
 * control and mutant values in the manifest, and treats a caught error that the manifest does not accept as an
 * unexpected failure, never as check-point evidence. Undefined is logged as {"$undefined":true}.
 */
export class WitnessAssertionError extends Error {
  constructor(readonly failed: string[], detail: string) {
    super(detail);
    this.name = "WitnessAssertionError";
  }
}

export type WitnessCheck = [label: string, actual: unknown, expected: unknown];

const encode = (value: unknown): unknown =>
  value === undefined ? { $undefined: true }
    : Array.isArray(value) ? value.map(encode)
    : value !== null && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, encode(v)]))
    : value;

function log(entry: Record<string, unknown>): void {
  const file = process.env.WITNESS_LOG;
  if (!file) return;
  const test = expect.getState().currentTestName ?? "";
  appendFileSync(file, JSON.stringify({ test, ...entry }) + "\n");
}

/** Records an error a witness test caught (for example through an outcome() helper). */
export function observeError(error: unknown): void {
  const name = error instanceof Error ? error.name : typeof error;
  const message = error instanceof Error ? error.message : String(error);
  log({ kind: "error", name, message });
}

export function witness(...checks: WitnessCheck[]): void {
  for (const [label, actual, expected] of checks) log({ kind: "check", label, actual: encode(actual), expected: encode(expected) });
  const failed = checks.filter(([, actual, expected]) => !isDeepStrictEqual(actual, expected));
  if (failed.length === 0) return;
  const detail = failed.map(([label, actual, expected]) => `WITNESS[${label}] expected ${JSON.stringify(encode(expected))} received ${JSON.stringify(encode(actual))}`).join("; ");
  throw new WitnessAssertionError(failed.map(([label]) => label), detail);
}
