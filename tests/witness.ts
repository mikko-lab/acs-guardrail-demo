import { isDeepStrictEqual } from "util";

/**
 * Named witness assertions for the runtime-test mutant gate (docs/tenant-scope.md, mutants/tenant/manifest.json).
 * A witness test evaluates all of its named assertions and then throws one WitnessAssertionError that lists every
 * failed label, so a mutant that must fail both a check-point and an effect assertion shows both in one run. The
 * gate recognises a detection only by these labels; any other failure (TypeError, timeout, load error) is technical.
 */
export class WitnessAssertionError extends Error {
  constructor(readonly failed: string[], detail: string) {
    super(detail);
    this.name = "WitnessAssertionError";
  }
}

export type WitnessCheck = [label: string, actual: unknown, expected: unknown];

export function witness(...checks: WitnessCheck[]): void {
  const failed = checks.filter(([, actual, expected]) => !isDeepStrictEqual(actual, expected));
  if (failed.length === 0) return;
  const detail = failed.map(([label, actual, expected]) => `WITNESS[${label}] expected ${JSON.stringify(expected)} received ${JSON.stringify(actual)}`).join("; ");
  throw new WitnessAssertionError(failed.map(([label]) => label), detail);
}
