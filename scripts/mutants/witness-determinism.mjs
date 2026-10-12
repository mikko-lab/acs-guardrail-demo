#!/usr/bin/env node
/**
 * Determinism check of the lifecycle witnesses (docs/mutant-gate.md#determinism). Runs the lifecycle test files
 * (tests/approval-lifecycle.test.ts and tests/approval-lifecycle-components.test.ts) --runs times (default 3) on the
 * unmodified tree with WITNESS_LOG and requires, in every run, that jest exits 0 without signal or timeout, that every
 * test passes, that every witness-log entry is bound to a test file and test, and that the witness log (every check value
 * and every caught error, per test) is identical to the first run's. Exit 0 when deterministic, 1 when a run differs or fails, 2 on a technical error of this script.
 *
 *   node scripts/mutants/witness-determinism.mjs [--runs 3]
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

try {
  const root = resolve(new URL("../..", import.meta.url).pathname);
  const args = process.argv.slice(2);
  const runs = Number(args.includes("--runs") ? args[args.indexOf("--runs") + 1] : 3);
  if (!Number.isInteger(runs) || runs < 2) throw new Error("--runs must be an integer of at least 2");
  const files = ["tests/approval-lifecycle.test.ts", "tests/approval-lifecycle-components.test.ts"];
  const work = mkdtempSync(join(tmpdir(), "witness-determinism-"));
  const observations = [];
  let failed = 0;
  for (let i = 1; i <= runs; i++) {
    const log = join(work, `run-${i}.jsonl`);
    const json = join(work, `run-${i}.json`);
    const r = spawnSync(process.execPath, [join(root, "node_modules/jest/bin/jest.js"), "--ci", "--json", "--outputFile", json, ...files],
      { cwd: root, encoding: "utf8", maxBuffer: 1 << 28, timeout: 10 * 60_000, env: { ...process.env, WITNESS_LOG: log } });
    const result = existsSync(json) ? JSON.parse(readFileSync(json, "utf8")) : undefined;
    const entries = existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
    // Entries are grouped by test file and test; an entry written outside any test fails the run.
    const byTest = {};
    for (const e of entries) (byTest[`${e.file} :: ${e.test}`] ??= []).push(e);
    const unbound = entries.filter(e => typeof e.test !== "string" || e.test === "" || typeof e.file !== "string").length;
    const ok = !r.error && !r.signal && r.status === 0 && result?.success === true && result.numFailedTests === 0 && unbound === 0;
    const checks = entries.filter(e => e.kind === "check").length, errors = entries.filter(e => e.kind === "error").length;
    const same = i === 1 || isDeepStrictEqual(byTest, observations[0]);
    if (!ok || !same) failed++;
    console.log(`run ${i}: jest ${r.error ? r.error.code : r.signal ?? r.status}, ${result?.numPassedTests ?? 0}/${result?.numTotalTests ?? 0} passed, ${checks} witness checks, ${errors} caught errors, ${unbound} unbound entries${i > 1 ? `, identical to run 1: ${same}` : ""}`);
    observations.push(byTest);
  }
  rmSync(work, { recursive: true, force: true });
  console.log(failed ? `witness determinism: FAILED (${failed} of ${runs} runs)` : `witness determinism: ${runs} identical runs`);
  process.exit(failed ? 1 : 0);
} catch (error) {
  console.error(`witness determinism: internal error: ${error?.stack ?? error}`);
  process.exit(2);
}
