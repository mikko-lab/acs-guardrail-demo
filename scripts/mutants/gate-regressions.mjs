#!/usr/bin/env node
/**
 * Regressions of the shared mutant gate itself (docs/mutant-gate.md#gate-regressions). Each case runs the gate with
 * one fixed, hash-checked manifest from mutants/tenant/regressions and requires its exit status and the reason it
 * reports:
 *   R1-inventory  M27e patch plus deletion of an unrelated test   -> 2 (test inventory differs from the control)
 *   R2-syntax     unexpected SyntaxError on the request path       -> 2 (unexpected witness value / caught error)
 *   R3-m27e       the real M27e mutant                             -> 0 (detected at stage start)
 *   R4-crash      a patch path that is a directory (gate crash)    -> 2 (internal error, never exit 1)
 */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
const cases = [
  ["R1-inventory", 2, "test inventory differs from the control"],
  ["R2-syntax", 2, "neither control"],
  ["R3-m27e", 0, "detected"],
  ["R4-crash", 2, "internal error"],
];
let failed = 0;
for (const [id, expected, reason] of cases) {
  const r = spawnSync("node", ["scripts/mutants/run-mutant-gate.mjs", "--manifest", `mutants/tenant/regressions/${id}.json`, "--out", `out/mutant-gate-regressions/${id}`], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
  const output = r.stdout + r.stderr;
  const line = output.split("\n").find(l => l.startsWith(id)) ?? (r.stderr.trim().split("\n").find(l => l.startsWith("mutant gate:")) ?? "");
  const ok = r.status === expected && !r.signal && output.includes(reason);
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${id}: gate exit ${r.status}${r.signal ? ` (signal ${r.signal})` : ""}, expected ${expected} with "${reason}" | ${line.slice(0, 400)}`);
}
process.exit(failed ? 1 : 0);
