#!/usr/bin/env node
/**
 * Regressions of the tenant mutant gate itself (docs/tenant-scope.md#gate-regressions). Each case runs the gate with
 * one fixed, hash-checked manifest from mutants/tenant/regressions and requires its exit status:
 *   R1-inventory  M27e patch plus deletion of an unrelated test   -> 2 (test inventory differs from the control)
 *   R2-syntax     unexpected SyntaxError on the request path       -> 2 (unexpected witness value / caught error)
 *   R3-m27e       the real M27e mutant                             -> 0 (detected at stage start)
 */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
const cases = [["R1-inventory", 2], ["R2-syntax", 2], ["R3-m27e", 0]];
let failed = 0;
for (const [id, expected] of cases) {
  const r = spawnSync("node", ["scripts/mutants/run-tenant-mutants.mjs", "--manifest", `mutants/tenant/regressions/${id}.json`, "--out", `out/mutant-gate-regressions/${id}`], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
  const line = (r.stdout + r.stderr).split("\n").find(l => l.startsWith(id)) ?? (r.stderr.trim().split("\n").pop() ?? "");
  const ok = r.status === expected && !r.signal;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${id}: gate exit ${r.status}${r.signal ? ` (signal ${r.signal})` : ""}, expected ${expected} | ${line}`);
}
process.exit(failed ? 1 : 0);
