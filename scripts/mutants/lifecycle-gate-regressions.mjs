#!/usr/bin/env node
/**
 * Regressions of the shared mutant gate under the lifecycle manifest's rules (strict whole run, lifecycle evidence
 * kinds; docs/mutant-gate.md#lifecycle-gate-regressions). Each case runs the gate with one fixed, hash-checked manifest
 * from mutants/lifecycle/regressions and requires its exit status and the reason it reports:
 *
 *   RL1-detected      the real M53 mutant                                     -> 0 (detected)
 *   RL2-inventory     M53 plus deletion of an unrelated test                  -> 2 (test inventory differs)
 *   RL3-value         the witness logs a value that is neither control nor mutant -> 2 (neither control nor mutant)
 *   RL4-error         M57 plus a changed error message: an unaccepted caught error -> 2 (unexpected caught errors)
 *   RL5-other-failure M53 plus a failing unrelated test (strict whole run)    -> 2 (unexpected failure outside the witnesses)
 *   RL6-crash         a patch path that is a directory (gate crash)           -> 2 (internal error)
 *   RL7-timeout       M53 plus a jest global teardown that never ends         -> 2 (jest: timed out)
 *   RL8-signal        M53 plus a jest config that kills its own process       -> 2 (jest: killed by signal)
 *   RL9-unchanged     a production-code change that changes nothing (comment) -> 1 (not detected)
 *   RL10-kinds        M67 (check_and_lifecycle) and M71 (component_check_point) -> 0, and the report counts neither as
 *                     containment evidence
 *   RL11-no-log       M53 plus a witness helper that writes no witness log    -> 2 (witness log missing)
 *   RL12-no-witness   M53 plus an L4c witness that never logs (the log exists) -> 2 (named witness logged no observations)
 *   RL13-collateral-syntax    M58 plus the pinned collateral L5-session failing with a SyntaxError -> 2 (collateral differs)
 *   RL14-collateral-assertion M64 plus the pinned collateral L11-unobservable failing with a SyntaxError at its
 *                             assertion, same observations                                     -> 2 (assertion differs)
 *   RL15-error-suffix         M57 plus a suffix outside the manifest in the L2b witnesses' caught errors -> 2 (unexpected caught errors)
 *   RL16-m58, RL17-m57        the real M58 and M57 mutants (controls of RL13 and RL15)         -> 0 (detected)
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
const out = id => `out/lifecycle-gate-regressions/${id}`;
const summary = id => JSON.parse(readFileSync(join(root, out(id), "report.json"), "utf8")).summary;
const sameList = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const cases = [
  ["RL1-detected", 0, "detected"],
  ["RL2-inventory", 2, "test inventory differs from the control"],
  ["RL3-value", 2, "neither control"],
  ["RL4-error", 2, "unexpected caught errors"],
  ["RL5-other-failure", 2, "unexpected failure or changed observation outside the named witnesses"],
  ["RL6-crash", 2, "internal error"],
  ["RL7-timeout", 2, "jest: timed out", ["--jest-timeout-ms", "240000"]],
  ["RL8-signal", 2, "jest: killed by signal SIGKILL"],
  ["RL9-unchanged", 1, "not_detected"],
  ["RL10-kinds", 0, "detected", [], id => {
    const s = summary(id);
    return sameList(s.containment_evidence, []) && sameList(s.lifecycle_evidence, ["M67"]) && sameList(s.evidence.component_check_point, ["M71"])
      ? "" : `report counts ${JSON.stringify({ containment: s.containment_evidence, lifecycle: s.lifecycle_evidence, component: s.evidence.component_check_point })}`;
  }],
  ["RL11-no-log", 2, "witness log missing"],
  ["RL12-no-witness", 2, "logged no observations"],
  ["RL13-collateral-syntax", 2, "collateral tests/approval-lifecycle.test.ts :: L5 binding comparisons"],
  ["RL14-collateral-assertion", 2, "assertion failure"],
  ["RL15-error-suffix", 2, "unexpected caught errors"],
  ["RL16-m58", 0, "detected"],
  ["RL17-m57", 0, "detected"],
];
let failed = 0;
for (const [id, expected, reason, extra = [], check] of cases) {
  const r = spawnSync(process.execPath, ["scripts/mutants/run-mutant-gate.mjs", "--manifest", `mutants/lifecycle/regressions/${id}.json`, "--out", out(id), ...extra], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
  const output = r.stdout + r.stderr;
  const line = output.split("\n").find(l => l.startsWith(id) || l.startsWith("M")) ?? (r.stderr.trim().split("\n").find(l => l.startsWith("mutant gate:")) ?? "");
  const reportIssue = r.status === expected && check ? check(id) : "";
  const ok = r.status === expected && !r.signal && output.includes(reason) && !reportIssue;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${id}: gate exit ${r.status}${r.signal ? ` (signal ${r.signal})` : ""}, expected ${expected} with "${reason}"${reportIssue ? `; ${reportIssue}` : ""} | ${line.slice(0, 400)}`);
}
process.exit(failed ? 1 : 0);
