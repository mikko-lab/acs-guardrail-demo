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
 *   RL10-kinds        M58, M58-i, M65, M67 and M71                            -> 0, and the report counts only M58 as
 *                     containment, M67 as lifecycle, M65 as availability, M71 as component evidence, M58-i as a variant
 *   RL11-no-log       M53 plus a witness helper that writes no witness log    -> 2 (witness log missing)
 *   RL12-no-witness   M53 plus an L4c witness that never logs (the log exists) -> 2 (named witness logged no observations)
 *   RL13-collateral-syntax    M58 plus the pinned collateral L5-session failing with a SyntaxError -> 2 (collateral differs)
 *   RL14-collateral-assertion M64 plus the pinned collateral L11-unobservable failing with a SyntaxError at its
 *                             assertion, same observations                                     -> 2 (assertion differs)
 *   RL15-error-suffix         M57 plus a suffix outside the manifest in the L2b witnesses' caught errors -> 2 (unexpected caught errors)
 *   RL16-m58, RL17-m57        the real M58 and M57 mutants (controls of RL13 and RL15)         -> 0 (detected)
 *   RL18-witness-aftereach    M53 plus an afterEach error in the L4c witness after its WitnessAssertionError -> 2
 *   RL19-unbound-beforeall    M53 plus a witness-log entry written in a file-level beforeAll   -> 2 (outside any test)
 *   RL20-same-name-files      M53, with a fixture test of another file named like the L4c witness -> 0 (bound by file)
 *   RL21-ambiguous-name       M53, with a fixture test of the same file named like [LC-L3]     -> 2 (ambiguous binding)
 *   RL22-tmpdir-worktree      M53 run with TMPDIR inside this git work tree                    -> 0 (the patch takes effect)
 *   RL23-patch-context        an M53 patch whose context does not match                        -> 2 (patch does not apply)
 *   RL24-unknown-only         --only with an id the manifest does not name                     -> 2 (rejected before any run)
 *
 *   node scripts/mutants/lifecycle-gate-regressions.mjs [case id ...]   (no ids: every case)
 *
 * A case with a fixture (RL20, RL21) runs the gate from a scratch copy of this tree with the manifest's hash-bound
 * fixture_patch applied, so the control and every mutant run see the fixture; the gate itself is this tree's.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const out = id => join(root, `out/lifecycle-gate-regressions/${id}`);
const summary = id => JSON.parse(readFileSync(join(out(id), "report.json"), "utf8")).summary;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const kindsCheck = id => {
  const s = summary(id);
  const want = {
    containment: ["M58"], lifecycle: ["M67"], availability: ["M65"], component: ["M71"],
    counts: { manifest_entries: 5, distinct_patches: 4, mechanisms: 4, variants: 1, witness_tests: 6, control_witness_tests: 1 },
    variants: { M58: ["M58-i"] }, beyond: ["M58", "M65", "M67"],
  };
  const got = {
    containment: s.containment_evidence, lifecycle: s.lifecycle_evidence, availability: s.availability_evidence, component: s.evidence.component_check_point,
    counts: s.counts, variants: s.variants, beyond: Object.keys(s.observed_beyond_kind ?? {}).sort(),
  };
  return same(got, want) ? "" : `report counts ${JSON.stringify(got)}`;
};
/** A scratch copy of this tree (regular files that git lists, node_modules linked) with the fixture patch applied. */
function fixtureRoot(id, manifestRel) {
  const manifest = JSON.parse(readFileSync(join(root, manifestRel), "utf8"));
  const patch = join(root, manifest.fixture_patch);
  if (sha256(readFileSync(patch)) !== manifest.fixture_patch_sha256) throw new Error(`${id}: fixture patch SHA-256 does not match the manifest`);
  const dir = mkdtempSync(join(tmpdir(), `gate-regression-${id}-`));
  const files = spawnSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" }).stdout.split("\0").filter(Boolean);
  for (const f of files) {
    if (f === "node_modules" || f.startsWith("node_modules/") || !existsSync(join(root, f)) || !lstatSync(join(root, f)).isFile()) continue;
    mkdirSync(dirname(join(dir, f)), { recursive: true }); cpSync(join(root, f), join(dir, f));
  }
  symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "dir");
  const git = argv => spawnSync("git", argv, { cwd: dir, encoding: "utf8", env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(dir) } });
  if (git(["init", "-q"]).status !== 0) throw new Error(`${id}: git init failed`);
  const apply = git(["apply", patch]);
  if (apply.status !== 0) throw new Error(`${id}: fixture patch does not apply: ${apply.stderr}`);
  if (git(["apply", "--check", "--reverse", patch]).status !== 0) throw new Error(`${id}: fixture patch did not take effect`);
  return dir;
}
const cases = [
  ["RL1-detected", 0, "detected"],
  ["RL2-inventory", 2, "test inventory differs from the control"],
  ["RL3-value", 2, "neither control"],
  ["RL4-error", 2, "unexpected caught errors"],
  ["RL5-other-failure", 2, "unexpected failure or changed observation outside the named witnesses"],
  ["RL6-crash", 2, "internal error"],
  ["RL7-timeout", 2, "jest: timed out", { extra: ["--jest-timeout-ms", "240000"] }],
  ["RL8-signal", 2, "jest: killed by signal SIGKILL"],
  ["RL9-unchanged", 1, "not_detected"],
  ["RL10-kinds", 0, "detected", { check: kindsCheck }],
  ["RL11-no-log", 2, "witness log missing"],
  ["RL12-no-witness", 2, "logged no observations"],
  ["RL13-collateral-syntax", 2, "collateral tests/approval-lifecycle.test.ts :: L5 binding comparisons"],
  ["RL14-collateral-assertion", 2, "assertion failure"],
  ["RL15-error-suffix", 2, "unexpected caught errors"],
  ["RL16-m58", 0, "detected"],
  ["RL17-m57", 0, "detected"],
  ["RL18-witness-aftereach", 2, "failed with more or other than its WitnessAssertionError"],
  ["RL19-unbound-beforeall", 2, "witness-log entry outside any test"],
  ["RL20-same-name-files", 0, "detected", { fixture: true }],
  ["RL21-ambiguous-name", 2, "ambiguous witness-log binding", { fixture: true }],
  ["RL22-tmpdir-worktree", 0, "detected", { tmpdirInWorktree: true }],
  ["RL23-patch-context", 2, "patch does not apply"],
  ["RL24-unknown-only", 2, "no mutant with this id in the manifest", { extra: ["--only", "RL24-no-such-id"] }],
];
// Optional case ids on the command line run only those cases (an unknown id is an error).
const selected = process.argv.slice(2);
const unknown = selected.filter(id => !cases.some(([c]) => c === id));
if (unknown.length) { console.error(`unknown regression case(s): ${unknown.join(", ")}`); process.exit(2); }
let failed = 0;
for (const [id, expected, reason, { extra = [], check, fixture, tmpdirInWorktree } = {}] of cases.filter(([c]) => !selected.length || selected.includes(c))) {
  const manifestRel = `mutants/lifecycle/regressions/${id}.json`;
  const gateRoot = fixture ? fixtureRoot(id, manifestRel) : root;
  const env = { ...process.env };
  if (tmpdirInWorktree) {
    // A TMPDIR inside this git work tree (out/ is git-ignored): the gate's copies are then inside a work tree too.
    env.TMPDIR = join(out(id), "tmp");
    mkdirSync(env.TMPDIR, { recursive: true });
    if (spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: env.TMPDIR, encoding: "utf8" }).stdout.trim() !== "true") throw new Error(`${id}: ${env.TMPDIR} is not inside a git work tree`);
  }
  const r = spawnSync(process.execPath, [join(gateRoot, "scripts/mutants/run-mutant-gate.mjs"), "--manifest", manifestRel, "--out", out(id), ...extra], { cwd: gateRoot, encoding: "utf8", maxBuffer: 1 << 28, env });
  if (fixture) rmSync(gateRoot, { recursive: true, force: true });
  const output = r.stdout + r.stderr;
  const line = output.split("\n").find(l => l.startsWith(id) || l.startsWith("M")) ?? (r.stderr.trim().split("\n").find(l => l.startsWith("mutant gate:")) ?? "");
  const reportIssue = r.status === expected && check ? check(id) : "";
  const ok = r.status === expected && !r.signal && output.includes(reason) && !reportIssue;
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${id}: gate exit ${r.status}${r.signal ? ` (signal ${r.signal})` : ""}, expected ${expected} with "${reason}"${reportIssue ? `; ${reportIssue}` : ""} | ${line.slice(0, 400)}`);
}
process.exit(failed ? 1 : 0);
