#!/usr/bin/env node
/**
 * Shared runtime-test mutant gate (docs/mutant-gate.md). One manifest per package: mutants/tenant/manifest.json
 * (tenant scope, package 1a), mutants/ancestor/manifest.json (ancestor chains, package 1b) and
 * mutants/lifecycle/manifest.json (approval-permit lifecycle, G3/G4).
 *
 *   node scripts/mutants/run-mutant-gate.mjs --manifest <manifest.json> [--out <dir>] [--only <id>]
 *
 * The manifest names, before any run, every mutant, its patch (hash-bound), its witness tests, and for every witness
 * label the exact value the unmodified runtime and the mutant must produce, plus the exact errors each witness may
 * catch in each run. Its SHA-256 is checked first.
 *
 * Control (unpatched copy): typecheck and build pass; jest exits 0 without signal or timeout; every test passes; every
 * witness logs exactly its control values and accepted control errors (tests/witness.ts writes WITNESS_LOG).
 *
 * Witness-log binding (every manifest): every witness-log entry names its test file and the test it was written in
 *   (tests/witness.ts binds an entry to a test only between its own beforeEach and afterEach hooks). An entry written
 *   outside any test (for example in a beforeAll), an entry whose file and test name match no test of the inventory,
 *   and a test inventory in which two tests of one file share a name (so an entry could not be bound to one test) are
 *   technical failures, in the control and in every mutant run.
 *
 * Mutant (fresh copy):
 *   technical soundness: the patch applies and takes effect (git apply runs isolated from any enclosing git work tree,
 *     every file the patch names changes, and the reverse patch applies to the result); typecheck and build pass; jest exits 0 or 1 without signal or timeout and
 *     writes its JSON result; no suite execution error; the test inventory (count and every test id) is identical to
 *     the control's.
 *   detection: jest exits 1; every witness fails with exactly one failure: the WitnessAssertionError its witness() call
 *     throws for the logged checks that failed (no other error of the test, for example an afterEach hook's, may
 *     accompany it); every witness logs exactly its manifest labels, each once, with the manifest control value as the
 *     test's own expectation; every label logs exactly its mutant
 *     value; the failed labels are exactly those whose mutant value differs from the control value; the caught errors
 *     are exactly the accepted mutant errors.
 *   A witness that logs exactly its control values must catch exactly its control errors; the mutant is then not
 *   detected (exit 1), never a technical failure.
 *   A witness value that is neither the control nor the mutant value, or an unaccepted caught error, is an
 *   unexpected failure: technical, never evidence.
 *   A witness with role "control" (for example the valid-chain control) names labels whose mutant value equals the
 *   control value: under the mutant it must still pass with exactly those values and errors. Otherwise the mutant
 *   breaks more than its named safeguard, which is a technical failure.
 *
 * Whole run (manifest "whole_run": "strict", used by the lifecycle manifest): every test that is not a named witness
 *   must pass and log exactly the witness-log entries (checks and caught errors) it logs in the control run, unless the
 *   mutant pins it in "collateral" with its exact status. A pinned collateral observation must occur exactly as pinned.
 *   Anything else is an unexpected failure (technical, exit 2): a witness's failure never redeems an otherwise
 *   unexpected run. A missing witness log (control or mutant) is a technical failure. A pinned collateral test must show
 *   exactly its pinned status, witness-log observations and (when failed) assertion failure (failure messages with only
 *   colour codes and stack-trace frame lines removed). Under the strict rule caught errors are compared exactly, never by
 *   prefix. Manifests without "whole_run" keep the earlier rule (other failures are diagnostics only).
 *
 * Evidence kinds: check_point, containment_effect, both, component_check_point, lifecycle_effect, check_and_lifecycle,
 * availability_effect and check_and_availability. Lifecycle state (approval and permit transitions) is reported as
 * lifecycle evidence and an availability effect (an allowed action denied or not executed) as availability evidence;
 * neither is ever counted as containment. Variants (variant_of) have their main entry's patch (an identical run) and are counted
 * separately from distinct patches and mechanisms.
 *
 * Any exception inside the gate itself (a crash) exits 2, never 1.
 *
 * Exit: 0 all detected; 1 some mutant not detected; 2 technical failure (manifest, unknown --only id, no mutant run,
 * control, patch, typecheck, build, process, inventory, witness-log binding, unexpected witness value, error or
 * failure).
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { constants as osConstants, tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

// A crash of the gate is a technical failure (exit 2), never a detection or a missed detection.
const crash = error => { console.error(`mutant gate: internal error: ${error?.stack ?? error}`); process.exit(2); };
process.on("uncaughtException", crash);
process.on("unhandledRejection", crash);
try {

const root = resolve(new URL("../..", import.meta.url).pathname);
const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
if (!opt("--manifest")) throw new Error("--manifest is required");
const manifestPath = resolve(root, opt("--manifest"));
const outDir = resolve(root, opt("--out", `out/mutants-${basename(dirname(manifestPath))}`));
if (args.includes("--only") && !opt("--only")) throw new Error("--only needs a mutant id");
const only = opt("--only", "");
const JEST_TIMEOUT_MS = Number(opt("--jest-timeout-ms", String(15 * 60_000)));

const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const fail = (code, message) => { console.error(`mutant gate: ${message}`); process.exit(code); };

// 1. Manifest and patches are fixed before the run.
const manifestBytes = readFileSync(manifestPath);
const expectedManifestSha = readFileSync(manifestPath.replace(/\.json$/, ".sha256"), "utf8").trim();
if (sha256(manifestBytes) !== expectedManifestSha) fail(2, `manifest SHA-256 ${sha256(manifestBytes)} does not match ${expectedManifestSha}`);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const KINDS = {
  check_point: ["check"], containment_effect: ["effect"], both: ["check", "effect"], component_check_point: ["check"],
  lifecycle_effect: ["lifecycle"], check_and_lifecycle: ["check", "lifecycle"],
  availability_effect: ["availability"], check_and_availability: ["check", "availability"],
};
const PARTS = ["check", "effect", "lifecycle", "availability"];
if (!Array.isArray(manifest.mutants) || manifest.mutants.length === 0) fail(2, "manifest names no mutants");
if (!Array.isArray(manifest.recorded_gaps)) fail(2, "manifest has no recorded_gaps list");
if (manifest.whole_run !== undefined && manifest.whole_run !== "strict") fail(2, `unknown whole_run mode ${manifest.whole_run}`);
const strict = manifest.whole_run === "strict";
if (manifest.gate_limitations !== undefined && !Array.isArray(manifest.gate_limitations)) fail(2, "gate_limitations must be a list");
const isControl = w => w.role === "control";
/** The parts whose labels change from control to mutant in the entry's (non-control) witnesses, in PARTS order. */
const changedParts = m => PARTS.filter(p => m.witnesses.some(w => !isControl(w) && w.labels.some(l => l.part === p && !isDeepStrictEqual(l.control, l.mutant))));
const ids = manifest.mutants.map(m => m.id);
if (new Set(ids).size !== ids.length) fail(2, "manifest mutant ids are not unique");
// An unknown --only id is rejected before any run: a run of no mutant is never a success.
if (only && !ids.includes(only)) fail(2, `--only ${only}: no mutant with this id in the manifest`);
for (const m of manifest.mutants) {
  if (m.variant_of !== undefined) {
    const main = manifest.mutants.find(x => x.id === m.variant_of);
    if (!main || main.variant_of !== undefined || main.patch_sha256 !== m.patch_sha256) fail(2, `${m.id}: variant_of must name a main entry with the same patch`);
  }
  if (!KINDS[m.kind]) fail(2, `${m.id}: unknown evidence kind ${m.kind}`);
  if (sha256(readFileSync(join(root, m.patch))) !== m.patch_sha256) fail(2, `${m.id}: patch SHA-256 does not match the manifest`);
  if (!m.witnesses.some(w => !isControl(w))) fail(2, `${m.id}: no witness`);
  if (strict && (!Array.isArray(m.collateral) || m.collateral.some(c => typeof c.test !== "string" || !["passed", "failed"].includes(c.status)
    || !Array.isArray(c.observations) || (c.status === "failed" ? typeof c.assertion !== "string" || c.assertion.length === 0 : c.assertion !== undefined)))) {
    fail(2, `${m.id}: a strict manifest must pin each collateral test's status, witness-log observations and (when it fails) assertion failure`);
  }
  for (const w of m.witnesses) {
    if (w.role !== undefined && !isControl(w)) fail(2, `${m.id}: unknown witness role ${w.role}`);
    if (!Array.isArray(w.labels) || w.labels.length === 0) fail(2, `${m.id}: witness ${w.test} names no labels`);
    if (w.labels.some(l => !PARTS.includes(l.part))) fail(2, `${m.id}: witness ${w.test} has a label with an unknown part`);
    if (isControl(w)) {
      if (w.labels.some(l => !isDeepStrictEqual(l.control, l.mutant))) fail(2, `${m.id}: control witness ${w.test} must keep every value`);
      continue;
    }
    for (const part of KINDS[m.kind]) {
      if (!w.labels.some(l => l.part === part && !isDeepStrictEqual(l.control, l.mutant))) fail(2, `${m.id}: kind ${m.kind} needs a changing ${part} label in ${w.test}`);
    }
  }
  if (m.observed_beyond_kind !== undefined && !changedParts(m).some(p => !KINDS[m.kind].includes(p))) fail(2, `${m.id}: observed_beyond_kind is noted but no label outside the kind changes`);
}

// 2. Copies, commands and observations.
const files = spawnSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" }).stdout.split("\0").filter(Boolean);
const work = mkdtempSync(join(tmpdir(), "mutant-gate-"));
function copyTree(name) {
  const dir = join(work, name);
  for (const f of files) {
    // Only regular files are copied; node_modules (or a symlink to it) is linked once below.
    if (f === "node_modules" || f.startsWith("node_modules/") || !existsSync(join(root, f)) || !lstatSync(join(root, f)).isFile()) continue;
    mkdirSync(dirname(join(dir, f)), { recursive: true }); cpSync(join(root, f), join(dir, f));
  }
  symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "dir");
  return dir;
}
const run = (cmd, argv, cwd, env = {}, timeout = 10 * 60_000) =>
  spawnSync(cmd, argv, { cwd, encoding: "utf8", maxBuffer: 1 << 28, timeout, env: { ...process.env, ...env } });
const procIssue = (name, p, okStatuses) => {
  if (p.error) return `${name}: ${p.error.code === "ETIMEDOUT" ? "timed out" : p.error.message}`;
  if (p.signal) return `${name}: killed by signal ${p.signal}`;
  if (typeof p.status === "number" && p.status > 128 && osConstants.signals) {
    const signal = Object.keys(osConstants.signals).find(k => osConstants.signals[k] === p.status - 128);
    if (signal) return `${name}: killed by signal ${signal} (exit status ${p.status})`;
  }
  if (!okStatuses.includes(p.status)) return `${name}: exit status ${p.status} (${(p.stdout + p.stderr).split("\n").filter(Boolean).slice(0, 3).join(" | ")})`;
  return undefined;
};
/** Typecheck, build and the full jest run of one tree. Returns { issue } for a technical failure, else the observations. */
function evaluateTree(dir, jestOkStatuses) {
  const typecheck = run("npm", ["run", "--silent", "typecheck"], dir);
  const typecheckIssue = procIssue("typecheck", typecheck, [0]);
  if (typecheckIssue) return { issue: typecheckIssue };
  const build = run("npm", ["run", "--silent", "build"], dir);
  const buildIssue = procIssue("build", build, [0]) ?? (existsSync(join(dir, "dist/src/guarded-executor.js")) ? undefined : "build: dist/src/guarded-executor.js missing");
  if (buildIssue) return { issue: buildIssue };
  const json = join(dir, "jest-result.json");
  const witnessLog = join(dir, "witness-log.jsonl");
  // jest runs as the direct child (no npx or shell in between), so a timeout or a signal reaches the jest process itself
  // and is reported as such.
  const jest = run(process.execPath, [join(dir, "node_modules/jest/bin/jest.js"), "--ci", "--json", "--outputFile", json], dir, { WITNESS_LOG: witnessLog }, JEST_TIMEOUT_MS);
  const jestIssue = procIssue("jest", jest, jestOkStatuses);
  if (jestIssue) return { issue: jestIssue };
  let result;
  try { result = JSON.parse(readFileSync(json, "utf8")); } catch { return { issue: "jest wrote no JSON result" }; }
  if (result.numRuntimeErrorTestSuites !== 0) return { issue: `${result.numRuntimeErrorTestSuites} suite execution errors` };
  const realDir = realpathSync(dir);
  const tests = result.testResults.flatMap(s => s.assertionResults.map(a => ({ file: relative(realDir, s.name), ...a })));
  for (const t of tests) { t.id = `${t.file} :: ${t.ancestorTitles.join(" > ")} :: ${t.title}`; t.bind = `${t.file}\u0000${[...t.ancestorTitles, t.title].join(" ")}`; }
  const inventory = tests.map(t => t.id).sort();
  // Under the strict whole-run rule a missing witness log is a technical failure in its own right: without it no
  // witness or whole-run observation can be compared.
  if (strict && !existsSync(witnessLog)) return { issue: "witness log missing: jest wrote no WITNESS_LOG observations" };
  const log = existsSync(witnessLog) ? readFileSync(witnessLog, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
  // Every witness-log entry is bound to exactly one test of the inventory, by test file and test name; anything that
  // cannot be bound is a technical failure, never an ignored observation.
  const byBind = new Map();
  for (const t of tests) byBind.set(t.bind, [...(byBind.get(t.bind) ?? []), t]);
  const ambiguous = [...byBind.values()].filter(ts => ts.length > 1).map(ts => ts[0].id);
  if (ambiguous.length) return { issue: `ambiguous witness-log binding: ${ambiguous.length} test name(s) occur more than once in one file: ${JSON.stringify(ambiguous.slice(0, 3))}` };
  for (const e of log) {
    if (typeof e.test !== "string" || e.test === "") return { issue: `witness-log entry outside any test: ${JSON.stringify(e).slice(0, 240)}` };
    const t = byBind.get(`${e.file}\u0000${e.test}`);
    if (!t) return { issue: `witness-log entry with an unknown test id: ${JSON.stringify(e).slice(0, 240)}` };
    e.testId = t[0].id;
  }
  return { status: jest.status, result, tests, inventory, log };
}
const findTest = (obs, w) => obs.tests.find(t => t.file === w.file && t.title === w.test && t.ancestorTitles.join(" ") === w.describe);
const witnessEntries = (obs, w) => { const t = findTest(obs, w); return t ? obs.log.filter(e => e.testId === t.id) : []; };
/**
 * The one failure a witness test may show: the WitnessAssertionError its witness() call throws, listing exactly the
 * logged checks whose value differs from the test's own expectation (tests/witness.ts). Undefined when no logged check
 * failed. Any other or additional failure of the test (another error, an afterEach hook's error) differs from it.
 */
const expectedWitnessFailure = entries => {
  const failed = entries.filter(e => e.kind === "check" && !isDeepStrictEqual(e.actual, e.expected));
  return failed.length ? `WitnessAssertionError: ${failed.map(e => `WITNESS[${e.label}] expected ${JSON.stringify(e.expected)} received ${JSON.stringify(e.actual)}`).join("; ")}` : undefined;
};
/**
 * Problems of a named witness's own observations, in any run: a check label the manifest does not name, a named label
 * logged other than once, a test expectation other than the manifest control value, and a failure other than exactly
 * its expected WitnessAssertionError (or a pass despite a failed logged check).
 */
function witnessShapeIssue(w, t, entries) {
  const checks = entries.filter(e => e.kind === "check");
  const extra = checks.find(e => !w.labels.some(l => l.label === e.label));
  if (extra) return `${w.test}: logged label ${extra.label}, which the manifest does not name`;
  for (const l of w.labels) {
    const seen = checks.filter(e => e.label === l.label);
    if (seen.length !== 1) return `${w.test}: label ${l.label} logged ${seen.length} times`;
    if (!isDeepStrictEqual(seen[0].expected, l.control)) return `${w.test}: label ${l.label} expects ${JSON.stringify(seen[0].expected)} in the test, manifest control value ${JSON.stringify(l.control)}`;
  }
  const expected = expectedWitnessFailure(entries);
  if (!t) return `${w.test}: missing from the test results`;
  if (t.status === "passed") return expected ? `${w.test} passed although a logged check failed (${expected.slice(0, 200)})` : undefined;
  if (t.status !== "failed") return `${w.test}: status ${t.status}`;
  const messages = t.failureMessages ?? [];
  if (messages.length !== 1 || assertionOf(t) !== expected) {
    return `${w.test} failed with more or other than its WitnessAssertionError: ${messages.length} failure message(s): ${JSON.stringify(assertionOf(t).slice(0, 300))}`;
  }
  return undefined;
}
/**
 * Caught errors against the manifest's accepted errors, in order. Under the strict whole-run rule every error must
 * equal its accepted text exactly ("Name: message"); no free message prefix is accepted. Manifests without the strict
 * rule keep the earlier prefix comparison (gate debt, docs/mutant-gate.md).
 */
const errorText = e => `${e.name}: ${e.message}`;
const errorsMatch = (observed, accepted) =>
  observed.length === accepted.length && observed.every((e, i) => strict ? errorText(e) === accepted[i] : errorText(e).startsWith(accepted[i]));
const describeErrors = errs => errs.map(e => `${e.name}: ${e.message}`.slice(0, 160));
const stripAnsi = text => text.replace(/\u001b\[[0-9;]*m/g, "");
/**
 * A V8 stack-trace frame line: "    at fn (file:line:col)", "    at file:line:col", "    at fn (<anonymous>)" or
 * "    at async Promise.all (index 0)". Only
 * such lines are frames; a message line that merely starts with "at" (for example "  at least ...") is kept.
 */
const STACK_FRAME = /^\s+at (?:.+ \((?:.+:\d+:\d+|<anonymous>|native|index \d+)\)|[^\s()]+:\d+:\d+|<anonymous>)$/;
/**
 * The assertion failure of a failed test, normalised for comparison: jest's failure messages with only two things
 * removed, colour codes and stack-trace frame lines (frames name the gate's temporary work directory). The error class,
 * the message and the whole assertion content stay in the comparison; trailing blank space is trimmed.
 */
const assertionOf = t => stripAnsi((t.failureMessages ?? []).join("\n")).split("\n").filter(l => !STACK_FRAME.test(l)).join("\n").trimEnd();
/** Witness-log entries of one test without their binding: { kind, label, actual, expected } or { kind, name, message }. */
const observationsOf = (log, id) => (log.get(id) ?? []).map(({ test: _test, file: _file, testId: _testId, ...rest }) => rest);
const logByTest = obs => { const by = new Map(); for (const e of obs.log) { if (!by.has(e.testId)) by.set(e.testId, []); by.get(e.testId).push(e); } return by; };
/**
 * Strict whole-run check: the tests (other than the named witnesses) whose status or witness-log observations differ
 * from the control must be exactly the mutant's pinned collateral. Each pinned collateral test must show exactly its
 * pinned status, its pinned witness-log observations (check values and caught errors, compared exactly) and, when it
 * fails, its pinned assertion failure. A collateral test that fails differently (another assertion, a SyntaxError, a
 * crash) is unexpected. Returns a problem, if any.
 */
function wholeRunIssue(m, obs) {
  const named = t => m.witnesses.some(w => t.file === w.file && t.title === w.test && t.ancestorTitles.join(" ") === w.describe);
  const controlLog = logByTest(control), mutantLog = logByTest(obs);
  const controlStatus = new Map(control.tests.map(t => [t.id, t.status]));
  const affected = obs.tests
    .filter(t => !named(t))
    .filter(t => t.status !== controlStatus.get(t.id) || !isDeepStrictEqual(observationsOf(mutantLog, t.id), observationsOf(controlLog, t.id)))
    .map(t => ({ test: t.id, status: t.status, observations: observationsOf(mutantLog, t.id), ...(t.status === "failed" ? { assertion: assertionOf(t) } : {}) }));
  const pinned = new Map(m.collateral.map(c => [c.test, c]));
  const seen = new Set(affected.map(c => c.test));
  for (const c of affected) {
    const p = pinned.get(c.test);
    if (!p) return { detail: `unexpected failure or changed observation outside the named witnesses: ${JSON.stringify({ test: c.test, status: c.status, assertion: c.assertion?.slice(0, 200) })}`, affected };
    if (p.status !== c.status) return { detail: `collateral ${c.test}: status ${c.status}, pinned ${p.status}`, affected };
    if (!isDeepStrictEqual(c.observations, p.observations)) return { detail: `collateral ${c.test}: witness-log observations ${JSON.stringify(c.observations).slice(0, 300)} differ from the pinned ${JSON.stringify(p.observations).slice(0, 300)}`, affected };
    if (c.status === "failed" && c.assertion !== p.assertion) return { detail: `collateral ${c.test}: assertion failure ${JSON.stringify(c.assertion.slice(0, 300))} differs from the pinned ${JSON.stringify((p.assertion ?? "").slice(0, 300))}`, affected };
  }
  const missing = m.collateral.filter(c => !seen.has(c.test));
  if (missing.length) return { detail: `pinned collateral did not occur as pinned: ${JSON.stringify(missing.map(c => ({ test: c.test, status: c.status })).slice(0, 3))}`, affected };
  return { affected };
}

/**
 * Applies a mutant patch to its copy and proves that it took effect. git apply runs as if outside any repository
 * (GIT_CEILING_DIRECTORIES stops repository discovery above the copy; GIT_DIR and GIT_WORK_TREE are cleared), so a work
 * directory inside a git work tree (for example a TMPDIR there) cannot make it skip paths and still exit 0. Every file
 * the patch names must then differ from its state before the patch, and the reverse patch must apply to the result.
 * Returns a problem, if any: a patch that does not apply or does not take effect is a technical failure.
 */
function applyPatch(dir, patchPath) {
  const env = { ...process.env, GIT_CEILING_DIRECTORIES: dirname(dir) };
  delete env.GIT_DIR; delete env.GIT_WORK_TREE;
  const git = argv => spawnSync("git", argv, { cwd: dir, encoding: "utf8", env });
  const numstat = git(["apply", "--numstat", patchPath]);
  if (numstat.status !== 0) return `patch does not apply: ${numstat.stderr.trim()}`;
  const touched = numstat.stdout.split("\n").filter(Boolean).map(l => l.split("\t").slice(2).join("\t"));
  if (touched.length === 0) return "patch does not apply: it names no file";
  const digest = f => (existsSync(join(dir, f)) && lstatSync(join(dir, f)).isFile() ? sha256(readFileSync(join(dir, f))) : null);
  const before = new Map(touched.map(f => [f, digest(f)]));
  const apply = git(["apply", patchPath]);
  if (apply.status !== 0) return `patch does not apply: ${apply.stderr.trim()}`;
  const unchanged = touched.filter(f => digest(f) === before.get(f));
  if (unchanged.length) return `patch did not take effect: ${JSON.stringify(unchanged)} unchanged after git apply`;
  const reverse = git(["apply", "--check", "--reverse", patchPath]);
  if (reverse.status !== 0) return `patch did not take effect: the reverse patch does not apply (${reverse.stderr.trim()})`;
  return undefined;
}

// 3. Control.
const report = { manifest: manifestPath.slice(root.length + 1), manifest_sha256: expectedManifestSha, control: null, mutants: [] };
const control = evaluateTree(copyTree("control"), [0]);
if (control.issue) fail(2, `control is not technically sound: ${control.issue}`);
const c = control.result;
report.control = { suites: c.numTotalTestSuites, tests: c.numTotalTests, failed: c.numFailedTests, inventory_sha256: sha256(control.inventory.join("\n")) };
if (!c.success || c.numFailedTests !== 0) fail(2, `control does not pass: ${JSON.stringify(report.control)}`);
for (const m of manifest.mutants) for (const w of m.witnesses) {
  const t = findTest(control, w);
  if (!t || t.status !== "passed") fail(2, `control: witness ${w.test} of ${m.id} is ${t ? t.status : "missing"}`);
  const entries = witnessEntries(control, w);
  if (entries.length === 0) fail(2, `control: named witness ${w.test} of ${m.id} logged no observations`);
  const shape = witnessShapeIssue(w, t, entries);
  if (shape) fail(2, `control: ${m.id}: ${shape}`);
  for (const l of w.labels) {
    const seen = entries.filter(e => e.kind === "check" && e.label === l.label);
    if (seen.length !== 1 || !isDeepStrictEqual(seen[0].actual, l.control)) fail(2, `control: ${m.id} label ${l.label} logged ${JSON.stringify(seen.map(e => e.actual))}, manifest control value ${JSON.stringify(l.control)}`);
  }
  const errs = entries.filter(e => e.kind === "error");
  if (!errorsMatch(errs, w.errors.control)) fail(2, `control: ${m.id} witness caught ${JSON.stringify(describeErrors(errs))}, accepted ${JSON.stringify(w.errors.control)}`);
}

// 4. Mutants.
let undetected = 0, technical = 0;
for (const m of manifest.mutants) {
  if (only && m.id !== only) continue;
  const entry = {
    id: m.id, kind: m.kind, ...(m.variant_of ? { variant_of: m.variant_of } : {}), removes: m.removes, changed_parts: changedParts(m),
    beyond_kind_parts: changedParts(m).filter(p => !KINDS[m.kind].includes(p)),
    ...(m.claim_limits ? { claim_limits: m.claim_limits } : {}), ...(m.observed_beyond_kind ? { observed_beyond_kind: m.observed_beyond_kind } : {}),
    status: "", witnesses: [], other_failures: [],
  };
  const dir = copyTree(m.id);
  const patchIssue = applyPatch(dir, join(root, m.patch));
  const obs = patchIssue ? { issue: patchIssue } : evaluateTree(dir, [0, 1]);
  const technicalFailure = detail => { entry.status = "technical_failure"; entry.detail = detail; };
  if (obs.issue) technicalFailure(obs.issue);
  else if (!isDeepStrictEqual(obs.inventory, control.inventory)) {
    const missing = control.inventory.filter(x => !obs.inventory.includes(x)), added = obs.inventory.filter(x => !control.inventory.includes(x));
    technicalFailure(`test inventory differs from the control: ${obs.inventory.length} tests (control ${control.inventory.length}); missing ${JSON.stringify(missing.slice(0, 3))}; added ${JSON.stringify(added.slice(0, 3))}`);
  } else {
    entry.tests = obs.result.numTotalTests;
    const named = new Set(m.witnesses.map(w => findTest(obs, w)?.id));
    const controls = m.witnesses.filter(isControl);
    entry.other_failures = obs.tests.filter(t => t.status === "failed" && !named.has(t.id)).map(t => t.title);
    let detected = obs.status === 1;
    for (const w of controls) {
      const t = findTest(obs, w);
      const entries = witnessEntries(obs, w);
      if (entries.length === 0) { technicalFailure(`named witness ${w.test} logged no observations`); break; }
      const errs = entries.filter(e => e.kind === "error");
      const values = Object.fromEntries(w.labels.map(l => [l.label, entries.filter(e => e.kind === "check" && e.label === l.label).map(e => e.actual)]));
      entry.witnesses.push({ test: w.test, role: "control", status: t?.status ?? "missing", values, caught_errors: describeErrors(errs) });
      const shape = witnessShapeIssue(w, t, entries);
      if (shape) { technicalFailure(`control witness: ${shape}`); break; }
      const changed = w.labels.find(l => values[l.label].length !== 1 || !isDeepStrictEqual(values[l.label][0], l.control));
      if (t?.status !== "passed" || changed || !errorsMatch(errs, w.errors.mutant)) {
        technicalFailure(`control witness ${w.test} does not hold under the mutant (${t?.status ?? "missing"}${changed ? `, label ${changed.label} logged ${JSON.stringify(values[changed.label])}` : ""}): the mutant breaks more than its named safeguard`);
        break;
      }
    }
    for (const w of entry.status ? [] : m.witnesses.filter(w => !isControl(w))) {
      const t = findTest(obs, w);
      const firstLine = ((t?.failureMessages ?? []).join("\n").trimStart().split("\n")[0] ?? "");
      const entries = witnessEntries(obs, w);
      if (entries.length === 0) { technicalFailure(`named witness ${w.test} logged no observations`); break; }
      const errs = entries.filter(e => e.kind === "error");
      const values = Object.fromEntries(w.labels.map(l => [l.label, entries.filter(e => e.kind === "check" && e.label === l.label).map(e => e.actual)]));
      // The witness's only failure must be the WitnessAssertionError for its failed checks; a second error of the same
      // test (for example an afterEach hook's) is never hidden behind it.
      const shape = witnessShapeIssue(w, t, entries);
      if (shape) { entry.witnesses.push({ test: w.test, status: t?.status ?? "missing", first_line: firstLine.slice(0, 300), values, caught_errors: describeErrors(errs) }); technicalFailure(shape); break; }
      const failedLabels = entries.filter(e => e.kind === "check" && !isDeepStrictEqual(e.actual, e.expected)).map(e => e.label).sort();
      const expectedFailed = w.labels.filter(l => !isDeepStrictEqual(l.control, l.mutant)).map(l => l.label).sort();
      const witnessReport = { test: w.test, status: t?.status ?? "missing", first_line: firstLine.slice(0, 300), values, caught_errors: describeErrors(errs), failed_labels: failedLabels };
      entry.witnesses.push(witnessReport);
      // Unexpected observations are technical failures, never evidence.
      const unexpectedValue = w.labels.find(l => values[l.label].length !== 1 || !(isDeepStrictEqual(values[l.label][0], l.mutant) || isDeepStrictEqual(values[l.label][0], l.control)));
      if (unexpectedValue) { technicalFailure(`${w.test}: label ${unexpectedValue.label} logged ${JSON.stringify(values[unexpectedValue.label])}, neither control ${JSON.stringify(unexpectedValue.control)} nor mutant ${JSON.stringify(unexpectedValue.mutant)}`); break; }
      // A witness that logs exactly its control values (the mutant changed nothing it observes) must catch exactly its
      // control errors and is then simply not detected; otherwise it must catch exactly the accepted mutant errors.
      const allControlValues = w.labels.every(l => isDeepStrictEqual(values[l.label][0], l.control));
      const acceptedErrors = allControlValues ? w.errors.control : w.errors.mutant;
      if (!errorsMatch(errs, acceptedErrors)) { technicalFailure(`${w.test}: unexpected caught errors ${JSON.stringify(witnessReport.caught_errors)}, accepted ${JSON.stringify(acceptedErrors)}`); break; }
      const allMutantValues = w.labels.every(l => isDeepStrictEqual(values[l.label][0], l.mutant));
      if (!(t?.status === "failed" && allMutantValues && isDeepStrictEqual(failedLabels, expectedFailed))) detected = false;
    }
    if (!entry.status && strict) {
      const whole = wholeRunIssue(m, obs);
      entry.collateral = whole.affected;
      if (whole.detail) technicalFailure(whole.detail);
    }
    if (!entry.status) entry.status = detected ? "detected" : "not_detected";
  }
  if (entry.status === "technical_failure") technical++;
  if (entry.status === "not_detected") undetected++;
  report.mutants.push(entry);
  console.log(`${m.id.padEnd(13)} ${m.kind.padEnd(22)} ${entry.status}${entry.detail ? ` (${entry.detail})` : ""}`);
}

// A run of no mutant is never a success.
if (report.mutants.length === 0) fail(2, "no mutant was run");
const byKind = kind => report.mutants.filter(e => e.kind === kind && e.status === "detected").map(e => e.id);
const ran = manifest.mutants.filter(m => report.mutants.some(e => e.id === m.id));
const witnessIds = role => new Set(ran.flatMap(m => m.witnesses.filter(w => isControl(w) === role).map(w => `${w.file} :: ${w.describe} :: ${w.test}`)));
report.summary = {
  detected: report.mutants.filter(e => e.status === "detected").length,
  not_detected: undetected,
  technical_failures: technical,
  // Entries, patches and witnesses are counted separately: a variant has its main entry's patch (an identical jest run) and is
  // not an independent failure mechanism.
  counts: {
    manifest_entries: ran.length,
    distinct_patches: new Set(ran.map(m => m.patch_sha256)).size,
    mechanisms: ran.filter(m => !m.variant_of).length,
    variants: ran.filter(m => m.variant_of).length,
    witness_tests: witnessIds(false).size,
    control_witness_tests: witnessIds(true).size,
  },
  variants: Object.fromEntries([...new Set(ran.filter(m => m.variant_of).map(m => m.variant_of))].map(v => [v, ran.filter(m => m.variant_of === v).map(m => m.id)])),
  evidence: Object.fromEntries(Object.keys(KINDS).map(k => [k, byKind(k)])),
  // Containment evidence is a tool call, managed state, returned content or the cancellation signal only. Lifecycle
  // state, availability effects (an allowed action denied) and component check points are never counted here.
  containment_evidence: [...byKind("both"), ...byKind("containment_effect")],
  lifecycle_evidence: [...byKind("lifecycle_effect"), ...byKind("check_and_lifecycle")],
  availability_evidence: [...byKind("availability_effect"), ...byKind("check_and_availability")],
  check_point_evidence_production_path: [...byKind("both"), ...byKind("check_point"), ...byKind("check_and_lifecycle"), ...byKind("check_and_availability")],
  // Labels of a part outside the claimed kind that also change are recorded here (with the manifest's note, if any) and
  // are never counted in the evidence lists above.
  observed_beyond_kind: Object.fromEntries(ran.filter(m => changedParts(m).some(p => !KINDS[m.kind].includes(p))).map(m => [m.id, {
    parts: changedParts(m).filter(p => !KINDS[m.kind].includes(p)), ...(m.observed_beyond_kind ? { note: m.observed_beyond_kind } : {}),
  }])),
  recorded_gaps: manifest.recorded_gaps,
  ...(manifest.gate_limitations ? { gate_limitations: manifest.gate_limitations } : {}),
};
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report.summary));
rmSync(work, { recursive: true, force: true });
process.exit(technical ? 2 : undetected ? 1 : 0);
} catch (error) {
  crash(error);
}
