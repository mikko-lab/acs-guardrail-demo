#!/usr/bin/env node
/**
 * Shared runtime-test mutant gate (docs/mutant-gate.md). One manifest per package: mutants/tenant/manifest.json
 * (tenant scope, package 1a) and mutants/ancestor/manifest.json (ancestor chains, package 1b).
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
 * Mutant (fresh copy):
 *   technical soundness: the patch applies; typecheck and build pass; jest exits 0 or 1 without signal or timeout and
 *     writes its JSON result; no suite execution error; the test inventory (count and every test id) is identical to
 *     the control's.
 *   detection: jest exits 1; every witness fails with WitnessAssertionError; every label logs exactly its mutant
 *     value; the failed labels are exactly those whose mutant value differs from the control value; the caught errors
 *     are exactly the accepted mutant errors.
 *   A witness value that is neither the control nor the mutant value, or an unaccepted caught error, is an
 *   unexpected failure: technical, never evidence.
 *   A witness with role "control" (for example the valid-chain control) names labels whose mutant value equals the
 *   control value: under the mutant it must still pass with exactly those values and errors. Otherwise the mutant
 *   breaks more than its named safeguard, which is a technical failure.
 *
 * Any exception inside the gate itself (a crash) exits 2, never 1.
 *
 * Exit: 0 all detected; 1 some mutant not detected; 2 technical failure (manifest, control, patch, typecheck, build,
 * process, inventory, unexpected witness value or error).
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
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
const only = opt("--only", "");
const JEST_TIMEOUT_MS = Number(opt("--jest-timeout-ms", String(15 * 60_000)));

const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const fail = (code, message) => { console.error(`mutant gate: ${message}`); process.exit(code); };

// 1. Manifest and patches are fixed before the run.
const manifestBytes = readFileSync(manifestPath);
const expectedManifestSha = readFileSync(manifestPath.replace(/\.json$/, ".sha256"), "utf8").trim();
if (sha256(manifestBytes) !== expectedManifestSha) fail(2, `manifest SHA-256 ${sha256(manifestBytes)} does not match ${expectedManifestSha}`);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const KINDS = { check_point: ["check"], containment_effect: ["effect"], both: ["check", "effect"], component_check_point: ["check"] };
if (!Array.isArray(manifest.mutants) || manifest.mutants.length === 0) fail(2, "manifest names no mutants");
if (!Array.isArray(manifest.recorded_gaps)) fail(2, "manifest has no recorded_gaps list");
const isControl = w => w.role === "control";
for (const m of manifest.mutants) {
  if (!KINDS[m.kind]) fail(2, `${m.id}: unknown evidence kind ${m.kind}`);
  if (sha256(readFileSync(join(root, m.patch))) !== m.patch_sha256) fail(2, `${m.id}: patch SHA-256 does not match the manifest`);
  if (!m.witnesses.some(w => !isControl(w))) fail(2, `${m.id}: no witness`);
  for (const w of m.witnesses) {
    if (w.role !== undefined && !isControl(w)) fail(2, `${m.id}: unknown witness role ${w.role}`);
    if (!Array.isArray(w.labels) || w.labels.length === 0) fail(2, `${m.id}: witness ${w.test} names no labels`);
    if (isControl(w)) {
      if (w.labels.some(l => !isDeepStrictEqual(l.control, l.mutant))) fail(2, `${m.id}: control witness ${w.test} must keep every value`);
      continue;
    }
    for (const part of KINDS[m.kind]) {
      if (!w.labels.some(l => l.part === part && !isDeepStrictEqual(l.control, l.mutant))) fail(2, `${m.id}: kind ${m.kind} needs a changing ${part} label in ${w.test}`);
    }
  }
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
  const jest = run("npx", ["jest", "--ci", "--json", "--outputFile", json], dir, { WITNESS_LOG: witnessLog }, JEST_TIMEOUT_MS);
  const jestIssue = procIssue("jest", jest, jestOkStatuses);
  if (jestIssue) return { issue: jestIssue };
  let result;
  try { result = JSON.parse(readFileSync(json, "utf8")); } catch { return { issue: "jest wrote no JSON result" }; }
  if (result.numRuntimeErrorTestSuites !== 0) return { issue: `${result.numRuntimeErrorTestSuites} suite execution errors` };
  const tests = result.testResults.flatMap(s => s.assertionResults.map(a => ({ file: s.name.slice(s.name.indexOf("/tests/") + 1), ...a })));
  const inventory = tests.map(t => `${t.file} :: ${t.ancestorTitles.join(" > ")} :: ${t.title}`).sort();
  const log = existsSync(witnessLog) ? readFileSync(witnessLog, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : [];
  return { status: jest.status, result, tests, inventory, log };
}
const findTest = (obs, w) => obs.tests.find(t => t.file === w.file && t.title === w.test && t.ancestorTitles.join(" ") === w.describe);
const witnessEntries = (obs, w) => obs.log.filter(e => e.test === `${w.describe} ${w.test}`);
const errorsMatch = (observed, accepted) =>
  observed.length === accepted.length && observed.every((e, i) => `${e.name}: ${e.message}`.startsWith(accepted[i]));
const describeErrors = errs => errs.map(e => `${e.name}: ${e.message}`.slice(0, 160));

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
  const entry = { id: m.id, kind: m.kind, removes: m.removes, status: "", witnesses: [], other_failures: [] };
  const dir = copyTree(m.id);
  const apply = run("git", ["apply", join(root, m.patch)], dir);
  const obs = apply.status !== 0 ? { issue: `patch does not apply: ${apply.stderr.trim()}` } : evaluateTree(dir, [0, 1]);
  const technicalFailure = detail => { entry.status = "technical_failure"; entry.detail = detail; };
  if (obs.issue) technicalFailure(obs.issue);
  else if (!isDeepStrictEqual(obs.inventory, control.inventory)) {
    const missing = control.inventory.filter(x => !obs.inventory.includes(x)), added = obs.inventory.filter(x => !control.inventory.includes(x));
    technicalFailure(`test inventory differs from the control: ${obs.inventory.length} tests (control ${control.inventory.length}); missing ${JSON.stringify(missing.slice(0, 3))}; added ${JSON.stringify(added.slice(0, 3))}`);
  } else {
    entry.tests = obs.result.numTotalTests;
    const named = new Set(m.witnesses.map(w => w.test));
    const controls = m.witnesses.filter(isControl);
    entry.other_failures = obs.tests.filter(t => t.status === "failed" && !named.has(t.title)).map(t => t.title);
    let detected = obs.status === 1;
    for (const w of controls) {
      const t = findTest(obs, w);
      const entries = witnessEntries(obs, w);
      const errs = entries.filter(e => e.kind === "error");
      const values = Object.fromEntries(w.labels.map(l => [l.label, entries.filter(e => e.kind === "check" && e.label === l.label).map(e => e.actual)]));
      entry.witnesses.push({ test: w.test, role: "control", status: t?.status ?? "missing", values, caught_errors: describeErrors(errs) });
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
      const errs = entries.filter(e => e.kind === "error");
      const values = Object.fromEntries(w.labels.map(l => [l.label, entries.filter(e => e.kind === "check" && e.label === l.label).map(e => e.actual)]));
      const failedLabels = [...firstLine.matchAll(/WITNESS\[([^\]]+)\]/g)].map(x => x[1]).sort();
      const expectedFailed = w.labels.filter(l => !isDeepStrictEqual(l.control, l.mutant)).map(l => l.label).sort();
      const witnessReport = { test: w.test, status: t?.status ?? "missing", first_line: firstLine.slice(0, 300), values, caught_errors: describeErrors(errs), failed_labels: failedLabels };
      entry.witnesses.push(witnessReport);
      // Unexpected observations are technical failures, never evidence.
      const unexpectedValue = w.labels.find(l => values[l.label].length !== 1 || !(isDeepStrictEqual(values[l.label][0], l.mutant) || isDeepStrictEqual(values[l.label][0], l.control)));
      if (unexpectedValue) { technicalFailure(`${w.test}: label ${unexpectedValue.label} logged ${JSON.stringify(values[unexpectedValue.label])}, neither control ${JSON.stringify(unexpectedValue.control)} nor mutant ${JSON.stringify(unexpectedValue.mutant)}`); break; }
      if (!errorsMatch(errs, w.errors.mutant)) { technicalFailure(`${w.test}: unexpected caught errors ${JSON.stringify(witnessReport.caught_errors)}, accepted ${JSON.stringify(w.errors.mutant)}`); break; }
      if (t?.status === "failed" && !firstLine.startsWith("WitnessAssertionError:")) { technicalFailure(`${w.test} failed without a WitnessAssertionError: ${firstLine.slice(0, 200)}`); break; }
      const allMutantValues = w.labels.every(l => isDeepStrictEqual(values[l.label][0], l.mutant));
      if (!(t?.status === "failed" && allMutantValues && isDeepStrictEqual(failedLabels, expectedFailed))) detected = false;
    }
    if (!entry.status) entry.status = detected ? "detected" : "not_detected";
  }
  if (entry.status === "technical_failure") technical++;
  if (entry.status === "not_detected") undetected++;
  report.mutants.push(entry);
  console.log(`${m.id.padEnd(13)} ${m.kind.padEnd(22)} ${entry.status}${entry.detail ? ` (${entry.detail})` : ""}`);
}

const byKind = kind => report.mutants.filter(e => e.kind === kind && e.status === "detected").map(e => e.id);
report.summary = {
  detected: report.mutants.filter(e => e.status === "detected").length,
  not_detected: undetected,
  technical_failures: technical,
  evidence: { both: byKind("both"), containment_effect: byKind("containment_effect"), check_point: byKind("check_point"), component_check_point: byKind("component_check_point") },
  containment_evidence: [...byKind("both"), ...byKind("containment_effect")],
  check_point_evidence_production_path: [...byKind("both"), ...byKind("check_point")],
  recorded_gaps: manifest.recorded_gaps,
};
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report.summary));
rmSync(work, { recursive: true, force: true });
process.exit(technical ? 2 : undetected ? 1 : 0);
} catch (error) {
  crash(error);
}
