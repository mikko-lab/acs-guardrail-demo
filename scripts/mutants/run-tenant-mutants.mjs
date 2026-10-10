#!/usr/bin/env node
/**
 * Runtime-test mutant gate for tenant scope (package 1a). See docs/tenant-scope.md#mutant-gate.
 *
 * The manifest (mutants/tenant/manifest.json) names every mutant, its patch, its witness tests, the expected
 * assertion labels and its evidence kind before any run; its SHA-256 and every patch's SHA-256 are checked first.
 *
 * 1. Control: an unpatched copy of the tree must typecheck and pass the whole jest suite, witnesses included.
 * 2. Each mutant, in a fresh copy: the patch must apply, the tree must typecheck, and jest must load the same number
 *    of suites as the control with no suite execution error. Anything else is a technical failure, never a detection.
 * 3. Detection: every named witness test fails with WitnessAssertionError, and every label the mutant's kind
 *    requires appears in that failure (check_point: check labels; containment_effect: effect labels; both: both;
 *    component_check_point: the component test's check labels).
 *
 * Exit: 0 all detected; 1 some mutant not detected; 2 technical failure (control, manifest, patch, typecheck, load).
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
const args = process.argv.slice(2);
const opt = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
const manifestPath = resolve(root, opt("--manifest", "mutants/tenant/manifest.json"));
const outDir = resolve(root, opt("--out", "out/mutants-tenant"));
const only = opt("--only", "");

const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const fail = (code, message) => { console.error(`mutant gate: ${message}`); process.exit(code); };

// Manifest and patches are fixed before the run.
const manifestBytes = readFileSync(manifestPath);
const expectedManifestSha = readFileSync(manifestPath.replace(/\.json$/, ".sha256"), "utf8").trim();
if (sha256(manifestBytes) !== expectedManifestSha) fail(2, `manifest SHA-256 ${sha256(manifestBytes)} does not match ${expectedManifestSha}`);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const KINDS = { check_point: ["check"], containment_effect: ["effect"], both: ["check", "effect"], component_check_point: ["check"] };
for (const m of manifest.mutants) {
  if (!KINDS[m.kind]) fail(2, `${m.id}: unknown evidence kind ${m.kind}`);
  const patch = readFileSync(join(root, m.patch));
  if (sha256(patch) !== m.patch_sha256) fail(2, `${m.id}: patch SHA-256 does not match the manifest`);
  for (const w of m.witnesses) for (const part of KINDS[m.kind]) {
    if (!(w[`${part}_labels`] ?? []).length) fail(2, `${m.id}: kind ${m.kind} needs ${part} labels for ${w.test}`);
  }
}

const files = spawnSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: root, encoding: "utf8" }).stdout.split("\0").filter(Boolean);
const work = mkdtempSync(join(tmpdir(), "tenant-mutants-"));
function copyTree(name) {
  const dir = join(work, name);
  for (const f of files) { mkdirSync(dirname(join(dir, f)), { recursive: true }); cpSync(join(root, f), join(dir, f)); }
  symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "dir");
  return dir;
}
const run = (cmd, argv, cwd) => spawnSync(cmd, argv, { cwd, encoding: "utf8", maxBuffer: 1 << 28, timeout: 15 * 60_000 });
function check(dir) {
  const tsc = run("npx", ["tsc", "--noEmit"], dir);
  if (tsc.status !== 0) return { typecheck: false, detail: (tsc.stdout + tsc.stderr).split("\n").slice(0, 5).join(" | ") };
  const json = join(dir, "jest-result.json");
  const jest = run("npx", ["jest", "--ci", "--json", "--outputFile", json], dir);
  let result;
  try { result = JSON.parse(readFileSync(json, "utf8")); } catch { return { typecheck: true, loaded: false, detail: `jest produced no result (status ${jest.status}, signal ${jest.signal})` }; }
  return { typecheck: true, loaded: true, result };
}
const testsOf = result => result.testResults.flatMap(s => s.assertionResults.map(a => ({ file: s.name.slice(s.name.indexOf("/tests/") + 1), ...a })));
const findTest = (result, w) => testsOf(result).find(t => t.file === w.file && t.title === w.test && t.ancestorTitles.join(" ") === w.describe);

const report = { manifest_sha256: expectedManifestSha, control: null, mutants: [] };
const control = check(copyTree("control"));
if (!control.typecheck || !control.loaded) fail(2, `control is not technically sound: ${control.detail}`);
const c = control.result;
report.control = { suites: c.numTotalTestSuites, tests: c.numTotalTests, failed: c.numFailedTests, runtime_errors: c.numRuntimeErrorTestSuites };
if (!c.success || c.numFailedTests !== 0 || c.numRuntimeErrorTestSuites !== 0) fail(2, `control does not pass: ${JSON.stringify(report.control)}`);
for (const m of manifest.mutants) for (const w of m.witnesses) {
  const t = findTest(c, w);
  if (!t || t.status !== "passed") fail(2, `control: witness ${w.test} of ${m.id} is ${t ? t.status : "missing"}`);
}

let undetected = 0, technical = 0;
for (const m of manifest.mutants) {
  if (only && m.id !== only) continue;
  const entry = { id: m.id, kind: m.kind, removes: m.removes, status: "", witnesses: [], other_failures: [] };
  const dir = copyTree(m.id);
  const apply = run("git", ["apply", join(root, m.patch)], dir);
  const outcome = apply.status !== 0 ? { typecheck: false, detail: `patch does not apply: ${apply.stderr.trim()}` } : check(dir);
  if (!outcome.typecheck || !outcome.loaded) { entry.status = "technical_failure"; entry.detail = outcome.detail; }
  else {
    const r = outcome.result;
    entry.suites = r.numTotalTestSuites; entry.tests = r.numTotalTests;
    if (r.numTotalTestSuites !== c.numTotalTestSuites || r.numRuntimeErrorTestSuites !== 0) {
      entry.status = "technical_failure"; entry.detail = `suites ${r.numTotalTestSuites} (control ${c.numTotalTestSuites}), suite execution errors ${r.numRuntimeErrorTestSuites}`;
    } else {
      const named = new Set(m.witnesses.map(w => w.test));
      entry.other_failures = testsOf(r).filter(t => t.status === "failed" && !named.has(t.title)).map(t => t.title);
      let detected = true;
      for (const w of m.witnesses) {
        const t = findTest(r, w);
        const message = (t?.failureMessages ?? []).join("\n");
        const firstLine = message.trimStart().split("\n")[0] ?? "";
        const required = KINDS[m.kind].flatMap(part => w[`${part}_labels`]);
        const failedLabels = [...message.matchAll(/WITNESS\[([^\]]+)\]/g)].map(x => x[1]);
        const witnessError = firstLine.startsWith("WitnessAssertionError:");
        const ok = t?.status === "failed" && witnessError && required.every(l => failedLabels.includes(l));
        entry.witnesses.push({ test: w.test, status: t?.status ?? "missing", witness_assertion: witnessError, required_labels: required, failed_labels: [...new Set(failedLabels)], first_line: firstLine.slice(0, 240) });
        if (!ok) detected = false;
        if (t?.status === "failed" && !witnessError) { entry.status = "technical_failure"; entry.detail = `witness ${w.test} failed without a WitnessAssertionError: ${firstLine.slice(0, 200)}`; }
      }
      if (!entry.status) entry.status = detected ? "detected" : "not_detected";
    }
  }
  if (entry.status === "technical_failure") technical++;
  if (entry.status === "not_detected") undetected++;
  report.mutants.push(entry);
  console.log(`${m.id.padEnd(5)} ${m.kind.padEnd(22)} ${entry.status}${entry.detail ? ` (${entry.detail})` : ""}`);
}

const byKind = kind => report.mutants.filter(e => e.kind === kind && e.status === "detected").map(e => e.id);
report.summary = {
  detected: report.mutants.filter(e => e.status === "detected").length,
  not_detected: undetected,
  technical_failures: technical,
  evidence: {
    both: byKind("both"),
    containment_effect: byKind("containment_effect"),
    check_point: byKind("check_point"),
    component_check_point: byKind("component_check_point"),
  },
  containment_evidence: [...byKind("both"), ...byKind("containment_effect")],
  check_point_evidence_production_path: [...byKind("both"), ...byKind("check_point")],
  recorded_gaps: ["M33: no production-path witness; component_check_point only (docs/tenant-scope.md)"],
};
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report.summary, null, 2));
rmSync(work, { recursive: true, force: true });
process.exit(technical ? 2 : undetected ? 1 : 0);
