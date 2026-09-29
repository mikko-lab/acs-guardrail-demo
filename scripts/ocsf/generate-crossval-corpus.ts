/**
 * Generates the OCSF 1.8.0 cross-validation corpus from the current exporter
 * (used by scripts/ocsf/cross-validate.sh).
 *
 * Every event is produced by exportAuditToOcsf(...) from an ACS audit stream;
 * nothing is written by hand. Each event is written as <outDir>/<name>.json
 * (the format read by `ocsf-toolkit --events-dir`), and a local validation
 * summary is written to <outDir>/../local-validation.json.
 *
 *   npx ts-node scripts/ocsf/generate-crossval-corpus.ts <outDir>
 *
 * Timestamps and hashes differ per run; the class/field shape does not.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { AuditCollector } from "../../src/audit";
import type { AuditEventType } from "../../src/acs-types";
import { exportAuditToOcsf, OcsfEvent, validateOcsfEvent } from "../../src/ocsf";
import { makeRequest, setup } from "../../tests/evals/eval-setup";

interface CorpusEntry {
  name: string;
  event: OcsfEvent;
}

function single(name: string, type: AuditEventType, metadata: Record<string, unknown>): CorpusEntry {
  const audit = new AuditCollector();
  audit.record(`crossval-${name}`, type, metadata);
  const [event] = exportAuditToOcsf(audit.getEvents(), { expectedHeadHash: audit.getHeadHash() }).events;
  return { name, event };
}

async function runtimeFlow(): Promise<CorpusEntry[]> {
  const { executor, audit } = setup(Date.now());
  const allow = makeRequest({ tool: "read_record", requestId: "crossval-allow", sessionId: "crossval-s" });
  await executor.process(allow);
  await executor.process(allow).catch(() => undefined); // replay
  await executor
    .process(makeRequest({ tool: "delete_record", requestId: "crossval-deny", sessionId: "crossval-s" }))
    .catch(() => undefined); // Guardian deny
  const result = exportAuditToOcsf(audit.getEvents(), { expectedHeadHash: audit.getHeadHash() });
  return result.events.map((event, i) => ({
    name: `G-${String(i).padStart(2, "0")}-${event.unmapped.acs.event_type}`,
    event,
  }));
}

async function main(): Promise<void> {
  const outDir = resolve(process.argv[2] ?? "ocsf-crossval/events");
  const corpus: CorpusEntry[] = [
    single("A-tool_call_requested", "tool_call_requested", { session_id: "crossval-s", tool: "read_record" }),
    single("B-guardian_decision-deny", "guardian_decision", {
      session_id: "crossval-s",
      decision: "deny",
      reason_codes: ["DENY_DESTRUCTIVE_TOOL"],
    }),
    single("C-tool_execution_completed-success", "tool_execution_completed", { status: "success" }),
    single("D-replay_rejected", "replay_rejected", { session_id: "crossval-s", reason_code: "REPLAY_DETECTED" }),
    single("E-capability_rejected-agent_mismatch", "capability_rejected", {
      reason: "capability_agent_mismatch",
      agent_id: "crossval-agent",
      session_id: "crossval-s",
      tool: "read_record",
    }),
    single("F-result_guardian_decision-deny", "result_guardian_decision", {
      decision: "deny",
      reason_codes: ["RESULT_POLICY"],
    }),
    ...(await runtimeFlow()),
  ];

  mkdirSync(outDir, { recursive: true });
  const summary = corpus.map(({ name, event }) => {
    writeFileSync(join(outDir, `${name}.json`), JSON.stringify(event, null, 2) + "\n");
    const issues = validateOcsfEvent(event);
    return {
      name,
      acs_event_type: event.unmapped.acs.event_type,
      class_uid: event.class_uid,
      type_uid: event.type_uid,
      local_validation: issues.length === 0 ? "PASS" : "FAIL",
      local_issues: issues,
    };
  });
  writeFileSync(join(dirname(outDir), "local-validation.json"), JSON.stringify(summary, null, 2) + "\n");
  process.stdout.write(`${corpus.length} events written to ${outDir}\n`);
}

main().catch(err => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
