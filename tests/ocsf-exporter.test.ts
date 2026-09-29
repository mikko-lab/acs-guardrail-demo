import { createHash } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import { AuditCollector, AUDIT_GENESIS_HASH } from "../src/audit";
import type { AuditEvent } from "../src/acs-types";
import {
  exportAuditToOcsf,
  exportAuditToOcsfJsonl,
  serializeOcsfJsonl,
  OCSF_SCHEMA_VERSION,
  OcsfExportIntegrityError,
  OcsfMappingError,
  OcsfTrustedHeadRequiredError,
  ocsfEventUid,
} from "../src/ocsf";

function buildStream(): AuditCollector {
  const audit = new AuditCollector();
  audit.record("req-1", "tool_call_requested", { session_id: "s-1", tool: "read_record" });
  audit.record("req-1", "guardian_decision", { session_id: "s-1", decision: "allow", reason_codes: ["OK"] });
  audit.record("req-1", "tool_execution_started");
  audit.record("req-1", "tool_execution_completed", { status: "success" });
  audit.record("req-2", "replay_rejected", { session_id: "s-1", reason_code: "REPLAY_DETECTED" });
  return audit;
}

function expectIntegrityFailure(fn: () => unknown, reason: string, index?: number): void {
  let caught: unknown;
  try {
    fn();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(OcsfExportIntegrityError);
  const err = caught as OcsfExportIntegrityError;
  expect(err.result.reason).toBe(reason);
  if (index !== undefined) expect(err.result.index).toBe(index);
}

describe("OCSF export: integrity gate (fail closed)", () => {
  it("exports a valid chain", () => {
    const audit = buildStream();
    const events = audit.getEvents();
    const result = exportAuditToOcsf(events);
    expect(result.ocsf_version).toBe("1.8.0");
    expect(result.integrity).toBe("structural");
    expect(result.source_event_count).toBe(5);
    expect(result.source_head_hash).toBe(audit.getHeadHash());
    expect(result.events).toHaveLength(5);
  });

  it("exports a valid chain with the correct trusted head", () => {
    const audit = buildStream();
    const result = exportAuditToOcsf(audit.getEvents(), { expectedHeadHash: audit.getHeadHash() });
    expect(result.integrity).toBe("trusted_head");
    expect(result.events).toHaveLength(5);
  });

  it("refuses a mutated event", () => {
    const events = buildStream().getEvents();
    events[1].metadata = { ...events[1].metadata, decision: "deny" };
    expectIntegrityFailure(() => exportAuditToOcsf(events), "event_hash_mismatch", 1);
  });

  it("refuses a mutated timestamp", () => {
    const events = buildStream().getEvents();
    events[2].timestamp = "2000-01-01T00:00:00.000Z";
    expectIntegrityFailure(() => exportAuditToOcsf(events), "event_hash_mismatch", 2);
  });

  it("refuses a broken previous_hash link", () => {
    const events = buildStream().getEvents();
    events[3].previous_hash = "0".repeat(64);
    expectIntegrityFailure(() => exportAuditToOcsf(events), "previous_hash_mismatch", 3);
  });

  it("refuses an invalid genesis", () => {
    const events = buildStream().getEvents();
    events[0].previous_hash = "NOT-GENESIS";
    expectIntegrityFailure(() => exportAuditToOcsf(events), "genesis_mismatch", 0);
  });

  it("refuses a removed middle event", () => {
    const events = buildStream().getEvents();
    events.splice(2, 1);
    expectIntegrityFailure(() => exportAuditToOcsf(events), "previous_hash_mismatch", 2);
  });

  it("refuses a removed first event", () => {
    const events = buildStream().getEvents();
    events.shift();
    expectIntegrityFailure(() => exportAuditToOcsf(events), "genesis_mismatch", 0);
  });

  it("refuses reordered events", () => {
    const events = buildStream().getEvents();
    [events[1], events[2]] = [events[2], events[1]];
    expectIntegrityFailure(() => exportAuditToOcsf(events), "previous_hash_mismatch", 1);
  });

  it("refuses missing hashes", () => {
    const events = buildStream().getEvents();
    delete events[4].event_hash;
    expectIntegrityFailure(() => exportAuditToOcsf(events), "missing_hash", 4);
  });

  it("refuses a wrong expected trusted head", () => {
    const audit = buildStream();
    expectIntegrityFailure(
      () => exportAuditToOcsf(audit.getEvents(), { expectedHeadHash: "f".repeat(64) }),
      "head_hash_mismatch"
    );
  });

  it("LIMITATION: without a trusted head a truncated but structurally valid prefix is exported", () => {
    // Documented limitation (docs/ocsf-export.md): structural verification
    // alone cannot tell a complete stream from a valid prefix of a longer one.
    const audit = buildStream();
    const prefix = audit.getEvents().slice(0, 3);
    const result = exportAuditToOcsf(prefix);
    expect(result.integrity).toBe("structural");
    expect(result.events).toHaveLength(3);
    expect(result.source_head_hash).not.toBe(audit.getHeadHash());
  });

  it("refuses a truncated prefix when the trusted head of the full stream is supplied", () => {
    const audit = buildStream();
    const trustedHead = audit.getHeadHash();
    const prefix = audit.getEvents().slice(0, 3);
    expectIntegrityFailure(
      () => exportAuditToOcsf(prefix, { expectedHeadHash: trustedHead }),
      "head_hash_mismatch",
      2
    );
  });

  it("refuses an emptied stream when a trusted head is supplied", () => {
    const audit = buildStream();
    expectIntegrityFailure(
      () => exportAuditToOcsf([], { expectedHeadHash: audit.getHeadHash() }),
      "head_hash_mismatch"
    );
  });

  it("LIMITATION: a fully recomputed chain passes structural verification but not trusted-head verification", () => {
    const original = buildStream();
    const trustedHead = original.getHeadHash();
    // An attacker able to rewrite the whole stream re-records a different history.
    const forged = new AuditCollector();
    forged.record("req-1", "tool_call_requested", { session_id: "s-1", tool: "read_record" });
    forged.record("req-1", "guardian_decision", { session_id: "s-1", decision: "deny", reason_codes: ["X"] });
    expect(exportAuditToOcsf(forged.getEvents()).events).toHaveLength(2);
    expectIntegrityFailure(
      () => exportAuditToOcsf(forged.getEvents(), { expectedHeadHash: trustedHead }),
      "head_hash_mismatch"
    );
  });

  it("requireTrustedHead refuses export without a trusted head", () => {
    const audit = buildStream();
    expect(() => exportAuditToOcsf(audit.getEvents(), { requireTrustedHead: true })).toThrow(
      OcsfTrustedHeadRequiredError
    );
    expect(
      exportAuditToOcsf(audit.getEvents(), { requireTrustedHead: true, expectedHeadHash: audit.getHeadHash() })
        .integrity
    ).toBe("trusted_head");
  });

  it("exports an empty stream as an empty result without a trusted head", () => {
    const result = exportAuditToOcsf([]);
    expect(result.events).toEqual([]);
    expect(result.source_head_hash).toBeNull();
    expect(serializeOcsfJsonl(result.events)).toBe("");
  });

  it("returns nothing partial: a failure on the last event yields no events at all", () => {
    const events = buildStream().getEvents();
    events[4].metadata = { tampered: true };
    let partial: unknown = "unset";
    try {
      partial = exportAuditToOcsf(events);
    } catch {
      // expected
    }
    expect(partial).toBe("unset");
    expect(() => exportAuditToOcsfJsonl(events)).toThrow(OcsfExportIntegrityError);
  });

  it("refuses a chain-valid event whose timestamp is not RFC 3339 (no partial export)", () => {
    // A chain can be structurally valid over any content; the mapper still fails closed.
    // Built as a foreign producer would, with an RFC 7231 timestamp.
    const forged: AuditEvent = {
      timestamp: "Tue, 29 Sep 2026 10:00:00 GMT",
      request_id: "req-1",
      event_type: "tool_execution_started",
      previous_hash: AUDIT_GENESIS_HASH,
    };
    forged.event_hash = createHash("sha256")
      .update(canonicalize({ timestamp: forged.timestamp, request_id: forged.request_id, event_type: forged.event_type, previous_hash: AUDIT_GENESIS_HASH }))
      .digest("hex");
    const events = [forged];
    expect(AuditCollector.verifyIntegrity(events)).toEqual({ valid: true });
    expect(() => exportAuditToOcsf(events)).toThrow(OcsfMappingError);
  });

  it("verifies and maps the same snapshot even if an accessor changes its value between reads", () => {
    const audit = buildStream();
    const events = audit.getEvents();
    const target = events[1];
    const honest = target.metadata;
    let reads = 0;
    Object.defineProperty(target, "metadata", {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? honest : { ...honest, decision: "deny", injected: "secret" };
      },
    });
    const result = exportAuditToOcsf(events);
    expect(reads).toBe(1);
    expect(result.events[1].unmapped.acs.metadata).toEqual({
      decision: "allow",
      reason_codes: ["OK"],
      session_id: "s-1",
    });
  });
});

describe("OCSF export: output properties", () => {
  it("preserves source order", () => {
    const audit = buildStream();
    const events = audit.getEvents();
    const result = exportAuditToOcsf(events);
    expect(result.events.map(e => e.unmapped.acs.event_hash)).toEqual(events.map(e => e.event_hash));
    expect(result.events.map(e => e.metadata.sequence)).toEqual([0, 1, 2, 3, 4]);
    expect(result.events.map(e => e.unmapped.acs.event_type)).toEqual(events.map(e => e.event_type));
  });

  it("same input produces byte-identical JSONL", () => {
    const events = buildStream().getEvents();
    const a = exportAuditToOcsfJsonl(events);
    const b = exportAuditToOcsfJsonl(JSON.parse(JSON.stringify(events)));
    expect(a).toBe(b);
    expect(a.length).toBeGreaterThan(0);
  });

  it("same ACS event yields the same event UID across exports", () => {
    const events = buildStream().getEvents();
    const first = exportAuditToOcsf(events).events.map(e => e.metadata.uid);
    const second = exportAuditToOcsf(events).events.map(e => e.metadata.uid);
    expect(first).toEqual(second);
    expect(first[0]).toBe(ocsfEventUid(events[0].event_hash!));
  });

  it("the event UID of a prefix event does not change when the stream grows", () => {
    const audit = buildStream();
    const before = exportAuditToOcsf(audit.getEvents()).events.map(e => e.metadata.uid);
    audit.record("req-3", "tool_call_requested", { session_id: "s-2", tool: "read_record" });
    const after = exportAuditToOcsf(audit.getEvents()).events.map(e => e.metadata.uid);
    expect(after.slice(0, before.length)).toEqual(before);
  });

  it("multiple events of one request_id get distinct event UIDs but share correlation_uid", () => {
    const result = exportAuditToOcsf(buildStream().getEvents());
    const req1 = result.events.filter(e => e.unmapped.acs.request_id === "req-1");
    expect(req1).toHaveLength(4);
    expect(new Set(req1.map(e => e.metadata.uid)).size).toBe(4);
    expect(new Set(req1.map(e => e.metadata.correlation_uid))).toEqual(new Set(["req-1"]));
  });

  it("identical content recorded twice in one chain still yields distinct UIDs (previous_hash differs)", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "tool_execution_started");
    audit.record("req-1", "tool_execution_started");
    const events = audit.getEvents();
    const result = exportAuditToOcsf(events);
    expect(result.events[0].metadata.uid).not.toBe(result.events[1].metadata.uid);
  });

  it("preserves event_hash, previous_hash, timestamp, request_id and event type as provenance", () => {
    const events = buildStream().getEvents();
    const result = exportAuditToOcsf(events);
    result.events.forEach((ocsf, i) => {
      const acs = ocsf.unmapped.acs;
      expect(acs.event_hash).toBe(events[i].event_hash);
      expect(acs.previous_hash).toBe(events[i].previous_hash);
      expect(acs.timestamp).toBe(events[i].timestamp);
      expect(acs.request_id).toBe(events[i].request_id);
      expect(acs.event_type).toBe(events[i].event_type);
      expect(acs.chain_index).toBe(i);
      expect(ocsf.metadata.original_time).toBe(events[i].timestamp);
    });
    expect(result.events[0].unmapped.acs.previous_hash).toBe(AUDIT_GENESIS_HASH);
  });

  it("uses the source event time, not export time", () => {
    const events = buildStream().getEvents();
    const result = exportAuditToOcsf(events);
    result.events.forEach((ocsf, i) => {
      expect(ocsf.time).toBe(Date.parse(events[i].timestamp));
    });
    expect(JSON.stringify(result)).not.toMatch(/exported_at/);
  });

  it("does not mutate the input AuditEvent objects", () => {
    const events = buildStream().getEvents();
    const before = JSON.parse(JSON.stringify(events));
    Object.freeze(events);
    events.forEach(e => {
      Object.freeze(e);
      if (e.metadata) Object.freeze(e.metadata);
    });
    const result = exportAuditToOcsf(events);
    expect(events).toEqual(before);
    // The output is detached from the input.
    (result.events[0].unmapped.acs.metadata as Record<string, unknown>).tool = "changed";
    expect(events[0].metadata?.tool).toBe("read_record");
  });

  it("export does not change the ACS chain or head", () => {
    const audit = buildStream();
    const head = audit.getHeadHash();
    exportAuditToOcsf(audit.getEvents());
    expect(audit.getHeadHash()).toBe(head);
    expect(audit.verifyIntegrity(head)).toEqual({ valid: true });
  });

  it("writes nothing to the console", () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map(m =>
      jest.spyOn(console, m).mockImplementation(() => undefined)
    );
    try {
      exportAuditToOcsfJsonl(buildStream().getEvents());
      try {
        const events = buildStream().getEvents();
        events[0].request_id = "x";
        exportAuditToOcsf(events);
      } catch {
        // expected
      }
      spies.forEach(s => expect(s).not.toHaveBeenCalled());
    } finally {
      spies.forEach(s => s.mockRestore());
    }
  });
});

describe("OCSF export: JSONL", () => {
  it("emits one parseable JSON OCSF event per line", () => {
    const events = buildStream().getEvents();
    const jsonl = exportAuditToOcsfJsonl(events);
    expect(jsonl.endsWith("\n")).toBe(true);
    const lines = jsonl.split("\n");
    expect(lines.pop()).toBe("");
    expect(lines).toHaveLength(events.length);
    lines.forEach((line, i) => {
      expect(line).not.toMatch(/\n/);
      const parsed = JSON.parse(line);
      expect(parsed.metadata.version).toBe(OCSF_SCHEMA_VERSION);
      expect(parsed.unmapped.acs.event_hash).toBe(events[i].event_hash);
    });
  });

  it("round-trips: parsed lines equal the exported objects", () => {
    const result = exportAuditToOcsf(buildStream().getEvents());
    const parsed = serializeOcsfJsonl(result.events)
      .trimEnd()
      .split("\n")
      .map(l => JSON.parse(l));
    expect(parsed).toEqual(JSON.parse(JSON.stringify(result.events)));
  });

  it("escapes newlines inside values so a line cannot be split or injected", () => {
    const audit = new AuditCollector();
    audit.record("req-1\n{\"class_uid\":0}", "tool_call_requested", { session_id: "s\n1", tool: "t\r\nx" });
    const jsonl = exportAuditToOcsfJsonl(audit.getEvents());
    expect(jsonl.split("\n").filter(Boolean)).toHaveLength(1);
    const parsed = JSON.parse(jsonl.trimEnd());
    expect(parsed.unmapped.acs.request_id).toBe("req-1\n{\"class_uid\":0}");
  });
});
