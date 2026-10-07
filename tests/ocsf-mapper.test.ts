import { AuditCollector } from "../src/audit";
import type { AuditEventType } from "../src/acs-types";
import { IncidentClassifier } from "../src/incident-evidence";
import {
  exportAuditToOcsf,
  exportAuditToOcsfJsonl,
  OCSF_METADATA_ALLOWLIST,
  OcsfDetectionFinding,
  OcsfEvent,
  validateOcsfEvent,
} from "../src/ocsf";
import { setup, makeRequest } from "./evals/eval-setup";

function exportOne(eventType: AuditEventType, metadata?: Record<string, unknown>, requestId = "req-1"): OcsfEvent {
  const audit = new AuditCollector();
  audit.record(requestId, eventType, metadata);
  return exportAuditToOcsf(audit.getEvents()).events[0];
}

/** Every key that appears anywhere in a JSON value. */
function allKeys(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach(v => allKeys(v, out));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      allKeys(v, out);
    }
  }
  return out;
}

const INVENTED_FIELDS = [
  "actor",
  "user",
  "src_endpoint",
  "dst_endpoint",
  "device",
  "ip",
  "tenant_uid",
  "api",
  "session",
  "identity",
  "cloud",
  "http_request",
];

describe("OCSF mapping: class selection", () => {
  it("a non-incident ACS event maps to OCSF Base Event (class_uid 0)", () => {
    const e = exportOne("tool_call_requested", { session_id: "s-1", tool: "read_record" });
    expect(e.class_uid).toBe(0);
    expect(e.category_uid).toBe(0);
    expect(e.activity_id).toBe(99);
    expect(e.activity_name).toBe("tool_call_requested");
    expect(e.type_uid).toBe(99);
    expect(e.severity_id).toBe(0);
    expect(e.metadata.version).toBe("1.8.0");
  });

  it("guardian_decision=deny is NOT automatically a Detection Finding", () => {
    const e = exportOne("guardian_decision", { session_id: "s-1", decision: "deny", reason_codes: ["DENY_DESTRUCTIVE"] });
    expect(e.class_uid).toBe(0);
    expect("finding_info" in e).toBe(false);
    expect(e.unmapped.acs.incident).toBeUndefined();
    expect(e.unmapped.acs.metadata?.decision).toBe("deny");
  });

  it("approval_requested is NOT a security incident", () => {
    const e = exportOne("approval_requested", { session_id: "s-1" });
    expect(e.class_uid).toBe(0);
    expect(e.unmapped.acs.incident).toBeUndefined();
  });

  it.each([
    ["tool_execution_blocked", { reason: "denied" }],
    ["human_rejection", { approver_type: "human", approver_id: "a", session_id: "s", request_id: "req-1" }],
    ["approval_expired", { session_id: "s-1" }],
    ["capability_rejected", { reason: "missing_capability", agent_id: "a", session_id: "s", tool: "t" }],
    ["approval_verification_failed", { reason: "expired" }],
    ["result_guardian_decision", { decision: "allow" }],
  ] as Array<[AuditEventType, Record<string, unknown>]>)(
    "%s without classifier incident evidence stays a Base Event",
    (type, metadata) => {
      expect(exportOne(type, metadata).class_uid).toBe(0);
    }
  );

  it.each([
    ["replay_rejected", { session_id: "s-1", reason_code: "REPLAY_DETECTED" }, "replay_attempt", 4, "High"],
    ["timestamp_rejected", { session_id: "s-1", reason_code: "TIMESTAMP_OUT_OF_WINDOW" }, "request_freshness_violation", 3, "Medium"],
    ["correlation_failed", { session_id: "s-1", request_id_ref: "r", tool: "t", disposition: "deny", reason: "unresolved_request_id_ref" }, "correlation_failure", 4, "High"],
    ["result_guardian_decision", { decision: "deny", reason_codes: ["X"] }, "result_policy_violation", 3, "Medium"],
    ["capability_rejected", { reason: "capability_agent_mismatch", agent_id: "a", session_id: "s", tool: "t" }, "authority_boundary_violation", 4, "High"],
    ["capability_rejected", { reason: "capability_authentication_failed", agent_id: "a", session_id: "s", tool: "t" }, "authority_authentication_failure", 4, "High"],
    ["approval_verification_failed", { reason: "invalid_signature" }, "authority_authentication_failure", 4, "High"],
  ] as Array<[AuditEventType, Record<string, unknown>, string, number, string]>)(
    "%s classified by IncidentClassifier becomes a Detection Finding (%s)",
    (type, metadata, incidentType, severityId, severity) => {
      const audit = new AuditCollector();
      audit.record("req-1", type, metadata);
      const events = audit.getEvents();
      const [incident] = IncidentClassifier.fromAudit(events);
      const e = exportAuditToOcsf(events).events[0] as OcsfDetectionFinding;
      expect(e.class_uid).toBe(2004);
      expect(e.category_uid).toBe(2);
      expect(e.activity_id).toBe(1);
      expect(e.type_uid).toBe(200401);
      expect(e.severity_id).toBe(severityId);
      expect(e.severity).toBe(severity);
      expect(e.finding_info.uid).toBe(incident.incident_id);
      expect(e.finding_info.types).toEqual([incidentType]);
      expect(e.unmapped.acs.incident).toEqual({
        classifier: "IncidentClassifier",
        envelope_version: "1",
        incident_id: incident.incident_id,
        incident_type: incidentType,
        severity: incident.severity,
        disposition: incident.disposition,
        requires_human_review: incident.requires_human_review,
      });
      // The finding still points to the ACS source evidence.
      expect(e.unmapped.acs.event_hash).toBe(events[0].event_hash);
      expect(e.time).toBe(Date.parse(incident.detected_at));
    }
  );

  it("finding ids equal the stream-level IncidentClassifier ids in a mixed stream", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "guardian_decision", { session_id: "s", decision: "deny" });
    audit.record("req-2", "replay_rejected", { session_id: "s", reason_code: "REPLAY_DETECTED" });
    audit.record("req-3", "tool_call_requested", { session_id: "s", tool: "t" });
    audit.record("req-4", "result_guardian_decision", { decision: "deny" });
    audit.record("req-5", "capability_rejected", { reason: "missing_capability" });
    audit.record("req-6", "capability_rejected", { reason: "capability_scope_mismatch" });
    const events = audit.getEvents();
    const incidents = IncidentClassifier.fromAudit(events);
    const out = exportAuditToOcsf(events).events;
    expect(out.map(e => e.class_uid)).toEqual([0, 2004, 0, 2004, 0, 2004]);
    const findings = out.filter((e): e is OcsfDetectionFinding => e.class_uid === 2004);
    expect(findings.map(f => f.finding_info.uid)).toEqual(incidents.map(i => i.incident_id));
  });

  it("maps the recorded tool_execution_completed outcome to status_id, and nothing else", () => {
    const ok = exportOne("tool_execution_completed", { status: "success" });
    const err = exportOne("tool_execution_completed", { status: "error" });
    const other = exportOne("tool_execution_completed", { status: "weird" });
    expect([ok.class_uid, (ok as any).status_id, (ok as any).status]).toEqual([0, 1, "Success"]);
    expect([(err as any).status_id, (err as any).status]).toEqual([2, "Failure"]);
    expect("status_id" in other).toBe(false);
    expect("status_id" in exportOne("guardian_decision", { decision: "allow" })).toBe(false);
  });
});

describe("OCSF mapping: Base Event type_name for type_uid 99 (Other)", () => {
  it.each([
    ["tool_call_requested", { session_id: "s-1", tool: "read_record" }],
    ["guardian_decision", { session_id: "s-1", decision: "deny", reason_codes: ["X"] }],
    ["tool_execution_completed", { status: "success" }],
  ] as Array<[AuditEventType, Record<string, unknown>]>)(
    "%s -> type_name 'Base Event: %s' with class/activity/type ids unchanged",
    (type, metadata) => {
      const e = exportOne(type, metadata);
      expect(e.type_name).toBe(`Base Event: ${type}`);
      expect(e.type_name).not.toBe("Base Event: Other");
      expect(e.type_uid).toBe(99);
      expect(e.activity_id).toBe(99);
      expect(e.activity_name).toBe(type);
      expect(e.class_uid).toBe(0);
      expect(e.category_uid).toBe(0);
      expect(e.severity_id).toBe(0);
      expect(validateOcsfEvent(e)).toEqual([]);
    }
  );

  it("every Base Event type_name embeds its ACS event type", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "tool_call_requested", { tool: "t" });
    audit.record("req-1", "approval_requested", { session_id: "s" });
    audit.record("req-1", "tool_execution_started");
    for (const e of exportAuditToOcsf(audit.getEvents()).events) {
      expect(e.class_uid).toBe(0);
      expect(e.type_name).toBe(`Base Event: ${e.unmapped.acs.event_type}`);
    }
  });

  it("Detection Finding classification fields are unchanged", () => {
    const e = exportOne("replay_rejected", { session_id: "s", reason_code: "REPLAY_DETECTED" });
    expect({
      class_uid: e.class_uid,
      class_name: e.class_name,
      category_uid: e.category_uid,
      category_name: e.category_name,
      activity_id: e.activity_id,
      activity_name: e.activity_name,
      type_uid: e.type_uid,
      type_name: e.type_name,
      severity_id: e.severity_id,
      severity: e.severity,
    }).toEqual({
      class_uid: 2004,
      class_name: "Detection Finding",
      category_uid: 2,
      category_name: "Findings",
      activity_id: 1,
      activity_name: "Create",
      type_uid: 200401,
      type_name: "Detection Finding: Create",
      severity_id: 4,
      severity: "High",
    });
  });
});

describe("OCSF mapping: no invented identity or endpoint data", () => {
  it("never emits actor/user/endpoint/device/tenant/API attributes, even when metadata has identity-like values", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "tool_call_requested", { session_id: "s-1", tool: "t", user: "alice", ip: "10.0.0.1" });
    audit.record("req-1", "capability_verified", { capability_id: "c", agent_id: "agent-1", session_id: "s-1", tool: "t" });
    audit.record("req-1", "human_approval", { approver_type: "human", approver_id: "alice@example.com", session_id: "s-1", request_id: "req-1" });
    audit.record("req-2", "capability_rejected", { reason: "capability_session_mismatch", agent_id: "agent-1", session_id: "s-1", tool: "t" });
    const out = exportAuditToOcsf(audit.getEvents()).events;
    for (const e of out) {
      const topLevel = Object.keys(e);
      const metadataKeys = Object.keys(e.metadata);
      for (const field of INVENTED_FIELDS) {
        expect(topLevel).not.toContain(field);
        expect(metadataKeys).not.toContain(field);
      }
      expect(metadataKeys).not.toContain("tenant_uid");
      expect(metadataKeys).not.toContain("reporter");
    }
    const json = JSON.stringify(out);
    expect(json).not.toContain("alice");
    expect(json).not.toContain("10.0.0.1");
  });

  it("agent_id stays ACS provenance, it is not promoted to an OCSF actor", () => {
    const e = exportOne("capability_verified", { capability_id: "c", agent_id: "agent-1", session_id: "s", tool: "t" });
    expect(e.unmapped.acs.metadata?.agent_id).toBe("agent-1");
    expect("actor" in e).toBe(false);
  });

  it("the ACS 'unknown' request_id sentinel is not used as an OCSF correlation id", () => {
    const e = exportOne("approval_verification_failed", { reason: "missing_ids" }, "unknown");
    expect(e.metadata.correlation_uid).toBeUndefined();
    expect(e.unmapped.acs.request_id).toBe("unknown");
  });
});

describe("OCSF mapping: metadata allowlist", () => {
  it("unknown metadata keys do not leak into the export", () => {
    const e = exportOne("guardian_decision", {
      session_id: "s-1",
      decision: "allow",
      reason_codes: ["OK"],
      api_key: "sk-SECRET",
      tool_payload: { ssn: "123-45-6789" },
      password: "hunter2",
    });
    expect(e.unmapped.acs.metadata).toEqual({ decision: "allow", reason_codes: ["OK"], session_id: "s-1" });
    expect(e.unmapped.acs.omitted_metadata_key_count).toBe(3);
    const line = exportAuditToOcsfJsonl((() => {
      const a = new AuditCollector();
      a.record("req-1", "guardian_decision", { decision: "allow", api_key: "sk-SECRET", nested: { ssn: "123-45-6789" } });
      return a.getEvents();
    })());
    expect(line).not.toContain("sk-SECRET");
    expect(line).not.toContain("123-45-6789");
    expect(line).not.toContain("api_key");
  });

  it("allowlisted keys with non-flat values (nested objects) are dropped", () => {
    const e = exportOne("tool_call_requested", { session_id: { secret: "x" }, tool: "read_record" });
    expect(e.unmapped.acs.metadata).toEqual({ tool: "read_record" });
    expect(e.unmapped.acs.omitted_metadata_key_count).toBe(1);
    expect(JSON.stringify(e)).not.toContain("secret");
  });

  it("allowlisted arrays must be string arrays", () => {
    const e = exportOne("guardian_decision", { decision: "allow", reason_codes: ["OK", { leak: "x" }] });
    expect(e.unmapped.acs.metadata).toEqual({ decision: "allow" });
  });

  it("allowlists are per event type: a key allowed for one type does not leak through another", () => {
    // `decision` is allowlisted for guardian_decision, not for tool_call_requested.
    const e = exportOne("tool_call_requested", { tool: "t", decision: "allow", reason: "x" });
    expect(e.unmapped.acs.metadata).toEqual({ tool: "t" });
  });

  it("approver_id is not exported for human approval/rejection", () => {
    for (const type of ["human_approval", "human_rejection"] as const) {
      const e = exportOne(type, { approver_type: "human", approver_id: "approver@example.com", session_id: "s", request_id: "req-1" });
      expect(e.unmapped.acs.metadata).toEqual({ approver_type: "human", request_id: "req-1", session_id: "s" });
      expect(JSON.stringify(e)).not.toContain("approver@example.com");
    }
  });

  it("the attacker-controlled raw timestamp of timestamp_rejected is not exported", () => {
    const e = exportOne("timestamp_rejected", { session_id: "s", reason_code: "TIMESTAMP_INVALID", raw: "<script>" });
    expect(JSON.stringify(e)).not.toContain("<script>");
    expect(e.unmapped.acs.metadata).toEqual({ reason_code: "TIMESTAMP_INVALID", session_id: "s" });
  });

  it("events without metadata export no metadata block", () => {
    const e = exportOne("tool_execution_started");
    expect(e.unmapped.acs.metadata).toBeUndefined();
    expect(e.unmapped.acs.omitted_metadata_key_count).toBe(0);
  });

  it("has an explicit allowlist entry for every ACS audit event type", () => {
    const types: AuditEventType[] = [
      "tool_result_created", "result_guardian_decision", "tool_result_delivered", "capability_verified",
      "capability_rejected", "approval_verification_failed", "tool_result_withheld", "tool_call_requested",
      "guardian_decision", "human_approval", "human_rejection", "approval_requested", "approval_expired",
      "tool_execution_started", "tool_execution_completed", "tool_execution_blocked", "replay_rejected",
      "timestamp_rejected", "correlation_failed", "authority_revoked", "authority_revocation_enforced",
    ];
    expect(Object.keys(OCSF_METADATA_ALLOWLIST).sort()).toEqual([...types].sort());
    expect(Object.isFrozen(OCSF_METADATA_ALLOWLIST)).toBe(true);
  });
});

describe("OCSF mapping: real runtime audit streams", () => {
  it("exports and validates the audit stream of real allow, deny and replay flows", async () => {
    const { executor, audit } = setup(Date.now());
    const allow = makeRequest({ tool: "read_record", requestId: "ocsf-allow", sessionId: "ocsf-s" });
    await executor.process(allow);
    await expect(executor.process(allow)).rejects.toThrow(); // replay
    await expect(
      executor.process(makeRequest({ tool: "delete_record", requestId: "ocsf-deny", sessionId: "ocsf-s" }))
    ).rejects.toThrow();

    const events = audit.getEvents();
    const result = exportAuditToOcsf(events, { expectedHeadHash: audit.getHeadHash() });
    expect(result.events).toHaveLength(events.length);
    for (const e of result.events) {
      expect(validateOcsfEvent(e)).toEqual([]);
    }
    const types = result.events.map(e => [e.unmapped.acs.event_type, e.class_uid]);
    expect(types).toContainEqual(["replay_rejected", 2004]);
    expect(types).toContainEqual(["guardian_decision", 0]);
    expect(types).toContainEqual(["tool_execution_blocked", 0]);
    // The guardian deny itself is not a finding.
    const denies = result.events.filter(e => e.unmapped.acs.metadata?.decision === "deny");
    expect(denies.length).toBeGreaterThan(0);
    denies.forEach(e => expect(e.class_uid).toBe(0));
    expect(result.events.filter(e => e.class_uid === 2004)).toHaveLength(IncidentClassifier.fromAudit(events).length);
  });
});
