import { AuditEvent } from "../src/acs-types";
import { IncidentClassifier, IncidentEnvelopeV1 } from "../src/incident-evidence";
import { setup, makeRequest, toUuid } from "./evals/eval-setup";
import { tools } from "../src/tools";

describe("IncidentClassifier (WP-05)", () => {
  const baseEvent = (type: string, reqId: string, meta: Record<string, unknown> = {}): AuditEvent => ({
    timestamp: new Date().toISOString(),
    request_id: reqId,
    event_type: type as any,
    metadata: meta,
  });

  describe("Unit Tests (V1 Spec)", () => {
    it("INC-001: DENY policy decision does not create an incident", () => {
      const events = [
        baseEvent("guardian_decision", "req-1", { decision: "deny" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(0);
    });

    it("INC-002: Same-session replay attempt produces HIGH incident with review trigger", () => {
      const events = [
        baseEvent("replay_rejected", "req-2", { session_id: "sess-1", reason_code: "REPLAY_DETECTED" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("replay_attempt");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);
      expect(incidents[0].disposition).toBe("blocked");
      expect(incidents[0].detected_at).toBe(events[0].timestamp); // Consistency check
    });

    it("INC-003: Unknown correlation reference produces correlation incident", () => {
      const events = [
        baseEvent("correlation_failed", "req-3", { 
          session_id: "sess-1", 
          request_id_ref: "req-ref", 
          reason: "unresolved_request_id_ref" 
        }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("correlation_failure");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);
    });

    it("INC-006: Result gate DENY produces result_policy_violation incident (decision === deny)", () => {
      const events = [
        baseEvent("result_guardian_decision", "req-6", { decision: "deny" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("result_policy_violation");
      expect(incidents[0].severity).toBe("medium");
      expect(incidents[0].requires_human_review).toBe(false);
    });

    it("INC-007: Human rejection does not produce a security incident", () => {
      const events = [
        baseEvent("human_rejection", "req-7", { session_id: "sess-1" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(0);
    });

    it("INC-008: Approval expiry does not produce a security incident", () => {
      const events = [
        baseEvent("approval_expired", "req-8", { session_id: "sess-1" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(0);
    });

    it("INC-009: Two sessions with same request_id are isolated correctly", () => {
      const events = [
        baseEvent("replay_rejected", "req-shared", { session_id: "sess-A" }),
        baseEvent("replay_rejected", "req-shared", { session_id: "sess-B" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(2);
      expect(incidents[0].incident_id).not.toBe(incidents[1].incident_id);
      expect(incidents[0].session_id).toBe("sess-A");
      expect(incidents[1].session_id).toBe("sess-B");
      expect(incidents[0].evidence_refs[0].source_fingerprint).not.toBe(incidents[1].evidence_refs[0].source_fingerprint);
    });

    it("Duplicate policy: Identical source events produce unique incidents via occurrence index", () => {
      const event = baseEvent("correlation_failed", "req-dup", { session_id: "sess-1" });
      const events = [event, event];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(2);
      expect(incidents[0].incident_id).not.toBe(incidents[1].incident_id);
      expect(incidents[0].evidence_refs[0].source_fingerprint).toBe(incidents[1].evidence_refs[0].source_fingerprint);
      expect(incidents[0].evidence_refs[0].occurrence_index).toBe(1);
      expect(incidents[1].evidence_refs[0].occurrence_index).toBe(2);
    });

    it("Ordering: Unrelated events do not change incident identity", () => {
      const secEvent = baseEvent("correlation_failed", "req-dup", { session_id: "sess-1" });
      const unrelated = baseEvent("guardian_decision", "req-unrelated", { decision: "allow" });
      
      const incidentsA = IncidentClassifier.fromAudit([secEvent]);
      const incidentsB = IncidentClassifier.fromAudit([unrelated, secEvent]);
      
      expect(incidentsA[0].incident_id).toBe(incidentsB[0].incident_id);
    });

    it("Timestamp rejection maps to request_freshness_violation", () => {
      const events = [
        baseEvent("timestamp_rejected", "req-time", { reason_code: "TIMESTAMP_OUT_OF_WINDOW" }),
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("request_freshness_violation");
      expect(incidents[0].severity).toBe("medium");
    });
    
    it("Malformed/unknown audit event is ignored safely", () => {
      const events = [
        baseEvent("unknown_event_type_xyz", "req-10") as any,
      ];
      const incidents = IncidentClassifier.fromAudit(events);
      expect(incidents).toHaveLength(0);
    });

    it("Missing or invalid timestamp -> 0 incidents", () => {
      const event1: AuditEvent = { ...baseEvent("replay_rejected", "req-1", { reason_code: "REPLAY_DETECTED" }) };
      delete (event1 as any).timestamp; // missing

      const event2: AuditEvent = { ...baseEvent("correlation_failed", "req-2", { reason: "unresolved_request_id_ref" }) };
      event2.timestamp = "invalid-date-string"; // invalid

      const incidents = IncidentClassifier.fromAudit([event1, event2]);
      expect(incidents).toHaveLength(0);
    });

    it("Fingerprint Collision Structure: structural serialization prevents delimiter ambiguity attacks", () => {
      const ts = new Date().toISOString();
      
      // Event 1: tool="my|tool", reason="some_reason"
      const event1: AuditEvent = {
        timestamp: ts,
        request_id: "req-1",
        event_type: "correlation_failed",
        metadata: { tool: "my|tool", reason: "some_reason" }
      };

      // Event 2: tool="my", reason="tool|some_reason"
      const event2: AuditEvent = {
        timestamp: ts,
        request_id: "req-1",
        event_type: "correlation_failed",
        metadata: { tool: "my", reason: "tool|some_reason" }
      };

      // Using join("|"), these would produce the same fingerprint: ...|my|tool|some_reason|...
      // Using JSON.stringify([]), they must produce different fingerprints.
      const incidents = IncidentClassifier.fromAudit([event1, event2]);
      expect(incidents).toHaveLength(2);
      expect(incidents[0].evidence_refs[0].source_fingerprint).not.toBe(incidents[1].evidence_refs[0].source_fingerprint);
      expect(incidents[0].incident_id).not.toBe(incidents[1].incident_id);
    });
  });

  describe("Real Runtime Integration Tests", () => {
    const BASE_TIME = Date.now();

    it("REAL-REPLAY: Incident from ReplayGuard replay_rejected", async () => {
      const { executor, audit } = setup(BASE_TIME);
      const req = makeRequest({ tool: "read_record", sessionId: "sess-replay", requestId: "req-replay-1" });
      
      await executor.process(req); // first OK
      
      await expect(executor.process(req)).rejects.toThrow(); // second fails

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());
      const replays = incidents.filter(i => i.incident_type === "replay_attempt");
      expect(replays).toHaveLength(1);
      expect(replays[0].severity).toBe("high");
      expect(replays[0].requires_human_review).toBe(true);
    });

    it("REAL-CORRELATION COMPONENT INTEGRATION: Incident from missing execution correlation", async () => {
      const { correlation, audit } = setup(BASE_TIME);
      
      const ctx = { audit, resultRequestId: "res-1", sessionId: "sess-1", tool: "read_record" };
      expect(() => correlation.validateAndConsume("sess-1", "unknown-ref", "read_record", ctx)).toThrow();
      
      const incidents = IncidentClassifier.fromAudit(audit.getEvents());
      const correlates = incidents.filter(i => i.incident_type === "correlation_failure");
      expect(correlates).toHaveLength(1);
      expect(correlates[0].severity).toBe("high");
    });

    it("REAL-RESULT-DENY: Incident from result_guardian_decision DENY", async () => {
      const { executor, audit } = setup(BASE_TIME);
      const req = makeRequest({ tool: "read_record", sessionId: "sess-result", requestId: "req-result-1" });
      
      const originalTool = tools["read_record"];
      try {
        tools["read_record"] = async () => ({ classification: "restricted", data: "secret" });
        await executor.process(req);
      } finally {
        tools["read_record"] = originalTool;
      }
      
      const incidents = IncidentClassifier.fromAudit(audit.getEvents());
      const blocks = incidents.filter(i => i.incident_type === "result_policy_violation");
      expect(blocks).toHaveLength(1);
      expect(blocks[0].severity).toBe("medium");
      expect(blocks[0].requires_human_review).toBe(false);
    });
    
    it("NORMAL OVERSIGHT INTEGRATION: ASK -> human rejection produces 0 incidents", async () => {
      const { executor, audit, testSigner } = setup(BASE_TIME);
      
      const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-1" });
      
      await executor.process(req); // -> PENDING
      
      const grant = testSigner.sign({
        version: 2, tool: req.params.payload.tool.name,
        decision: "reject",
        session_id: toUuid("sess-ask"),
        request_id: toUuid("req-ask-1"),
        approver: { type: "human", id: "demo-operator" },
        issued_at: new Date().toISOString()
      });
      
      await executor.resolveApproval(grant); // -> REJECTED
      
      const incidents = IncidentClassifier.fromAudit(audit.getEvents());
      expect(incidents).toHaveLength(0);
    });
  });
});
