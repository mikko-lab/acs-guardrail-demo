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

  describe("Authority Incident Runtime Integration (WP-07B)", () => {
    it("REAL-AUTH-001: invalid capability signature produces authentication incident from runtime evidence", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.postTamperCapability = cap => ({
        ...cap,
        agent_id: "tampered-after-signing"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "real-auth-1",
        requestId: "real-auth-001"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_authentication_failure");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);

      // Incident context must come from trusted runtime audit context.
      expect(incidents[0].agent_id).toBe(req.params.metadata.agent_id);
      expect(incidents[0].session_id).toBe(req.params.metadata.session_id);
      expect(incidents[0].tool).toBe("read_record");
      expect(incidents[0].reason).toBe("capability_authentication_failed");
      expect(incidents[0].source_event_type).toBe("capability_rejected");
    });

    it("REAL-AUTH-002: validly signed wrong-agent capability produces boundary incident", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        agent_id: "spoofed-agent"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "real-auth-2",
        requestId: "real-auth-002"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].reason).toBe("capability_agent_mismatch");
      expect(incidents[0].agent_id).toBe(req.params.metadata.agent_id);
      expect(incidents[0].agent_id).not.toBe("spoofed-agent");
    });

    it("REAL-AUTH-003: validly signed wrong-session capability produces boundary incident", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        session_id: "spoofed-session"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "real-auth-3",
        requestId: "real-auth-003"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].reason).toBe("capability_session_mismatch");
      expect(incidents[0].session_id).toBe(req.params.metadata.session_id);
      expect(incidents[0].session_id).not.toBe("spoofed-session");
    });

    it("REAL-AUTH-004: capability tool-scope mismatch produces boundary incident", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        allowed_tools: ["delete_record"]
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "real-auth-4",
        requestId: "real-auth-004"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].reason).toBe("capability_scope_mismatch");
      expect(incidents[0].tool).toBe("read_record");
    });

    it("REAL-AUTH-005: tampered ApprovalGrantV2 produces authentication incident and preserves trusted tool context", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "real-auth-5",
        requestId: "real-auth-005"
      }, clock);

      await executor.process(req);

      const validGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: new Date(clock.nowMs()).toISOString()
      });

      const tamperedGrant = {
        ...validGrant,
        tool: "delete_record"
      };

      await expect(
        executor.resolveApproval(tamperedGrant)
      ).rejects.toThrow(/Invalid signature/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_authentication_failure");
      expect(incidents[0].reason).toBe("invalid_signature");
      expect(incidents[0].session_id).toBe(req.params.metadata.session_id);

      // expected_tool from PendingAction is normalized into incident.tool.
      expect(incidents[0].tool).toBe("update_record");
    });

    it("REAL-AUTH-006: validly signed wrong-tool approval produces boundary incident", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "real-auth-6",
        requestId: "real-auth-006"
      }, clock);

      await executor.process(req);

      const wrongToolGrant = testSigner.sign({
        version: 2,
        tool: "read_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: new Date(clock.nowMs()).toISOString()
      });

      await expect(
        executor.resolveApproval(wrongToolGrant)
      ).rejects.toThrow(/tool does not match/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].reason).toBe("tool_binding_mismatch");
      expect(incidents[0].tool).toBe("update_record");
    });

    it("REAL-AUTH-007: validly signed wrong approver produces boundary incident without spoofed identity evidence", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "real-auth-7",
        requestId: "real-auth-007"
      }, clock);

      await executor.process(req);

      const wrongApproverGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "spoofed-human" },
        issued_at: new Date(clock.nowMs()).toISOString()
      });

      await expect(
        executor.resolveApproval(wrongApproverGrant)
      ).rejects.toThrow(/approver does not match expected approver/);

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].reason).toBe("wrong_approver_identity");
      expect(incidents[0].tool).toBe("update_record");

      expect(JSON.stringify(incidents[0])).not.toContain("spoofed-human");
    });

    it("REAL-AUTH-008: operational capability rejection does not become a security incident", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.returnNull = true;

      const req = makeRequest({
        tool: "read_record",
        sessionId: "real-auth-8",
        requestId: "real-auth-008"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Missing capability/);

      const authorityEvents = audit.getEvents().filter(
        e => e.event_type === "capability_rejected"
      );

      expect(authorityEvents).toHaveLength(1);
      expect(authorityEvents[0].metadata?.reason).toBe("missing_capability");

      const incidents = IncidentClassifier.fromAudit(audit.getEvents());
      expect(incidents).toHaveLength(0);
    });
  });


  describe("Authority Incident Mapping (WP-07B)", () => {
    it("AIM-001: invalid capability signature -> authentication incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("capability_rejected", "aim-1", {
          agent_id: "agent-a",
          session_id: "sess-a",
          tool: "read_record",
          reason: "capability_authentication_failed"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_authentication_failure");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);
      expect(incidents[0].disposition).toBe("blocked");
      expect(incidents[0].agent_id).toBe("agent-a");
      expect(incidents[0].tool).toBe("read_record");
    });

    it("AIM-002: capability agent mismatch -> authority boundary incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("capability_rejected", "aim-2", {
          agent_id: "trusted-agent",
          session_id: "sess-a",
          tool: "read_record",
          reason: "capability_agent_mismatch"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);
      expect(incidents[0].agent_id).toBe("trusted-agent");
    });

    it("AIM-003: capability session mismatch -> authority boundary incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("capability_rejected", "aim-3", {
          agent_id: "agent-a",
          session_id: "trusted-session",
          tool: "read_record",
          reason: "capability_session_mismatch"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].session_id).toBe("trusted-session");
    });

    it("AIM-004: capability scope mismatch -> authority boundary incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("capability_rejected", "aim-4", {
          agent_id: "agent-a",
          session_id: "sess-a",
          tool: "update_record",
          reason: "capability_scope_mismatch"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].tool).toBe("update_record");
    });

    it("AIM-005: operational and policy capability failures are not security incidents", () => {
      const reasons = [
        "missing_capability",
        "capability_provider_error",
        "capability_expired",
        "capability_not_yet_valid",
        "capability_malformed",
        "capability_unsupported_scope",
        "capability_verification_failed",
      ];

      for (const reason of reasons) {
        const incidents = IncidentClassifier.fromAudit([
          baseEvent("capability_rejected", `aim-cap-${reason}`, {
            agent_id: "agent-a",
            session_id: "sess-a",
            tool: "read_record",
            reason
          }),
        ]);

        expect(incidents).toHaveLength(0);
      }
    });

    it("AIM-006: invalid approval signature -> authentication incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("approval_verification_failed", "aim-6", {
          session_id: "sess-a",
          expected_tool: "update_record",
          reason: "invalid_signature"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_authentication_failure");
      expect(incidents[0].severity).toBe("high");
      expect(incidents[0].requires_human_review).toBe(true);
      expect(incidents[0].tool).toBe("update_record");
    });

    it("AIM-007: approval tool binding mismatch -> authority boundary incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("approval_verification_failed", "aim-7", {
          session_id: "sess-a",
          expected_tool: "update_record",
          reason: "tool_binding_mismatch"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].tool).toBe("update_record");
    });

    it("AIM-008: wrong approver identity -> authority boundary incident", () => {
      const incidents = IncidentClassifier.fromAudit([
        baseEvent("approval_verification_failed", "aim-8", {
          session_id: "sess-a",
          expected_tool: "update_record",
          reason: "wrong_approver_identity"
        }),
      ]);

      expect(incidents).toHaveLength(1);
      expect(incidents[0].incident_type).toBe("authority_boundary_violation");
      expect(incidents[0].requires_human_review).toBe(true);
    });

    it("AIM-009: non-security and runtime-unreachable approval reasons are not incidents", () => {
      const reasons = [
        "missing_ids",
        "pending_action_not_found",
        "v1_rejected",
        "malformed_grant",
        "session_mismatch",
        "request_mismatch",
        "approval_verification_failed",
      ];

      for (const reason of reasons) {
        const incidents = IncidentClassifier.fromAudit([
          baseEvent("approval_verification_failed", `aim-app-${reason}`, {
            session_id: "sess-a",
            expected_tool: "update_record",
            reason
          }),
        ]);

        expect(incidents).toHaveLength(0);
      }
    });

    it("AIM-009A: legacy incident fingerprint remains backward-compatible", () => {
      const timestamp = "2026-09-22T12:00:00.000Z";

      const event = {
        ...baseEvent("replay_rejected", "legacy-request", {
          session_id: "legacy-session",
          reason_code: "REPLAY_DETECTED"
        }),
        timestamp
      };

      const incidents = IncidentClassifier.fromAudit([event]);

      expect(incidents).toHaveLength(1);

      const { createHash } = require("crypto");
      const legacySerialized = JSON.stringify([
        "replay_rejected",
        timestamp,
        "legacy-session",
        "legacy-request",
        "",
        "",
        "REPLAY_DETECTED",
        ""
      ]);

      const expectedFingerprint = createHash("sha256")
        .update(legacySerialized)
        .digest("hex");

      expect(
        incidents[0].evidence_refs[0].source_fingerprint
      ).toBe(expectedFingerprint);

      expect(incidents[0].incident_id).toBe(
        `INC-${expectedFingerprint}-1`
      );
    });

    it("AIM-010: trusted authority context participates in incident identity", () => {
      const timestamp = new Date().toISOString();

      const eventA = {
        ...baseEvent("capability_rejected", "shared-request", {
          agent_id: "agent-A",
          session_id: "shared-session",
          tool: "read_record",
          reason: "capability_agent_mismatch"
        }),
        timestamp
      };

      const eventB = {
        ...baseEvent("capability_rejected", "shared-request", {
          agent_id: "agent-B",
          session_id: "shared-session",
          tool: "read_record",
          reason: "capability_agent_mismatch"
        }),
        timestamp
      };

      const incidentA = IncidentClassifier.fromAudit([eventA])[0];
      const incidentB = IncidentClassifier.fromAudit([eventB])[0];

      expect(incidentA.incident_id).not.toBe(incidentB.incident_id);
      expect(incidentA.agent_id).toBe("agent-A");
      expect(incidentB.agent_id).toBe("agent-B");

      const approvalA = {
        ...baseEvent("approval_verification_failed", "shared-approval", {
          session_id: "shared-session",
          expected_tool: "read_record",
          reason: "tool_binding_mismatch"
        }),
        timestamp
      };

      const approvalB = {
        ...baseEvent("approval_verification_failed", "shared-approval", {
          session_id: "shared-session",
          expected_tool: "update_record",
          reason: "tool_binding_mismatch"
        }),
        timestamp
      };

      const approvalIncidentA = IncidentClassifier.fromAudit([approvalA])[0];
      const approvalIncidentB = IncidentClassifier.fromAudit([approvalB])[0];

      expect(approvalIncidentA.incident_id).not.toBe(approvalIncidentB.incident_id);
      expect(approvalIncidentA.tool).toBe("read_record");
      expect(approvalIncidentB.tool).toBe("update_record");
    });
  });

});
