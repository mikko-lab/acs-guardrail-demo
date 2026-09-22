import { setup, makeRequest, fresh, toUuid, createAuthorityTestDeps } from "./evals/eval-setup";
import crypto from "crypto";

describe("Runtime Authority Enforcement (AUTHR-001..021)", () => {
  it("AUTHR-001 valid capability + Guardian ALLOW -> execution", async () => {
    const { executor, audit, clock } = setup(Date.now());
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);

    const result = await executor.process(req);

    expect((result as any).status).toBe("executed");
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "capability_verified")).toBe(true);
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "allow")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
  });

  it("AUTHR-002 missing capability -> blocked", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    capabilityProvider.returnNull = true;
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-2" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Missing capability/);

    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "capability_rejected")).toBe(true);
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });

  it("AUTHR-003 wrong agent -> blocked (AGENT_MISMATCH)", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    // Modify agent_id BEFORE signing: the wrong agent_id is validly signed, then rejected by authority context.
    capabilityProvider.tamperCapability = (cap) => ({ ...cap, agent_id: "wrong-agent" });
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-3" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

    const events = audit.getEvents();
    const rej = events.find(e => e.event_type === "capability_rejected");
    expect(rej).toBeDefined();
    // tamperCapability modifies BEFORE signing, so the signature is valid for the wrong agent_id
    // The verifier checks signature first (passes), then agent_id context (AGENT_MISMATCH)
    expect((rej as any)?.metadata.reason).toBe("capability_agent_mismatch");
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
  });

  it("AUTHR-004 wrong session -> blocked (SESSION_MISMATCH)", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    // preTamper: sign a capability with wrong session_id (valid sig, wrong session)
    capabilityProvider.tamperCapability = (cap) => ({ ...cap, session_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" });
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-4" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);
    const events = audit.getEvents();
    expect((events.find(e => e.event_type === "capability_rejected") as any)?.metadata.reason).toBe("capability_session_mismatch");
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
  });

  it("AUTHR-005 wrong tool -> blocked (TOOL_SCOPE_MISMATCH)", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    // preTamper: sign a capability with restricted allowed_tools (valid sig, missing requested tool)
    capabilityProvider.tamperCapability = (cap) => ({ ...cap, allowed_tools: ["other_tool"] });
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-5" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);
    const events = audit.getEvents();
    expect((events.find(e => e.event_type === "capability_rejected") as any)?.metadata.reason).toBe("capability_scope_mismatch");
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
  });

  it("AUTHR-006 expired capability -> blocked (EXPIRED)", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    // preTamper: sign a capability that has already expired.
    // Both issued_at and expires_at are in the past, but expires_at > issued_at (structurally valid).
    capabilityProvider.tamperCapability = (cap) => ({
      ...cap,
      issued_at: fresh(clock.nowMs(), -5000),   // 5s ago
      expires_at: fresh(clock.nowMs(), -1000),   // 1s ago — expired
    });
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-6" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);
    const events = audit.getEvents();
    expect((events.find(e => e.event_type === "capability_rejected") as any)?.metadata.reason).toBe("capability_expired");
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
  });


  it("AUTHR-007 not-yet-valid capability -> blocked (NOT_YET_VALID)", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    // preTamper: sign a capability with issued_at in the future (valid sig, not yet active)
    capabilityProvider.tamperCapability = (cap) => ({ ...cap, issued_at: fresh(clock.nowMs(), +10000), expires_at: fresh(clock.nowMs(), +20000) });
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-7" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);
    const events = audit.getEvents();
    expect((events.find(e => e.event_type === "capability_rejected") as any)?.metadata.reason).toBe("capability_not_yet_valid");
    expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
  });

  it("AUTHR-008 valid capability + Guardian DENY -> blocked", async () => {
    const { executor, audit, clock } = setup(Date.now());
    const req = makeRequest({ tool: "delete_record", sessionId: "sess-1", requestId: "req-8" }, clock);

    await expect(executor.process(req)).rejects.toThrow(/Execution blocked \(deny\)/);

    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "capability_verified")).toBe(true);
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "deny")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });


  it("AUTHR-009 ASK + correct ApprovalGrantV2 -> execution", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-9" }, clock);
    
    const res1 = await executor.process(req).catch(e => console.log("PROCESS ERROR:", e));
    expect((res1 as any).status).toBe("pending");
    
    const grant = testSigner.sign({
      version: 2, tool: "update_record", decision: "approve",
      session_id: (req.params.metadata as any).session_id, request_id: (req.params as any).request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });
    
    const res2 = await executor.resolveApproval(grant);
    expect((res2 as any)?.exit_status).toBe("success");
  });

  it("AUTHR-010 ASK + ApprovalGrantV1 -> blocked", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-10" }, clock);
    await executor.process(req).catch(e => { console.error("PROCESS ERROR IN TEST:", e); throw e; });
    
    const grantV1 = testSigner.sign({
      version: 1, decision: "approve",
      session_id: (req.params.metadata as any).session_id, request_id: (req.params as any).request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });
    
    await expect(executor.resolveApproval(grantV1)).rejects.toThrow(/Validation Error/);
    
    const events = audit.getEvents();
    expect((events.find(e => e.event_type === "approval_verification_failed") as any)?.metadata.reason).toBe("v1_rejected");
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    
    // pending preserved
    const grantV2 = testSigner.sign({
      version: 2, tool: "update_record", decision: "approve",
      session_id: (req.params.metadata as any).session_id, request_id: (req.params as any).request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });
    const res = await executor.resolveApproval(grantV2);
    expect((res as any)?.exit_status).toBe("success");
  });

  it("AUTHR-011 ASK + wrong-tool V2 -> blocked AND pending preserved, then correct V2 -> exactly one execution", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({
      tool: "update_record",
      sessionId: "sess-1",
      requestId: "req-11"
    }, clock);

    await executor.process(req);

    const wrongGrant = testSigner.sign({
      version: 2,
      tool: "read_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });

    await expect(
      executor.resolveApproval(wrongGrant)
    ).rejects.toThrow(/tool does not match/);

    let events = audit.getEvents();
    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(0);

    const correctGrant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });

    const result = await executor.resolveApproval(correctGrant);
    expect((result as any)?.exit_status).toBe("success");

    events = audit.getEvents();
    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(1);
  });

  it("AUTHR-012 ASK + tool tampered after signing -> invalid signature, pending preserved", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({
      tool: "update_record",
      sessionId: "sess-1",
      requestId: "req-12"
    }, clock);

    await executor.process(req);

    const correctGrant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });

    const tamperedGrant = {
      ...correctGrant,
      tool: "delete_record"
    };

    await expect(
      executor.resolveApproval(tamperedGrant)
    ).rejects.toThrow(/Invalid signature/);

    let events = audit.getEvents();
    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(0);

    const result = await executor.resolveApproval(correctGrant);
    expect((result as any)?.exit_status).toBe("success");

    events = audit.getEvents();
    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(1);
  });

  it("AUTHR-013 ASK + expired pending + otherwise valid V2 -> blocked", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({
      tool: "update_record",
      sessionId: "sess-1",
      requestId: "req-13"
    }, clock);

    await executor.process(req);

    clock.currentMs += 1000 * 60 * 20;

    const grant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });

    await expect(
      executor.resolveApproval(grant)
    ).rejects.toThrow(/expired/);

    let events = audit.getEvents();

    expect(
      events.some(e => e.event_type === "approval_expired")
    ).toBe(true);

    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(0);

    await expect(
      executor.resolveApproval(grant)
    ).rejects.toThrow(/No pending action found/);

    events = audit.getEvents();

    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(0);
  });

  it("AUTHR-014 ASK + reject V2 -> no execution and retry approve fails", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-14" }, clock);
    await executor.process(req).catch(e => { console.error("PROCESS ERROR IN TEST:", e); throw e; });
    
    const grantReject = testSigner.sign({
      version: 2, tool: "update_record", decision: "reject",
      session_id: (req.params.metadata as any).session_id, request_id: (req.params as any).request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });
    
    await executor.resolveApproval(grantReject);
    expect(audit.getEvents().some(e => e.event_type === "human_rejection")).toBe(true);
    expect(audit.getEvents().some(e => e.event_type === "tool_execution_started")).toBe(false);
    
    const grantApprove = testSigner.sign({
      version: 2, tool: "update_record", decision: "approve",
      session_id: (req.params.metadata as any).session_id, request_id: (req.params as any).request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });
    await expect(executor.resolveApproval(grantApprove)).rejects.toThrow(/No pending action found/);
  });

  it("AUTHR-015 CapabilityProvider throws -> blocked", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    capabilityProvider.forceThrow = true;
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-15" }, clock);
    
    await expect(executor.process(req)).rejects.toThrow(/Capability provider error/);
    expect(audit.getEvents().some(e => e.event_type === "tool_execution_started")).toBe(false);
  });

  it("AUTHR-016 replay -> provider NOT called on replayed request", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-16" }, clock);

    await executor.process(req);
    expect(capabilityProvider.resolveCalled).toBe(1);

    // Replay the same request — ReplayGuard fires before capability check
    await expect(executor.process(req)).rejects.toThrow();  // ReplayGuardError
    // Provider must NOT be called again on replay (replay gate fires first)
    expect(capabilityProvider.resolveCalled).toBe(1);
  });

  it("AUTHR-017 invalid request signature -> provider NEVER called", async () => {
    const { executor, capabilityProvider, clock } = setup(Date.now());
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-17" }, clock);
    (req as any).signature = "invalid";

    await expect(executor.process(req)).rejects.toThrow();
    expect(capabilityProvider.resolveCalled).toBe(0);
  });

  it("AUTHR-018 valid capability + Guardian ALLOW + Result Guardian DENY -> result withheld", async () => {
    const { executor, guardian, audit, clock } = setup(Date.now());

    const originalEvaluateResult = guardian.evaluateResult.bind(guardian);

    guardian.evaluateResult = jest.fn().mockImplementation((request) => ({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        type: "final",
        acs_version: "0.1.0",
        request_id: request.params.request_id,
        decision: "deny",
        reasoning: "Blocked by result policy",
        reason_codes: ["blocked_data"]
      }
    }));

    try {
      const req = makeRequest({
        tool: "read_record",
        sessionId: "sess-1",
        requestId: "req-18"
      }, clock);

      const result = await executor.process(req);

      expect(result.status).toBe("executed");

      if (result.status !== "executed") {
        throw new Error("Expected executed result");
      }

      expect(result.result.exit_status).toBe("blocked");

      const events = audit.getEvents();

      expect(
        events.some(e => e.event_type === "capability_verified")
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "tool_execution_started")
      ).toBe(true);

      expect(
        events.some(
          e =>
            e.event_type === "result_guardian_decision" &&
            e.metadata?.decision === "deny"
        )
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "tool_result_withheld")
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "tool_result_delivered")
      ).toBe(false);
    } finally {
      guardian.evaluateResult = originalEvaluateResult;
    }
  });

  it("AUTHR-019 SAME signed capability reused for TWO distinct request_ids", async () => {
    const { executor, audit, clock, capabilityProvider } = setup(Date.now());

    const req1 = makeRequest({
      tool: "read_record",
      sessionId: "sess-1",
      requestId: "req-19a"
    }, clock);

    const req2 = makeRequest({
      tool: "read_record",
      sessionId: "sess-1",
      requestId: "req-19b"
    }, clock);

    expect(req1.params.request_id).not.toBe(req2.params.request_id);

    const cap = capabilityProvider.resolve({
      agent_id: req1.params.metadata.agent_id,
      session_id: req1.params.metadata.session_id,
      request_id: req1.params.request_id,
      tool: "read_record"
    });

    if (
      !cap ||
      typeof cap !== "object" ||
      !("capability_id" in cap) ||
      typeof cap.capability_id !== "string"
    ) {
      throw new Error("Expected signed capability with capability_id");
    }

    const capabilityId = cap.capability_id;

    // CapabilityGrantV1 is deliberately reusable within the same
    // agent/session/tool/time scope. capability_id is not a nonce.
    capabilityProvider.fixedCapability = cap;

    const result1 = await executor.process(req1);
    const result2 = await executor.process(req2);

    expect(result1.status).toBe("executed");
    expect(result2.status).toBe("executed");

    const capabilityEvents = audit
      .getEvents()
      .filter(e => e.event_type === "capability_verified");

    expect(capabilityEvents).toHaveLength(2);

    expect(capabilityEvents[0].metadata?.capability_id).toBe(capabilityId);
    expect(capabilityEvents[1].metadata?.capability_id).toBe(capabilityId);

    expect(capabilityEvents[0].request_id).not.toBe(
      capabilityEvents[1].request_id
    );
  });

  it("AUTHR-021 validly signed wrong approver -> blocked, pending preserved, correct approver executes once", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());

    const req = makeRequest({
      tool: "update_record",
      sessionId: "sess-1",
      requestId: "req-21"
    }, clock);

    const pending = await executor.process(req);
    expect((pending as any).status).toBe("pending");

    const wrongApproverGrant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "another-human" },
      issued_at: fresh(clock.nowMs())
    });

    await expect(
      executor.resolveApproval(wrongApproverGrant)
    ).rejects.toThrow(/approver does not match expected approver/);

    let events = audit.getEvents();

    expect(
      events.some(
        e =>
          e.event_type === "approval_verification_failed" &&
          e.metadata?.reason === "wrong_approver_identity"
      )
    ).toBe(true);

    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(0);

    const correctGrant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs())
    });

    const result = await executor.resolveApproval(correctGrant);
    expect((result as any)?.exit_status).toBe("success");

    events = audit.getEvents();

    expect(
      events.filter(e => e.event_type === "tool_execution_started")
    ).toHaveLength(1);
  });

  it("AUTHR-020 capability_verified + Guardian DENY -> no execution", async () => {
    const { executor, audit, clock } = setup(Date.now());
    const req = makeRequest({ tool: "delete_record", sessionId: "sess-1", requestId: "req-20" }, clock);
    
    await expect(executor.process(req)).rejects.toThrow(/Execution blocked \(deny\)/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "capability_verified")).toBe(true);
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "deny")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });
});

