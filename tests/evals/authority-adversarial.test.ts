import { setup, makeRequest, fresh } from "./eval-setup";

describe("Authority Adversarial Evaluation (WP-07A)", () => {
  describe("Capability boundary evidence", () => {
    it("AEV-001 invalid capability signature -> authentication rejection before Guardian", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.postTamperCapability = cap => ({
        ...cap,
        agent_id: "tampered-after-signing"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-1",
        requestId: "aev-001"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_authentication_failed");
      expect(rejected?.metadata?.agent_id).toBe(req.params.metadata.agent_id);
      expect(rejected?.metadata?.session_id).toBe(req.params.metadata.session_id);
      expect(rejected?.metadata?.tool).toBe("read_record");

      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-002 validly signed wrong agent -> trusted request context retained", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        agent_id: "spoofed-agent"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-2",
        requestId: "aev-002"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_agent_mismatch");

      // Trusted evidence comes from the authenticated request,
      // not the mismatching capability.
      expect(rejected?.metadata?.agent_id).toBe(req.params.metadata.agent_id);
      expect(rejected?.metadata?.agent_id).not.toBe("spoofed-agent");

      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-003 validly signed wrong session -> trusted request session retained", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        session_id: "spoofed-session"
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-3",
        requestId: "aev-003"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_session_mismatch");
      expect(rejected?.metadata?.session_id).toBe(req.params.metadata.session_id);
      expect(rejected?.metadata?.session_id).not.toBe("spoofed-session");

      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-004 validly signed capability without requested tool -> scope rejection", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        allowed_tools: ["delete_record"]
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-4",
        requestId: "aev-004"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_scope_mismatch");
      expect(rejected?.metadata?.tool).toBe("read_record");

      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-005 expired valid capability -> rejected before Guardian", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        issued_at: fresh(clock.nowMs(), -2000),
        expires_at: fresh(clock.nowMs(), -1000)
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-5",
        requestId: "aev-005"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_expired");
      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-006 not-yet-valid capability -> rejected before Guardian", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.tamperCapability = cap => ({
        ...cap,
        issued_at: fresh(clock.nowMs(), 1000),
        expires_at: fresh(clock.nowMs(), 2000)
      });

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-6",
        requestId: "aev-006"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability rejected/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_not_yet_valid");
      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-007 missing capability -> fail closed before Guardian", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.returnNull = true;

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-7",
        requestId: "aev-007"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Missing capability/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("missing_capability");
      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-008 provider failure -> safe audit evidence and no Guardian", async () => {
      const { executor, audit, clock, capabilityProvider } = setup(Date.now());

      capabilityProvider.forceThrow = true;

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-8",
        requestId: "aev-008"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Capability provider error/);

      const events = audit.getEvents();
      const rejected = events.find(e => e.event_type === "capability_rejected");

      expect(rejected?.metadata?.reason).toBe("capability_provider_error");
      expect(JSON.stringify(rejected?.metadata)).not.toContain("Mock provider error");

      expect(events.some(e => e.event_type === "guardian_decision")).toBe(false);
      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });

    it("AEV-009 valid capability + Guardian DENY -> capability is not execution authorization", async () => {
      const { executor, audit, clock } = setup(Date.now());

      const req = makeRequest({
        tool: "delete_record",
        sessionId: "aev-9",
        requestId: "aev-009"
      }, clock);

      await expect(executor.process(req)).rejects.toThrow(/Execution blocked/);

      const events = audit.getEvents();

      expect(events.some(e => e.event_type === "capability_verified")).toBe(true);
      expect(
        events.some(
          e =>
            e.event_type === "guardian_decision" &&
            e.metadata?.decision === "deny"
        )
      ).toBe(true);

      expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    });
  });

  describe("Approval, ordering and result authority evidence", () => {
    it("AEV-010 ASK + ApprovalGrantV1 -> v1_rejected, pending preserved, V2 executes once", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "aev-10",
        requestId: "aev-010"
      }, clock);

      const pending = await executor.process(req);
      expect(pending.status).toBe("pending");

      const v1 = testSigner.sign({
        version: 1,
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await expect(executor.resolveApproval(v1)).rejects.toThrow();

      let events = audit.getEvents();

      expect(
        events.some(
          e =>
            e.event_type === "approval_verification_failed" &&
            e.metadata?.reason === "v1_rejected"
        )
      ).toBe(true);

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(0);

      const v2 = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await executor.resolveApproval(v2);

      events = audit.getEvents();

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });

    it("AEV-011 ASK + validly signed wrong-tool V2 -> mismatch, pending preserved, correct V2 executes once", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "aev-11",
        requestId: "aev-011"
      }, clock);

      await executor.process(req);

      const wrongToolGrant = testSigner.sign({
        version: 2,
        tool: "read_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await expect(
        executor.resolveApproval(wrongToolGrant)
      ).rejects.toThrow(/tool does not match/);

      let events = audit.getEvents();

      const failure = events.find(
        e =>
          e.event_type === "approval_verification_failed" &&
          e.metadata?.reason === "tool_binding_mismatch"
      );

      expect(failure).toBeDefined();
      expect(failure?.metadata?.session_id).toBe(
        req.params.metadata.session_id
      );
      expect(failure?.metadata?.expected_tool).toBe("update_record");

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

      await executor.resolveApproval(correctGrant);

      events = audit.getEvents();

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });

    it("AEV-012 ASK + V2 tampered after signing -> invalid_signature, pending preserved", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "aev-12",
        requestId: "aev-012"
      }, clock);

      await executor.process(req);

      const validGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      const tamperedGrant = {
        ...validGrant,
        tool: "delete_record"
      };

      await expect(
        executor.resolveApproval(tamperedGrant)
      ).rejects.toThrow(/Invalid signature/);

      let events = audit.getEvents();

      expect(
        events.some(
          e =>
            e.event_type === "approval_verification_failed" &&
            e.metadata?.reason === "invalid_signature"
        )
      ).toBe(true);

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(0);

      await executor.resolveApproval(validGrant);

      events = audit.getEvents();

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });

    it("AEV-013 ASK + validly signed wrong approver -> trusted evidence, pending preserved", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "aev-13",
        requestId: "aev-013"
      }, clock);

      await executor.process(req);

      const wrongApproverGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "spoofed-human" },
        issued_at: fresh(clock.nowMs())
      });

      await expect(
        executor.resolveApproval(wrongApproverGrant)
      ).rejects.toThrow(/approver does not match expected approver/);

      let events = audit.getEvents();

      const failure = events.find(
        e =>
          e.event_type === "approval_verification_failed" &&
          e.metadata?.reason === "wrong_approver_identity"
      );

      expect(failure).toBeDefined();
      expect(failure?.metadata?.session_id).toBe(
        req.params.metadata.session_id
      );
      expect(failure?.metadata?.expected_tool).toBe("update_record");

      // Spoofed approver identity must not become trusted audit evidence.
      expect(JSON.stringify(failure?.metadata)).not.toContain("spoofed-human");

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

      await executor.resolveApproval(correctGrant);

      events = audit.getEvents();

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });

    it("AEV-014 expired pending approval -> expiry evidence, removal, no resurrection", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "aev-14",
        requestId: "aev-014"
      }, clock);

      await executor.process(req);

      clock.currentMs += 20 * 60 * 1000;

      const grant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await expect(executor.resolveApproval(grant)).rejects.toThrow(/expired/);

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

    it("AEV-015 replay is rejected before capability resolution", async () => {
      const { executor, clock, capabilityProvider } = setup(Date.now());

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-15",
        requestId: "aev-015"
      }, clock);

      await executor.process(req);
      expect(capabilityProvider.resolveCalled).toBe(1);

      await expect(executor.process(req)).rejects.toThrow();

      expect(capabilityProvider.resolveCalled).toBe(1);
    });

    it("AEV-016 invalid request signature is rejected before capability lookup", async () => {
      const { executor, clock, capabilityProvider } = setup(Date.now());

      const req = makeRequest({
        tool: "read_record",
        sessionId: "aev-16",
        requestId: "aev-016"
      }, clock);

      (req as any).signature = "invalid";

      await expect(executor.process(req)).rejects.toThrow();

      expect(capabilityProvider.resolveCalled).toBe(0);
    });

    it("AEV-017 capability + request ALLOW + execution + result DENY -> withheld, not delivered", async () => {
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
          sessionId: "aev-17",
          requestId: "aev-017"
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

    it("AEV-018 unknown approval -> pending_action_not_found without mutating unrelated pending action", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const realRequest = makeRequest({
        tool: "update_record",
        sessionId: "aev-18-real",
        requestId: "aev-018-real"
      }, clock);

      await executor.process(realRequest);

      const unknownGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: "unknown-session",
        request_id: "unknown-request",
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await expect(
        executor.resolveApproval(unknownGrant)
      ).rejects.toThrow(/No pending action found/);

      let events = audit.getEvents();

      expect(
        events.some(
          e =>
            e.event_type === "approval_verification_failed" &&
            e.metadata?.reason === "pending_action_not_found"
        )
      ).toBe(true);

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(0);

      // The unrelated legitimate pending action must remain intact.
      const correctGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: realRequest.params.metadata.session_id,
        request_id: realRequest.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await executor.resolveApproval(correctGrant);

      events = audit.getEvents();

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });
  });

  describe("Normal authority and oversight controls", () => {
    it("NORMAL-001 valid capability + Guardian ALLOW + result ALLOW -> no authority failure events", async () => {
      const { executor, audit, clock } = setup(Date.now());

      const req = makeRequest({
        tool: "read_record",
        sessionId: "normal-1",
        requestId: "normal-001"
      }, clock);

      const result = await executor.process(req);

      expect(result.status).toBe("executed");

      const events = audit.getEvents();

      expect(
        events.some(e => e.event_type === "capability_verified")
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "capability_rejected")
      ).toBe(false);

      expect(
        events.some(e => e.event_type === "approval_verification_failed")
      ).toBe(false);

      expect(
        events.some(e => e.event_type === "tool_result_delivered")
      ).toBe(true);
    });

    it("NORMAL-002 valid V2 human rejection -> normal oversight outcome, no authority verification failure", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "normal-2",
        requestId: "normal-002"
      }, clock);

      await executor.process(req);

      const rejectGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "reject",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await executor.resolveApproval(rejectGrant);

      const events = audit.getEvents();

      expect(
        events.some(e => e.event_type === "human_rejection")
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "approval_verification_failed")
      ).toBe(false);

      expect(
        events.some(e => e.event_type === "tool_execution_started")
      ).toBe(false);
    });

    it("NORMAL-003 valid V2 human approval -> normal oversight outcome and exactly one execution", async () => {
      const { executor, audit, clock, testSigner } = setup(Date.now());

      const req = makeRequest({
        tool: "update_record",
        sessionId: "normal-3",
        requestId: "normal-003"
      }, clock);

      await executor.process(req);

      const approveGrant = testSigner.sign({
        version: 2,
        tool: "update_record",
        decision: "approve",
        session_id: req.params.metadata.session_id,
        request_id: req.params.request_id,
        approver: { type: "human", id: "demo-operator" },
        issued_at: fresh(clock.nowMs())
      });

      await executor.resolveApproval(approveGrant);

      const events = audit.getEvents();

      expect(
        events.some(e => e.event_type === "human_approval")
      ).toBe(true);

      expect(
        events.some(e => e.event_type === "approval_verification_failed")
      ).toBe(false);

      expect(
        events.filter(e => e.event_type === "tool_execution_started")
      ).toHaveLength(1);
    });
  });
});
