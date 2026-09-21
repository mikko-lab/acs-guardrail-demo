import { setup, makeRequest, fresh, toUuid } from "./eval-setup";

describe("Domain F & Adversarial Sequences", () => {
  const BASE_TIME = Date.now();

  it("Sequence 1: ASK -> execution attempt before approval -> correlation fails", async () => {
    const { executor, correlation, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    
    // Attack: Try to forge a result consumption before approval is given directly at the store
    expect(() => correlation.validateAndConsume(toUuid("sess-1"), toUuid("req-1"), "update_record")).toThrow(/Unknown/);
    
    // Now approve
    const grant = testSigner.sign({
      version: 1, session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    
    const res = await executor.resolveApproval(grant);
    expect(res).toBeDefined();
  });

  it("Sequence 2: ALLOW -> consume -> double consume -> fail-closed", async () => {
    const { executor, correlation, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req); // Internally executes and consumes correlation
    
    // Attack: Attacker tries to consume the same correlation reference again.
    // Because GuardedExecutor hides processResultRequest, we attack the store directly to prove the invariant.
    const ctx = { audit, resultRequestId: "res-malicious", sessionId: toUuid("sess-1"), tool: "read_record" };
    expect(() => correlation.validateAndConsume(toUuid("sess-1"), toUuid("req-1"), "read_record", ctx)).toThrow(/already consumed/);
    
    // Verify fail-closed evidence exists
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed" && e.request_id === "res-malicious")).toBe(true);
    // Verify no secondary delivery
    const deliveries = events.filter(e => e.event_type === "tool_result_delivered");
    expect(deliveries.length).toBe(1); // Only the legitimate first one
  });

  it("Sequence 3: Session A valid state -> Session B uses A's reference -> fail-closed", async () => {
    const { correlation, audit } = setup(BASE_TIME);
    
    // Session A is pending or executed, meaning its correlation is registered
    correlation.registerExecution(toUuid("sess-A"), toUuid("req-1"), "read_record");
    
    // Session B tries to use A's reference
    const ctx = { audit, resultRequestId: "res-b", sessionId: toUuid("sess-B"), tool: "read_record" };
    expect(() => correlation.validateAndConsume(toUuid("sess-B"), toUuid("req-1"), "read_record", ctx)).toThrow(/Unknown/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed" && e.request_id === "res-b")).toBe(true);
    
    // A's state is unchanged, we can still consume it from Session A
    expect(() => correlation.validateAndConsume(toUuid("sess-A"), toUuid("req-1"), "read_record")).not.toThrow();
  });
});
