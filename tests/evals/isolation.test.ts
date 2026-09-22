import { setup, makeRequest, fresh, toUuid } from "./eval-setup";

describe("Domain D & G: Isolation", () => {
  const BASE_TIME = Date.now();

  it("EVAL-D1: approval from session A does not apply to session B, state is preserved", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const reqA = makeRequest({ tool: "update_record", sessionId: "sess-A", requestId: "req-1" }, clock);
    await executor.process(reqA);
    const reqB = makeRequest({ tool: "update_record", sessionId: "sess-B", requestId: "req-1" }, clock); // Same req ID, diff session
    await executor.process(reqB);
    
    // Grant for A
    const grantA = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-A"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    
    await executor.resolveApproval(grantA);
    
    // Verify A executed (there should be exactly 1 execution for this request ID across all sessions)
    let events = audit.getEvents();
    let executions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-1"));
    expect(executions.length).toBe(1);

    // Grant for B
    const grantB = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-B"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    
    await executor.resolveApproval(grantB); // Approving B should work normally

    events = audit.getEvents();
    executions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-1"));
    
    // Verify B got its execution, bringing total to 2. No cross-pollution or state deletion.
    expect(executions.length).toBe(2);
  });

  it("EVAL-D2: approval for request A does not resolve request B in same session, state preserved", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const reqA = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-a" }, clock);
    await executor.process(reqA);
    const reqB = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-b" }, clock);
    await executor.process(reqB);
    
    // Grant for A
    const grantA = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-a"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    
    await executor.resolveApproval(grantA); // Resolves A
    
    let events = audit.getEvents();
    let aExecutions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-a"));
    expect(aExecutions.length).toBe(1); // A executed exactly once

    let bExecutions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-b"));
    expect(bExecutions.length).toBe(0); // B is unexecuted

    // Grant for B
    const grantB = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-b"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });

    await executor.resolveApproval(grantB);

    events = audit.getEvents();
    aExecutions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-a"));
    bExecutions = events.filter(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-b"));

    // Verify A still has exactly one execution, B has exactly one
    expect(aExecutions.length).toBe(1);
    expect(bExecutions.length).toBe(1);
  });

  it("EVAL-D4: expired approval or pending action -> subsequent retry fails", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    
    // Advance clock past the 15-minute expiry
    clock.currentMs += 20 * 60 * 1000;
    
    // Sign an approval after expiry
    const grantLate = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), -10), decision: "approve"
    });
    
    await expect(executor.resolveApproval(grantLate)).rejects.toThrow(/expired/);
    
    // Attacker tries AGAIN with a new grant, but the pending action was deleted during the first expiry!
    const grantLate2 = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    await expect(executor.resolveApproval(grantLate2)).rejects.toThrow(/No pending action/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });

  it("EVAL-D5: rejection is final for the request_id, retry requires new request", async () => {
    const { executor, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    
    const grantReject = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "reject"
    });
    await executor.resolveApproval(grantReject);
    
    // Maliciously follow up with approve for same request
    const grantApprove = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +20), decision: "approve"
    });
    await expect(executor.resolveApproval(grantApprove)).rejects.toThrow(/No pending action/);
  });
});
