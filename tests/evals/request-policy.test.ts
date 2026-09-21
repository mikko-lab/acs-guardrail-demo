import { setup, makeRequest, fresh } from "./eval-setup";

describe("Domain A: Guardian request policy", () => {
  const BASE_TIME = Date.now();
  
  it("EVAL-A1: ALLOW -> valid request proceeds to execution", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record" }, clock);
    const res = await executor.process(req);
    
    expect(res.status).toBe("executed");
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "allow")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(true);
  });

  it("EVAL-A2: DENY -> execution does not start", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "delete_record" }, clock);
    await expect(executor.process(req)).rejects.toThrow(/Execution blocked \(deny\)/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "deny")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_blocked" && e.metadata?.reason === "denied")).toBe(true);
    // Negative assertions
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(false);
  });

  it("EVAL-A3: ASK -> execution does not start without approval", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record" }, clock);
    const res = await executor.process(req);
    
    expect(res.status).toBe("pending");
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "guardian_decision" && e.metadata?.decision === "ask")).toBe(true);
    expect(events.some(e => e.event_type === "approval_requested")).toBe(true);
    // Negative assertions
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(false);
  });

  it("EVAL-A4: ASK + valid approval -> execution proceeds", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record" }, clock);
    await executor.process(req);
    
    const grant = testSigner.sign({
      version: 1,
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs(), +1000),
      decision: "approve"
    });
    
    const res = await executor.resolveApproval(grant);
    expect(res).toBeDefined();
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "human_approval")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
  });

  it("EVAL-A5: ASK + human rejection -> execution blocked", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record" }, clock);
    await executor.process(req);
    
    const grant = testSigner.sign({
      version: 1,
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs(), +1000),
      decision: "reject"
    });
    
    await executor.resolveApproval(grant);
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "human_rejection")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_blocked")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });

  it("EVAL-A6: ASK + expired approval -> execution blocked", async () => {
    const { executor, audit, clock, testSigner } = setup(BASE_TIME);
    const req = makeRequest({ tool: "update_record" }, clock);
    await executor.process(req);
    
    // Advance clock past the 15-minute expiry
    clock.currentMs += 20 * 60 * 1000;
    
    const grant = testSigner.sign({
      version: 1,
      session_id: req.params.metadata.session_id,
      request_id: req.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs()),
      decision: "approve"
    });
    
    await expect(executor.resolveApproval(grant)).rejects.toThrow(/expired/);
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "approval_expired")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(false);
  });
});
