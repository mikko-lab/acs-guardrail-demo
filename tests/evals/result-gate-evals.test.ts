import { setup, makeRequest, fresh, toUuid } from "./eval-setup";
import { OversightMetrics } from "../../src/oversight-metrics";

describe("Domain F: Result Gate", () => {
  const BASE_TIME = Date.now();

  it("EVAL-F1: request ALLOW + result ALLOW -> result delivered", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    const res = await executor.process(req);
    
    if (res.status === "pending") throw new Error("Expected execution");
    expect(res.result.exit_status).toBe("success");
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(true);
    expect(events.some(e => e.event_type === "tool_result_withheld")).toBe(false);
  });

  it("EVAL-F2: request ALLOW + result DENY -> result withheld, no delivery", async () => {
    const { executor, guardian, audit, clock } = setup(BASE_TIME);
    
    // Mock guardian result evaluation to DENY
    const origEvalRes = guardian.evaluateResult.bind(guardian);
    guardian.evaluateResult = jest.fn().mockImplementation((r) => {
      return {
        jsonrpc: "2.0", id: r.id,
        result: { type: "final", acs_version: "0.1.0", request_id: r.params.request_id, decision: "deny", reasoning: "Blocked", reason_codes: ["blocked_data"] }
      };
    });

    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-f2" }, clock);
    const res = await executor.process(req);
    
    if (res.status === "pending") throw new Error("Expected execution");
    expect(res.result.exit_status).toBe("blocked");
    expect((res.result.outputs[0].value as any).error).toMatch(/Output withheld/);
    
    const events = audit.getEvents();
    
    // Assertions
    const reqGateEvent = events.find(e => e.event_type === "guardian_decision" && e.request_id === toUuid("req-f2"));
    expect(reqGateEvent?.metadata?.decision).toBe("allow");
    
    expect(events.some(e => e.event_type === "tool_execution_started" && e.request_id === toUuid("req-f2"))).toBe(true);
    
    // result gate decision is mapped to the result request ID, so we just check it exists with deny
    expect(events.some(e => e.event_type === "result_guardian_decision" && e.metadata?.decision === "deny")).toBe(true);
    
    expect(events.some(e => e.event_type === "tool_result_withheld")).toBe(true);
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(false);
    
    guardian.evaluateResult = origEvalRes;
  });

  it("EVAL-F3: request ASK -> human approval -> execution -> result DENY -> result withheld", async () => {
    const { executor, guardian, audit, clock, testSigner } = setup(BASE_TIME);
    
    // Mock guardian result evaluation to DENY
    const origEvalRes = guardian.evaluateResult.bind(guardian);
    guardian.evaluateResult = jest.fn().mockImplementation((r) => {
      return {
        jsonrpc: "2.0", id: r.id,
        result: { type: "final", acs_version: "0.1.0", request_id: r.params.request_id, decision: "deny", reasoning: "Blocked", reason_codes: ["blocked_data"] }
      };
    });

    const req = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req); // Pending ASK
    
    const grant = testSigner.sign({
      version: 1, session_id: toUuid("sess-1"), request_id: toUuid("req-1"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +10), decision: "approve"
    });
    
    const res = await executor.resolveApproval(grant);
    if (!res) throw new Error("Expected result");
    
    expect(res.exit_status).toBe("blocked");
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
    expect(events.some(e => e.event_type === "tool_result_withheld")).toBe(true);
    expect(events.some(e => e.event_type === "tool_result_delivered")).toBe(false);
    
    guardian.evaluateResult = origEvalRes;
  });

  it("EVAL-F4: result_guardian_decision does not alter request-gate oversight metrics", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req); // ALLOW at request gate, ALLOW at result gate
    
    const metrics = new OversightMetrics(audit);
    const snap = metrics.getSnapshot();
    
    expect(snap.total_decisions).toBe(1);
    expect(snap.allow_count).toBe(1);
    
    const events = audit.getEvents();
    const resultDecisions = events.filter(e => e.event_type === "result_guardian_decision");
    expect(resultDecisions.length).toBe(1); // It exists but isn't counted in metrics
  });

  it("EVAL-F5: Result gate DENY does not retroactively modify the original request-gate event", async () => {
    const { executor, guardian, audit, clock } = setup(BASE_TIME);
    
    guardian.evaluateResult = jest.fn().mockImplementation((r) => ({
      jsonrpc: "2.0", id: r.id,
      result: { type: "final", acs_version: "0.1.0", request_id: r.params.request_id, decision: "deny", reasoning: "Blocked", reason_codes: ["blocked_data"] }
    }));

    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    
    const events = audit.getEvents();
    
    const reqGateEvent = events.find(e => e.event_type === "guardian_decision" && e.request_id === toUuid("req-1"));
    expect(reqGateEvent).toBeDefined();
    expect(reqGateEvent?.metadata?.decision).toBe("allow"); // Original request decision is STILL 'allow'
    
    const resGateEvent = events.find(e => e.event_type === "result_guardian_decision");
    expect(resGateEvent).toBeDefined();
    expect(resGateEvent?.metadata?.decision).toBe("deny"); // Result gate decision is 'deny'
  });
});
