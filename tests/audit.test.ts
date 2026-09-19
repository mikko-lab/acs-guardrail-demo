import { ExecutionGate } from "../src/execution-gate";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";

describe("Audit Collector invariants", () => {
  let audit: AuditCollector;
  let guardian: Guardian;
  let gate: ExecutionGate;

  beforeEach(() => {
    audit = new AuditCollector();
    guardian = new Guardian();
    gate = new ExecutionGate(audit);
  });

  const createRequest = (id: string, tool: string): AcsToolCallRequest => ({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: `call-${id}`,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "test-agent", session_id: "session-test" },
      payload: {
        tool: { name: tool },
        arguments: {},
      },
    },
  });

  // 8. every request gets a Guardian decision audit event
  it("8. every request gets a Guardian decision audit event", async () => {
    const req = createRequest("req-8", "read_record");
    const response = guardian.evaluate(req);
    await gate.execute(req, response);

    const events = audit.getEventsForRequest("req-8");
    const decisionEvent = events.find(e => e.event_type === "guardian_decision");
    expect(decisionEvent).toBeDefined();
    expect(decisionEvent?.metadata?.["decision"]).toBe("allow");
  });

  // 9. blocked actions get an audit event
  it("9. blocked actions get an audit event (deny)", async () => {
    const req = createRequest("req-9", "some_random_tool");
    const response = guardian.evaluate(req);

    await expect(gate.execute(req, response)).rejects.toThrow();

    const events = audit.getEventsForRequest("req-9");
    const blockedEvent = events.find(e => e.event_type === "tool_execution_blocked");
    expect(blockedEvent).toBeDefined();
    expect(blockedEvent?.metadata?.["reason"]).toBe("denied");
  });

  it("9b. blocked actions get an audit event (pending ask)", async () => {
    const req = createRequest("req-9b", "update_record");
    const response = guardian.evaluate(req);

    await expect(gate.execute(req, response)).rejects.toThrow();

    const events = audit.getEventsForRequest("req-9b");
    const blockedEvent = events.find(e => e.event_type === "tool_execution_blocked");
    expect(blockedEvent).toBeDefined();
    expect(blockedEvent?.metadata?.["reason"]).toBe("pending_approval");
  });

  // 10. successful execution gets start + completion audit events
  it("10. successful execution gets start + completion audit events", async () => {
    const req = createRequest("req-10", "read_record");
    const response = guardian.evaluate(req);
    await gate.execute(req, response);

    const events = audit.getEventsForRequest("req-10");
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_completed")).toBe(true);
  });
});
