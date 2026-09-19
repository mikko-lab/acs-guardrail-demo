import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";

import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";

describe("Audit Collector invariants", () => {
  let audit: AuditCollector;
  let executor: GuardedExecutor;

  beforeEach(() => {
    audit = new AuditCollector();
    executor = new GuardedExecutor(new SchemaValidator(), new SignatureService("test-secret", "key-1"),
      new ReplayGuard({ audit }),
      new Guardian(),
      audit,
        new ExecutionCorrelationStore()
      );
  });

  const testSignatureService = new SignatureService("test-secret", "key-1");
  const createRequest = (id: string, tool: string): AcsToolCallRequest => testSignatureService.signRequest({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: id,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "test-agent", session_id: "26f7a67a-cfda-4fa3-8315-6de161b37a47" },
      payload: {
        tool: { name: tool },
        arguments: {},
      },
    },
  });

  // 8. every request gets a Guardian decision audit event
  it("8. every request gets a Guardian decision audit event", async () => {
    const req = createRequest("f34c8e1e-0637-4c38-b66d-d2cf1e39ed1e", "read_record");
    await executor.process(req);

    const events = audit.getEventsForRequest("f34c8e1e-0637-4c38-b66d-d2cf1e39ed1e");
    const decisionEvent = events.find(e => e.event_type === "guardian_decision");
    expect(decisionEvent).toBeDefined();
    expect(decisionEvent?.metadata?.["decision"]).toBe("allow");
  });

  // 9. blocked actions get an audit event
  it("9. blocked actions get an audit event (deny)", async () => {
    const req = createRequest("d4050efb-29e2-4edb-9564-115948d338c2", "some_random_tool");

    await expect(executor.process(req)).rejects.toThrow();

    const events = audit.getEventsForRequest("d4050efb-29e2-4edb-9564-115948d338c2");
    const blockedEvent = events.find(e => e.event_type === "tool_execution_blocked");
    expect(blockedEvent).toBeDefined();
    expect(blockedEvent?.metadata?.["reason"]).toBe("denied");
  });

  it("9b. paused actions get an approval_requested event", async () => {
    const req = createRequest("7340d64e-3a59-4f17-9096-865ba73666ad", "update_record");

    const result = await executor.process(req);
    expect(result.status).toBe("pending");

    const events = audit.getEventsForRequest("7340d64e-3a59-4f17-9096-865ba73666ad");
    const askEvent = events.find(e => e.event_type === "approval_requested");
    expect(askEvent).toBeDefined();
  });

  // 10. successful execution gets start + completion audit events
  it("10. successful execution gets start + completion audit events", async () => {
    const req = createRequest("f3e6b6d5-d371-42e7-b384-27019524b015", "read_record");
    await executor.process(req);

    const events = audit.getEventsForRequest("f3e6b6d5-d371-42e7-b384-27019524b015");
    expect(events.some(e => e.event_type === "tool_execution_started")).toBe(true);
    expect(events.some(e => e.event_type === "tool_execution_completed")).toBe(true);
  });
});
