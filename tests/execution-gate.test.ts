import { ExecutionGate } from "../src/execution-gate";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";
import { executionCounters, resetCounters } from "../src/tools";

describe("Execution Gate", () => {
  let audit: AuditCollector;
  let guardian: Guardian;
  let gate: ExecutionGate;

  beforeEach(() => {
    audit = new AuditCollector();
    guardian = new Guardian();
    gate = new ExecutionGate(audit);
    resetCounters();
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
        arguments: { record_id: { value: "42" } },
      },
    },
  });

  it("request arguments use ToolArgumentValue { value } shape", () => {
    const req = createRequest("req-shape", "read_record");
    const arg = req.params.payload.arguments["record_id"];
    expect(arg).toBeDefined();
    expect(arg).toHaveProperty("value");
    expect(arg.value).toBe("42");
  });

  it("1. read_record → ALLOW → executes exactly once", async () => {
    const req = createRequest("req-1", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(executionCounters.read_record).toBe(1);
    expect(result.request_id_ref).toBe("req-1");
    expect(result.exit_status).toBe("success");
  });

  it("successful tool result references original request_id", async () => {
    const req = createRequest("req-ref", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(result.request_id_ref).toBe(req.params.request_id);
  });

  it("successful tool result has non-empty outputs array", async () => {
    const req = createRequest("req-out", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(Array.isArray(result.outputs)).toBe(true);
    expect(result.outputs.length).toBeGreaterThan(0);
    expect(result.outputs[0]).toHaveProperty("value");
  });

  it("update_record → ASK → executes when passed to ExecutionGate (approval verified upstream)", async () => {
    const req = createRequest("req-ask", "update_record");
    const response = guardian.evaluate(req);
    // In the new architecture, GuardedExecutor holds the request until approved,
    // then passes it to ExecutionGate. ExecutionGate trusts the upstream approval.
    const result = await gate.execute(req, response);
    expect(executionCounters.update_record).toBe(1);
    expect(result.exit_status).toBe("success");
    expect(result.request_id_ref).toBe("req-ask");
  });

  it("5. unknown tool → DENY → never executes (ExecutionGate hard block)", async () => {
    const req = createRequest("req-5", "some_random_tool");
    const response = guardian.evaluate(req);
    await expect(gate.execute(req, response)).rejects.toThrow("Execution blocked (deny)");
    expect(executionCounters.unknown_tool).toBe(0);
  });

  it("blocked execution cannot invoke the tool", async () => {
    const reqDeny = createRequest("req-d", "evil_tool");
    const respDeny = guardian.evaluate(reqDeny);
    await expect(gate.execute(reqDeny, respDeny)).rejects.toThrow();
    expect(executionCounters.unknown_tool).toBe(0);
  });
});
