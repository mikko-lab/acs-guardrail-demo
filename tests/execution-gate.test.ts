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

  /** Build a minimal valid ACS request with params nesting and ToolArgumentValue arguments. */
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
        // ACS ToolArgumentValue shape: { value: ... }
        arguments: { record_id: { value: "42" } },
      },
    },
  });

  // ── Shape: arguments use { value: ... } ───────────────────────────
  it("request arguments use ToolArgumentValue { value } shape", () => {
    const req = createRequest("req-shape", "read_record");
    const arg = req.params.payload.arguments["record_id"];
    expect(arg).toBeDefined();
    expect(arg).toHaveProperty("value");
    expect(arg.value).toBe("42");
  });

  // ── Decision: allow ───────────────────────────────────────────────
  it("1. read_record → ALLOW → executes exactly once", async () => {
    const req = createRequest("req-1", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(executionCounters.read_record).toBe(1);
    // toolCallResult references the original request_id
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

  // ── Decision: ask (without approval) ─────────────────────────────
  it("2. update_record → ASK → does not execute without approval", async () => {
    const req = createRequest("req-2", "update_record");
    const response = guardian.evaluate(req);
    await expect(gate.execute(req, response)).rejects.toThrow("Pending human approval");
    expect(executionCounters.update_record).toBe(0);
  });

  it("7. ASK cannot reach the tool implementation before approval", async () => {
    const req = createRequest("req-7", "update_record");
    const response = guardian.evaluate(req);
    await expect(gate.execute(req, response)).rejects.toThrow("Pending human approval");
    expect(executionCounters.update_record).toBe(0);
  });

  // ── Decision: ask (with correct approval) ────────────────────────
  it("3. update_record → ASK + approval for exact request_id → executes exactly once", async () => {
    const req = createRequest("req-3", "update_record");
    const response = guardian.evaluate(req);
    gate.supplyApproval("req-3");
    const result = await gate.execute(req, response);
    expect(executionCounters.update_record).toBe(1);
    expect(result.exit_status).toBe("success");
    expect(result.request_id_ref).toBe("req-3");
  });

  // ── Approval binding: wrong request_id cannot authorize ──────────
  it("4. approval for another request_id cannot authorize execution", async () => {
    const req = createRequest("req-4", "update_record");
    const response = guardian.evaluate(req);
    gate.supplyApproval("req-other");           // wrong id
    await expect(gate.execute(req, response)).rejects.toThrow("Pending human approval");
    expect(executionCounters.update_record).toBe(0);
  });

  it("approval is bound to exact request_id (no cross-authorization)", async () => {
    const reqA = createRequest("req-A", "update_record");
    const reqB = createRequest("req-B", "update_record");
    const respA = guardian.evaluate(reqA);
    const respB = guardian.evaluate(reqB);

    gate.supplyApproval("req-A");

    // A executes
    await gate.execute(reqA, respA);
    expect(executionCounters.update_record).toBe(1);

    // B is still blocked — approval for A cannot authorize B
    await expect(gate.execute(reqB, respB)).rejects.toThrow("Pending human approval");
    expect(executionCounters.update_record).toBe(1); // still 1, not 2
  });

  // ── Decision: deny ────────────────────────────────────────────────
  it("5. unknown tool → DENY → never executes", async () => {
    const req = createRequest("req-5", "some_random_tool");
    const response = guardian.evaluate(req);
    await expect(gate.execute(req, response)).rejects.toThrow("Execution blocked");
    expect(executionCounters.unknown_tool).toBe(0);
  });

  it("6. DENY can never reach the tool implementation (approval cannot override a deny)", async () => {
    const req = createRequest("req-6", "some_random_tool");
    const response = guardian.evaluate(req);
    gate.supplyApproval("req-6");              // approval present but irrelevant for deny
    await expect(gate.execute(req, response)).rejects.toThrow("Execution blocked");
    expect(executionCounters.unknown_tool).toBe(0);
  });

  it("blocked execution cannot invoke the tool", async () => {
    const reqDeny = createRequest("req-d", "evil_tool");
    const respDeny = guardian.evaluate(reqDeny);
    await expect(gate.execute(reqDeny, respDeny)).rejects.toThrow();
    expect(executionCounters.unknown_tool).toBe(0);
  });
});
