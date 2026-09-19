import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
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
      metadata: { agent_id: "test-agent", session_id: "8f6e1e26-2b6f-4368-9e23-d3a66a2c392a" },
      payload: {
        tool: { name: tool },
        arguments: { record_id: { value: "42" } },
      },
    },
  });

  it("request arguments use ToolArgumentValue { value } shape", () => {
    const req = createRequest("be5ced22-40ba-4c51-87c6-4b5f2f221359", "read_record");
    const arg = req.params.payload.arguments["record_id"];
    expect(arg).toBeDefined();
    expect(arg).toHaveProperty("value");
    expect(arg.value).toBe("42");
  });

  it("1. read_record → ALLOW → executes exactly once", async () => {
    const req = createRequest("607381f3-8792-476e-b8ef-550d4f9cbd38", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(executionCounters.read_record).toBe(1);
    expect(result.request_id_ref).toBe("607381f3-8792-476e-b8ef-550d4f9cbd38");
    expect(result.exit_status).toBe("success");
  });

  it("successful tool result references original request_id", async () => {
    const req = createRequest("5f34aec3-9d71-4172-9fb9-7da82e397f4b", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(result.request_id_ref).toBe(req.params.request_id);
  });

  it("successful tool result has non-empty outputs array", async () => {
    const req = createRequest("dfd4c254-e5d8-4c7d-9bb4-2e67c9796a3e", "read_record");
    const response = guardian.evaluate(req);
    const result = await gate.execute(req, response);
    expect(Array.isArray(result.outputs)).toBe(true);
    expect(result.outputs.length).toBeGreaterThan(0);
    expect(result.outputs[0]).toHaveProperty("value");
  });

  it("update_record → ASK → executes when passed to ExecutionGate (approval verified upstream)", async () => {
    const req = createRequest("6eb2661d-b60e-4d45-9c30-fba121945e0f", "update_record");
    const response = guardian.evaluate(req);
    // In the new architecture, GuardedExecutor holds the request until approved,
    // then passes it to ExecutionGate. ExecutionGate trusts the upstream approval.
    const result = await gate.execute(req, response);
    expect(executionCounters.update_record).toBe(1);
    expect(result.exit_status).toBe("success");
    expect(result.request_id_ref).toBe("6eb2661d-b60e-4d45-9c30-fba121945e0f");
  });

  it("5. unknown tool → DENY → never executes (ExecutionGate hard block)", async () => {
    const req = createRequest("3125737e-272a-488c-8334-71ce2278919a", "some_random_tool");
    const response = guardian.evaluate(req);
    await expect(gate.execute(req, response)).rejects.toThrow("Execution blocked (deny)");
    expect(executionCounters.unknown_tool).toBe(0);
  });

  it("blocked execution cannot invoke the tool", async () => {
    const reqDeny = createRequest("8b286a26-b1d9-4536-b504-738382f1175c", "evil_tool");
    const respDeny = guardian.evaluate(reqDeny);
    await expect(gate.execute(reqDeny, respDeny)).rejects.toThrow();
    expect(executionCounters.unknown_tool).toBe(0);
  });
});
