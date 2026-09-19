import { ExecutionGate, ExecutionPermit } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import { AcsToolCallRequest } from "../src/acs-types";
import { executionCounters, resetCounters, tools } from "../src/tools";

function makeRequest(tool: string, sessionId = "sess", requestId = "req"): AcsToolCallRequest {
  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "1",
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent", session_id: sessionId },
      payload: { tool: { name: tool }, arguments: {} }
    }
  };
}

describe("ExecutionGate: Permit Authorization (H-02 Final)", () => {
  let audit: AuditCollector;
  let gate: ExecutionGate;
  let authority: symbol;

  beforeEach(() => {
    resetCounters();
    audit = new AuditCollector();
    authority = Symbol("test-authority");
    gate = new ExecutionGate(audit, authority);
  });

  afterEach(() => {
    // Test hygiene: restore mocked tools
    if (tools["throw_error_tool"] && (tools["throw_error_tool"] as any).__isMock) {
      delete tools["throw_error_tool"];
    }
  });

  it("1. public createIssuer API no longer exists", () => {
    expect((gate as any).createIssuer).toBeUndefined();
  });

  it("4. wrong authority cannot mint a valid permit", () => {
    const wrongAuth = Symbol("wrong");
    expect(() => gate.mintPermit(wrongAuth, "s", "r", "t")).toThrow(/Unauthorized/);
  });

  it("3. fabricated ALLOW cannot execute", async () => {
    const req = makeRequest("read_record");
    const fakeAllow = { result: { decision: "allow" } };
    await expect(gate.execute(req, fakeAllow as any)).rejects.toThrow(/valid execution permit required/);
    expect(executionCounters.read_record || 0).toBe(0);
  });

  it("5. fabricated permit cannot execute", async () => {
    const req = makeRequest("read_record");
    const fakePermit = { sessionId: "sess", requestId: "req", toolName: "read_record" };
    await expect(gate.execute(req, fakePermit as any)).rejects.toThrow(/valid execution permit required/);
    expect(executionCounters.read_record || 0).toBe(0);
  });

  it("6. permit for request A cannot execute request B", async () => {
    const reqB = makeRequest("read_record", "sess", "reqB");
    const permitA = gate.mintPermit(authority, "sess", "reqA", "read_record");
    await expect(gate.execute(reqB, permitA)).rejects.toThrow(/permit request mismatch/);
    expect(executionCounters.read_record || 0).toBe(0);
  });

  it("7. permit for session A cannot execute session B request", async () => {
    const reqB = makeRequest("read_record", "sessB", "req");
    const permitA = gate.mintPermit(authority, "sessA", "req", "read_record");
    await expect(gate.execute(reqB, permitA)).rejects.toThrow(/permit session mismatch/);
    expect(executionCounters.read_record || 0).toBe(0);
  });

  it("10. reused execution permit cannot execute twice (leaves counter at exactly 1)", async () => {
    const req = makeRequest("read_record");
    const permit = gate.mintPermit(authority, "sess", "req", "read_record");
    await gate.execute(req, permit); // Works
    expect(executionCounters.read_record).toBe(1);

    // Reuse fails
    await expect(gate.execute(req, permit)).rejects.toThrow(/valid execution permit required/);
    expect(executionCounters.read_record).toBe(1);
  });

  it("11. execution failure consumes permit before tool throws", async () => {
    const req = makeRequest("throw_error_tool");
    const mockTool = async () => { throw new Error("Mocked throw"); };
    (mockTool as any).__isMock = true;
    tools["throw_error_tool"] = mockTool;

    const permit = gate.mintPermit(authority, "sess", "req", "throw_error_tool");
    await expect(gate.execute(req, permit)).rejects.toThrow();

    // Trying again with same permit fails due to permit consumed, not tool throwing
    await expect(gate.execute(req, permit)).rejects.toThrow(/valid execution permit required/);
  });
});
