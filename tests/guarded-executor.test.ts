import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";

/**
 * tests/guarded-executor.test.ts
 *
 * Integration tests for GuardedExecutor — the mandatory orchestration boundary.
 */

import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard, ReplayGuardError, type Clock } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";
import { executionCounters, resetCounters, tools } from "../src/tools";

const SKEW_MS = 300_000;

function makeClock(nowMs: number): Clock {
  return { nowMs: () => nowMs };
}

const fresh = (nowMs: number, offsetMs = 0) =>
  new Date(nowMs + offsetMs).toISOString();

const testSignatureService = new SignatureService("test-secret", "key-1");
function makeRequest(overrides: {
  requestId?: string;
  sessionId?: string;
  timestamp?: string;
  tool?: string;
}): AcsToolCallRequest {
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "8910e724-3b59-4c4e-9883-9a83495b3f8e",
    params: {
      acs_version: "0.1.0",
      request_id: overrides.requestId ?? "123e4567-e89b-12d3-a456-426614174000",
      timestamp: overrides.timestamp ?? new Date().toISOString(),
      metadata: {
        agent_id: "test-agent",
        session_id: overrides.sessionId ?? "123e4567-e89b-12d3-a456-426614174001",
      },
      payload: {
        tool: { name: overrides.tool ?? "read_record" },
        arguments: {},
      },
    },
  };
  return testSignatureService.signRequest(req);
}

function makeExecutor(nowMs: number): {
  executor: GuardedExecutor;
  audit: AuditCollector;
  replayGuard: ReplayGuard;
  guardian: Guardian;
} {
  const audit = new AuditCollector();
  const replayGuard = new ReplayGuard({ skewWindowMs: SKEW_MS, clock: makeClock(nowMs), audit });
  const guardian = new Guardian();
  const executor = new GuardedExecutor(new SchemaValidator(), new SignatureService("test-secret", "key-1"),
    replayGuard,
    guardian,
    new ExecutionGate(audit),
    audit
  );
  return { executor, audit, replayGuard, guardian };
}

beforeEach(() => {
  resetCounters();
});

describe("GuardedExecutor: ASK Pause/Resume Semantics", () => {
  it("1, 2. ASK stores the original request as pending and does not execute the tool", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", requestId: "38a6cdcc-5661-48d9-8ef2-614cc9d71af8" });

    const result = await executor.process(req);
    expect(result.status).toBe("pending");
    expect(executionCounters.update_record).toBe(0);
  });

  it("3. approval for exact session_id + request_id resumes the SAME action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "1fb64e52-4333-4f0a-bbdf-48dd855a2eac" });

    await executor.process(req);
    const toolResult = await executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "1fb64e52-4333-4f0a-bbdf-48dd855a2eac");

    expect(toolResult.exit_status).toBe("success");
    expect(executionCounters.update_record).toBe(1);
  });

  it("4, 5. approval does not pass through ReplayGuard or Guardian again", async () => {
    const { executor, replayGuard, guardian } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "afa99e08-7005-4da5-99d9-23dd96fee1fa" });

    await executor.process(req);

    const replayCheckSpy = jest.spyOn(replayGuard, "check");
    const guardianEvalSpy = jest.spyOn(guardian, "evaluate");

    await executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "afa99e08-7005-4da5-99d9-23dd96fee1fa");

    expect(replayCheckSpy).not.toHaveBeenCalled();
    expect(guardianEvalSpy).not.toHaveBeenCalled();
  });

  it("6, 7. approval with wrong session_id or request_id fails", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "5633eb77-603e-42c2-8a3d-22bbdc0ded55" });

    await executor.process(req);

    await expect(executor.approve("wrong-sess", "5633eb77-603e-42c2-8a3d-22bbdc0ded55")).rejects.toThrow(/No pending action found/);
    await expect(executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "wrong-req")).rejects.toThrow(/No pending action found/);
    expect(executionCounters.update_record).toBe(0);
  });

  it("8, 9. one approval can execute exactly once; second approval attempt fails", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "062d9289-5b2f-49ed-92ba-953a352737d3" });

    await executor.process(req);

    await executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "062d9289-5b2f-49ed-92ba-953a352737d3");
    expect(executionCounters.update_record).toBe(1);

    // Action is consumed
    await expect(executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "062d9289-5b2f-49ed-92ba-953a352737d3")).rejects.toThrow(/No pending action found/);
    expect(executionCounters.update_record).toBe(1);
  });

  it("10. DENY never creates a pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "evil_tool", sessionId: "bc1b44cc-b043-41f4-b731-929f4391a600", requestId: "51d0ffcf-0ce9-4248-a2c1-f239929d7c18" });

    await expect(executor.process(req)).rejects.toThrow(/Execution blocked/);
    await expect(executor.approve("bc1b44cc-b043-41f4-b731-929f4391a600", "51d0ffcf-0ce9-4248-a2c1-f239929d7c18")).rejects.toThrow(/No pending action found/);
  });

  it("11. ALLOW never creates a pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "read_record", sessionId: "db0aa27d-ba50-4f7a-af41-9f3d16d98031", requestId: "962648ef-8f39-41d1-822d-49aecc13e8de" });

    const result = await executor.process(req);
    expect(result.status).toBe("executed");

    await expect(executor.approve("db0aa27d-ba50-4f7a-af41-9f3d16d98031", "962648ef-8f39-41d1-822d-49aecc13e8de")).rejects.toThrow(/No pending action found/);
  });

  it("12. rejected pending action never executes", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "a0f84a8d-3666-45c7-9665-c30ddb8aeb19", requestId: "21c1ad6c-1533-4e51-966d-b361080bdbb4" });

    await executor.process(req);
    executor.reject("a0f84a8d-3666-45c7-9665-c30ddb8aeb19", "21c1ad6c-1533-4e51-966d-b361080bdbb4");

    expect(executionCounters.update_record).toBe(0);
    await expect(executor.approve("a0f84a8d-3666-45c7-9665-c30ddb8aeb19", "21c1ad6c-1533-4e51-966d-b361080bdbb4")).rejects.toThrow(/No pending action found/);
  });

  it("13. replaying the original toolCallRequest through process() is still rejected", async () => {
    const nowMs = Date.now();
    const { executor } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "60041258-113a-4301-8d02-c0617907db17", timestamp: fresh(nowMs) });

    await executor.process(req); // Stored as pending

    // Replay attack via network
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);
  });

  it("14. approval of the pending request is NOT treated as a replay", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "61a7f982-cfc3-4577-9011-4715b50788ca", requestId: "131446d7-450c-4f7c-a042-d85d13c46256" });

    await executor.process(req);

    // Resuming works
    await expect(executor.approve("61a7f982-cfc3-4577-9011-4715b50788ca", "131446d7-450c-4f7c-a042-d85d13c46256")).resolves.toBeDefined();
  });
});

describe("GuardedExecutor: Replay & Timestamp protections", () => {
  it("same-session replay stops before Guardian", async () => {
    const nowMs = Date.now();
    const { executor, guardian } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "read_record", requestId: "67defc99-2550-46d2-85ee-765919f52aca", timestamp: fresh(nowMs) });

    await executor.process(req); // Ok

    const evalSpy = jest.spyOn(guardian, "evaluate");
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);
    expect(evalSpy).not.toHaveBeenCalled();
  });

  it("stale timestamp stops before Guardian", async () => {
    const nowMs = Date.now();
    const { executor, guardian } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "read_record", timestamp: fresh(nowMs, -(SKEW_MS + 1000)) });

    const evalSpy = jest.spyOn(guardian, "evaluate");
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);
    expect(evalSpy).not.toHaveBeenCalled();
  });
});

describe("GuardedExecutor: Session Lifecycle & Exactly-Once Safety", () => {
  it("clearSession removes ReplayGuard state for session A", async () => {
    const nowMs = Date.now();
    const { executor } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "read_record", sessionId: "0a80d086-3c9a-4e88-9425-3eff90377465", requestId: "e57e7a5c-8c44-4f51-ab37-4157bb90e0c5", timestamp: fresh(nowMs) });

    await executor.process(req);
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);

    executor.clearSession("0a80d086-3c9a-4e88-9425-3eff90377465");
    await expect(executor.process(req)).resolves.toBeDefined();
  });

  it("clearSession removes all pending ASK actions for session A", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "0a80d086-3c9a-4e88-9425-3eff90377465", requestId: "fba1a89e-5ea2-4ff3-9a30-0688862cebfb" });

    await executor.process(req);
    executor.clearSession("0a80d086-3c9a-4e88-9425-3eff90377465");

    // Approval fails because it was cleared
    await expect(executor.approve("0a80d086-3c9a-4e88-9425-3eff90377465", "fba1a89e-5ea2-4ff3-9a30-0688862cebfb")).rejects.toThrow(/No pending action found/);
  });

  it("clearSession does not affect session B", async () => {
    const { executor } = makeExecutor(Date.now());
    const reqB = makeRequest({ tool: "update_record", sessionId: "3a1b741f-3d7e-4f5f-9b6b-f1a8d28898ee", requestId: "e03d2eff-ae87-46bd-9992-1670bd82ccf2" });

    await executor.process(reqB);
    executor.clearSession("0a80d086-3c9a-4e88-9425-3eff90377465"); // clear a different session

    // Approval for B should still succeed
    await expect(executor.approve("3a1b741f-3d7e-4f5f-9b6b-f1a8d28898ee", "e03d2eff-ae87-46bd-9992-1670bd82ccf2")).resolves.toBeDefined();
  });

  it("tool execution failure after approval does not restore the pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "01939deb-ba80-4689-a823-76e79e65e163", requestId: "1c090296-a303-4188-aa48-be35bf9ae8a5" });

    // Store original tool
    const originalTool = tools.update_record;
    let mockCalledCount = 0;

    try {
      // Temporarily mock the tool to fail
      tools.update_record = async () => {
        mockCalledCount++;
        throw new Error("Simulated tool execution failure");
      };

      await executor.process(req);

      // Execution throws
      await expect(executor.approve("01939deb-ba80-4689-a823-76e79e65e163", "1c090296-a303-4188-aa48-be35bf9ae8a5")).rejects.toThrow("Simulated tool execution failure");

      // The action must be gone; it was consumed BEFORE execution
      await expect(executor.approve("01939deb-ba80-4689-a823-76e79e65e163", "1c090296-a303-4188-aa48-be35bf9ae8a5")).rejects.toThrow(/No pending action found/);

      // Verify it only ran once
      expect(mockCalledCount).toBe(1);
    } finally {
      // Restore original tool
      tools.update_record = originalTool;
    }
  });
});
