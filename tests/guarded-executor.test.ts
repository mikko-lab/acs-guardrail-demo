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

function makeRequest(overrides: {
  requestId?: string;
  sessionId?: string;
  timestamp?: string;
  tool?: string;
}): AcsToolCallRequest {
  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "call-int-test",
    params: {
      acs_version: "0.1.0",
      request_id: overrides.requestId ?? "req-int",
      timestamp: overrides.timestamp ?? new Date().toISOString(),
      metadata: {
        agent_id: "test-agent",
        session_id: overrides.sessionId ?? "session-int",
      },
      payload: {
        tool: { name: overrides.tool ?? "read_record" },
        arguments: {},
      },
    },
  };
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
  const executor = new GuardedExecutor(
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
    const req = makeRequest({ tool: "update_record", requestId: "req-ask-1" });
    
    const result = await executor.process(req);
    expect(result.status).toBe("pending");
    expect(executionCounters.update_record).toBe(0);
  });

  it("3. approval for exact session_id + request_id resumes the SAME action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-3" });
    
    await executor.process(req);
    const toolResult = await executor.approve("sess-ask", "req-ask-3");
    
    expect(toolResult.exit_status).toBe("success");
    expect(executionCounters.update_record).toBe(1);
  });

  it("4, 5. approval does not pass through ReplayGuard or Guardian again", async () => {
    const { executor, replayGuard, guardian } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-4" });
    
    await executor.process(req);
    
    const replayCheckSpy = jest.spyOn(replayGuard, "check");
    const guardianEvalSpy = jest.spyOn(guardian, "evaluate");
    
    await executor.approve("sess-ask", "req-ask-4");
    
    expect(replayCheckSpy).not.toHaveBeenCalled();
    expect(guardianEvalSpy).not.toHaveBeenCalled();
  });

  it("6, 7. approval with wrong session_id or request_id fails", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-6" });
    
    await executor.process(req);
    
    await expect(executor.approve("wrong-sess", "req-ask-6")).rejects.toThrow(/No pending action found/);
    await expect(executor.approve("sess-ask", "wrong-req")).rejects.toThrow(/No pending action found/);
    expect(executionCounters.update_record).toBe(0);
  });

  it("8, 9. one approval can execute exactly once; second approval attempt fails", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-8" });
    
    await executor.process(req);
    
    await executor.approve("sess-ask", "req-ask-8");
    expect(executionCounters.update_record).toBe(1);
    
    // Action is consumed
    await expect(executor.approve("sess-ask", "req-ask-8")).rejects.toThrow(/No pending action found/);
    expect(executionCounters.update_record).toBe(1);
  });

  it("10. DENY never creates a pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "evil_tool", sessionId: "sess-deny", requestId: "req-deny" });
    
    await expect(executor.process(req)).rejects.toThrow(/Execution blocked/);
    await expect(executor.approve("sess-deny", "req-deny")).rejects.toThrow(/No pending action found/);
  });

  it("11. ALLOW never creates a pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "read_record", sessionId: "sess-allow", requestId: "req-allow" });
    
    const result = await executor.process(req);
    expect(result.status).toBe("executed");
    
    await expect(executor.approve("sess-allow", "req-allow")).rejects.toThrow(/No pending action found/);
  });

  it("12. rejected pending action never executes", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-rej", requestId: "req-rej" });
    
    await executor.process(req);
    executor.reject("sess-rej", "req-rej");
    
    expect(executionCounters.update_record).toBe(0);
    await expect(executor.approve("sess-rej", "req-rej")).rejects.toThrow(/No pending action found/);
  });

  it("13. replaying the original toolCallRequest through process() is still rejected", async () => {
    const nowMs = Date.now();
    const { executor } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-13", timestamp: fresh(nowMs) });
    
    await executor.process(req); // Stored as pending
    
    // Replay attack via network
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);
  });

  it("14. approval of the pending request is NOT treated as a replay", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-ask", requestId: "req-ask-14" });
    
    await executor.process(req);
    
    // Resuming works
    await expect(executor.approve("sess-ask", "req-ask-14")).resolves.toBeDefined();
  });
});

describe("GuardedExecutor: Replay & Timestamp protections", () => {
  it("same-session replay stops before Guardian", async () => {
    const nowMs = Date.now();
    const { executor, guardian } = makeExecutor(nowMs);
    const req = makeRequest({ tool: "read_record", requestId: "req-rp-1", timestamp: fresh(nowMs) });

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
    const req = makeRequest({ tool: "read_record", sessionId: "sess-A", requestId: "req-clean", timestamp: fresh(nowMs) });

    await executor.process(req);
    await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);

    executor.clearSession("sess-A");
    await expect(executor.process(req)).resolves.toBeDefined();
  });

  it("clearSession removes all pending ASK actions for session A", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-A", requestId: "req-clean-ask" });

    await executor.process(req);
    executor.clearSession("sess-A");
    
    // Approval fails because it was cleared
    await expect(executor.approve("sess-A", "req-clean-ask")).rejects.toThrow(/No pending action found/);
  });

  it("clearSession does not affect session B", async () => {
    const { executor } = makeExecutor(Date.now());
    const reqB = makeRequest({ tool: "update_record", sessionId: "sess-B", requestId: "req-B-ask" });

    await executor.process(reqB);
    executor.clearSession("sess-A"); // clear a different session
    
    // Approval for B should still succeed
    await expect(executor.approve("sess-B", "req-B-ask")).resolves.toBeDefined();
  });

  it("tool execution failure after approval does not restore the pending action", async () => {
    const { executor } = makeExecutor(Date.now());
    const req = makeRequest({ tool: "update_record", sessionId: "sess-fail", requestId: "req-fail" });

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
      await expect(executor.approve("sess-fail", "req-fail")).rejects.toThrow("Simulated tool execution failure");
      
      // The action must be gone; it was consumed BEFORE execution
      await expect(executor.approve("sess-fail", "req-fail")).rejects.toThrow(/No pending action found/);
      
      // Verify it only ran once
      expect(mockCalledCount).toBe(1);
    } finally {
      // Restore original tool
      tools.update_record = originalTool;
    }
  });
});
