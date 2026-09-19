/**
 * src/guarded-executor.ts
 *
 * Mandatory orchestration boundary for the ACS guardrail demo.
 *
 * Purpose: make ReplayGuard a structural requirement, not a convention.
 * Callers cannot accidentally skip replay/timestamp checks because they
 * are wired here in a fixed, non-bypassable sequence:
 *
 *   1. ReplayGuard.check(request)       — timestamp + session-scoped replay
 *   2. Guardian.evaluate(request)       — deterministic policy decision
 *   3. ExecutionGate.execute(request, response) — honor the decision
 *
 * A request that fails step 1 never reaches step 2 or step 3.
 * The tool implementation is therefore unreachable on any replay or
 * timestamp violation without modifying this file.
 *
 * Session lifecycle:
 *   clearSession(sessionId) delegates to ReplayGuard.clearSession() AND
 *   removes all pending actions for that session.
 *
 * Human approval for ASK decisions:
 *   An ASK decision results in a pending action. 
 *   approve(sessionId, requestId) consumes the action and executes it exactly once.
 *   reject(sessionId, requestId) consumes it without execution.
 */

import { AcsToolCallRequest, AcsResponseEnvelope, AcsToolCallResult } from "./acs-types";
import { ReplayGuard } from "./replay-guard";
import { Guardian } from "./guardian";
import { ExecutionGate } from "./execution-gate";
import { AuditCollector } from "./audit";

export type ProcessResult =
  | { status: "executed"; result: AcsToolCallResult }
  | { status: "pending" };

interface PendingAction {
  request: AcsToolCallRequest;
  response: AcsResponseEnvelope;
}

export class GuardedExecutor {
  private readonly replayGuard: ReplayGuard;
  private readonly guardian: Guardian;
  private readonly gate: ExecutionGate;
  private readonly audit: AuditCollector;

  // Keyed by: `${session_id}:${request_id}`
  private readonly pendingActions: Map<string, PendingAction> = new Map();

  constructor(
    replayGuard: ReplayGuard,
    guardian: Guardian,
    gate: ExecutionGate,
    audit: AuditCollector
  ) {
    this.replayGuard = replayGuard;
    this.guardian = guardian;
    this.gate = gate;
    this.audit = audit;
  }

  /**
   * Process a single tool-call request through the full enforcement stack.
   *
   * Throws ReplayGuardError if the request fails timestamp or replay checks.
   * Throws Error if the Guardian denies.
   * Returns { status: "pending" } if Guardian asks for approval.
   * Returns { status: "executed", result: AcsToolCallResult } on allow.
   */
  async process(request: AcsToolCallRequest): Promise<ProcessResult> {
    const { params } = request;
    
    // Step 1 — replay/timestamp gate (throws on any violation)
    this.replayGuard.check(request);

    // Record request after replay passes
    this.audit.record(params.request_id, "tool_call_requested", {
      tool: params.payload.tool.name,
    });

    // Step 2 — deterministic Guardian policy
    const response = this.guardian.evaluate(request);

    this.audit.record(params.request_id, "guardian_decision", {
      decision: response.result.decision,
      reason_codes: response.result.reason_codes,
    });

    // Step 3 — branch on decision
    if (response.result.decision === "deny") {
      // Gate enforces hard block logic
      const result = await this.gate.execute(request, response);
      return { status: "executed", result }; // Unreachable; gate throws
    }
    
    if (response.result.decision === "ask") {
      const key = `${params.metadata.session_id}:${params.request_id}`;
      this.pendingActions.set(key, { request, response });
      this.audit.record(params.request_id, "approval_requested");
      return { status: "pending" };
    }

    // decision === "allow"
    const result = await this.gate.execute(request, response);
    return { status: "executed", result };
  }

  /**
   * Approve a pending action and execute it exactly once.
   * Resumes the SAME action without re-evaluating ReplayGuard or Guardian.
   */
  async approve(sessionId: string, requestId: string): Promise<AcsToolCallResult> {
    const key = `${sessionId}:${requestId}`;
    const pending = this.pendingActions.get(key);
    
    if (!pending) {
      throw new Error(`No pending action found for session ${sessionId}, request ${requestId}`);
    }

    // Consume the pending action (exactly-once execution)
    this.pendingActions.delete(key);

    this.audit.record(requestId, "human_approval");
    return this.gate.execute(pending.request, pending.response);
  }

  /**
   * Reject a pending action without executing it.
   */
  reject(sessionId: string, requestId: string): void {
    const key = `${sessionId}:${requestId}`;
    const pending = this.pendingActions.get(key);

    if (!pending) {
      throw new Error(`No pending action found for session ${sessionId}, request ${requestId}`);
    }

    // Consume without execution
    this.pendingActions.delete(key);
    
    this.audit.record(requestId, "human_rejection");
    this.audit.record(requestId, "tool_execution_blocked", { reason: "human_rejected" });
  }

  /**
   * Release replay state for a session.
   * Must be called when the session ends.
   */
  clearSession(sessionId: string): void {
    this.replayGuard.clearSession(sessionId);
    // Also clean up any abandoned pending actions for this session
    for (const key of this.pendingActions.keys()) {
      if (key.startsWith(`${sessionId}:`)) {
        this.pendingActions.delete(key);
      }
    }
  }
}

