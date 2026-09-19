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
import { SchemaValidator, AddressableSchemaError } from "./schema-validator";
import { SignatureService } from "./signature-service";
import { ExecutionCorrelationStore } from "./execution-correlation";
import * as crypto from "crypto";

export type ProcessResult =
  | { status: "executed"; result: AcsToolCallResult }
  | { status: "pending" };

interface PendingAction {
  request: AcsToolCallRequest;
  response: AcsResponseEnvelope;
}

export class GuardedExecutor {
  private readonly schemaValidator: SchemaValidator;
  private readonly signatureService: SignatureService;
  private readonly replayGuard: ReplayGuard;
  private readonly guardian: Guardian;
  private readonly gate: ExecutionGate;
  private readonly audit: AuditCollector;
  private readonly correlation: ExecutionCorrelationStore;

  // Keyed by: `${session_id}:${request_id}`
  private readonly pendingActions: Map<string, PendingAction> = new Map();

  constructor(
    schemaValidator: SchemaValidator,
    signatureService: SignatureService,
    replayGuard: ReplayGuard,
    guardian: Guardian,
    gate: ExecutionGate,
    audit: AuditCollector,
    correlation: ExecutionCorrelationStore
  ) {
    this.schemaValidator = schemaValidator;
    this.signatureService = signatureService;
    this.replayGuard = replayGuard;
    this.guardian = guardian;
    this.gate = gate;
    this.audit = audit;
    this.correlation = correlation;
  }

  /**
   * Process a single untrusted tool-call request through the full enforcement stack.
   *
   * 0. Validates schema (throws AddressableSchemaError or SchemaValidationError on failure).
   * 0.5. Verifies envelope signature (throws SignatureInvalidError).
   * 1. ReplayGuard checks timestamp or replay violations.
   * 2. Guardian policy evaluated (and outbound response schema validated & signed).
   * 3. Branches on decision (throws on deny, pending on ask, executes on allow).
   */
  async process(input: unknown): Promise<ProcessResult> {
    // Step 0 — Schema validation
    const validated = this.schemaValidator.validateRequest(input);
    if (validated.method !== "steps/toolCallRequest") {
      throw new Error("Expected toolCallRequest");
    }
    const request = validated as import("./acs-types").AcsToolCallRequest;
    const { params } = request;

    // Step 0.5 — Signature verification
    this.signatureService.verifyRequest(request);

    // Step 1 — replay/timestamp gate (throws on any violation)
    this.replayGuard.check(request);

    // Record request after replay passes
    this.audit.record(params.request_id, "tool_call_requested", {
      tool: params.payload.tool.name,
    });

    // Step 2 — deterministic Guardian policy (and outbound validation)
    const rawResponse = this.guardian.evaluate(request);
    let response = this.schemaValidator.validateResponse(rawResponse);

    // Step 2.5 — sign outbound response and immediately verify it
    response = this.signatureService.signResponse(response, params.metadata.session_id);
    this.schemaValidator.validateResponse(response); // verify signing didn't break schema

    // Demonstrate response verification (Consumer-side check before executing)
    this.signatureService.verifyResponse(response, params.metadata.session_id);

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
    const result = await this.executeAndProcessResult(request, response);
    return { status: "executed", result };
  }


  private async processResultRequest(signedResultRequest: import("./acs-types").AcsToolCallResultRequest): Promise<import("./acs-types").AcsToolCallResult> {
    const validated = this.schemaValidator.validateRequest(signedResultRequest);
    if (validated.method !== "steps/toolCallResult") {
      throw new Error("Unexpected request method in result processing");
    }
    const request = validated as import("./acs-types").AcsToolCallResultRequest;
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const requestIdRef = params.payload.request_id_ref;

    this.signatureService.verifyRequest(request as any);
    this.replayGuard.check(request as any);
    this.correlation.validateAndConsume(sessionId, requestIdRef);

    const rawResponse = this.guardian.evaluateResult(request);
    let response = this.schemaValidator.validateResponse(rawResponse);

    response = this.signatureService.signResponse(response, sessionId);
    this.schemaValidator.validateResponse(response);
    this.signatureService.verifyResponse(response, sessionId);

    this.audit.record(params.request_id, "result_guardian_decision", {
      decision: response.result.decision,
      reason_codes: response.result.reason_codes
    });

    const payload = params.payload;

    if (response.result.decision === "deny") {
      this.audit.record(params.request_id, "tool_result_withheld", { tool: payload.tool.name });
      return {
        tool: payload.tool,
        request_id_ref: requestIdRef,
        exit_status: "blocked",
        outputs: [{ value: { error: "Output withheld by policy." } }]
      };
    }

    this.audit.record(params.request_id, "tool_result_delivered", { tool: payload.tool.name });
    return payload;
  }

  private async executeAndProcessResult(request: import("./acs-types").AcsToolCallRequest, response: import("./acs-types").AcsResponseEnvelope): Promise<import("./acs-types").AcsToolCallResult> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const originalRequestId = params.request_id;

    let exitStatus: "success" | "failure" | "blocked" | "timeout" = "success";
    let outputs: any[] = [];
    try {
      this.audit.record(originalRequestId, "tool_execution_started", { tool: toolName });
      this.correlation.markExecuted(sessionId, originalRequestId);
      const result = await this.gate.execute(request, response);
      outputs = result.outputs || [{ value: result }];
      exitStatus = result.exit_status || "success";
      this.audit.record(originalRequestId, "tool_execution_completed", { tool: toolName });
    } catch (error: unknown) {
      exitStatus = "failure";
      outputs = [{ value: { error: "Tool execution failed", code: "tool_execution_failed" } }];
      this.audit.record(originalRequestId, "tool_execution_blocked", { error: "failed" });
    }

    const resultRequest = {
      jsonrpc: "2.0",
      method: "steps/toolCallResult",
      id: crypto.randomUUID(),
      params: {
        acs_version: "0.1.0",
        request_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        metadata: {
          agent_id: params.metadata.agent_id,
          session_id: sessionId
        },
        payload: {
          tool: { name: toolName },
          request_id_ref: originalRequestId,
          exit_status: exitStatus,
          outputs
        }
      }
    };

    this.audit.record(resultRequest.params.request_id, "tool_result_created", { tool: toolName });
    const signedResultRequest = this.signatureService.signRequest(resultRequest as any);
    return this.processResultRequest(signedResultRequest as any);
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
    return this.executeAndProcessResult(pending.request, pending.response);
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
    this.correlation.clearSession(sessionId);
    // Also clean up any abandoned pending actions for this session
    for (const key of this.pendingActions.keys()) {
      if (key.startsWith(`${sessionId}:`)) {
        this.pendingActions.delete(key);
      }
    }
  }
}

