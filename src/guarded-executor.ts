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
 *
 * Authority revocation (docs/authority-revocation.md):
 *   revoke(target) is a trusted-integrator API, not reachable from agent requests.
 *   It records a monotonic, in-memory revocation of a capability or a session.
 *   Revoked authority is denied at the request, approval, start and delivery
 *   boundaries. A tool that is already running is NOT stopped and its side
 *   effects are NOT prevented; only its result delivery is withheld.
 *   clearSession() releases session state and never removes a revocation.
 */

import { AcsToolCallRequest, AcsResponseEnvelope, AcsToolCallResult } from "./acs-types";
import { ReplayGuard } from "./replay-guard";
import { Guardian } from "./guardian";
import { ExecutionGate, ExecutionPermit } from "./execution-gate";
import { AuditCollector } from "./audit";
import { SchemaValidator, AddressableSchemaError } from "./schema-validator";
import { SignatureService } from "./signature-service";
import { ExecutionCorrelationStore } from "./execution-correlation";
import * as crypto from "crypto";
import { CapabilityGrantVerifier, CapabilityContext, CapabilityVerificationError, CapabilityGrantV1 } from "./capability-grant";
import { AuthorityRevocationRegistry, parseRevocationTarget, RevocationMatch, RevocationTarget } from "./authority-revocation";

export interface CapabilityLookupContext {
  agent_id: string;
  session_id: string;
  request_id: string;
  tool: string;
}

export interface CapabilityProvider {
  resolve(context: CapabilityLookupContext): unknown | undefined;
}


export type ProcessResult =
  | { status: "executed"; result: AcsToolCallResult }
  | { status: "pending" };

interface PendingAction {
  createdAtMs: number;
  expiresAtMs: number;
  request: AcsToolCallRequest;
  response: AcsResponseEnvelope;
  /** Authority context verified when the ASK was created; the approval is bound to it. */
  agentId: string;
  capability: CapabilityGrantV1;
}

/** Boundary at which revoked authority was enforced. */
export type RevocationStage = "request" | "approval" | "start" | "delivery";

export class AuthorityRevokedError extends Error {
  readonly code = "AUTHORITY_REVOKED";
  readonly stage: RevocationStage;
  readonly reason: RevocationMatch["reason"];
  readonly revocation_id: string;
  constructor(stage: RevocationStage, match: RevocationMatch) {
    super(`Execution blocked (${stage}): authority revoked (${match.reason}, ${match.record.revocation_id})`);
    this.name = "AuthorityRevokedError";
    this.stage = stage;
    this.reason = match.reason;
    this.revocation_id = match.record.revocation_id;
  }
}

/**
 * Acknowledgement of a revoke() call. It states where the revocation is enforced;
 * it does not claim that running tools have stopped or that their effects were prevented.
 */
export interface RevocationReceiptV1 {
  version: 1;
  revocation_id: string;
  target: RevocationTarget;
  /** "already_revoked" for a duplicate call; the original effective point is reported. */
  status: "revoked" | "already_revoked";
  effective_sequence: number;
  effective_at: string;
  enforced_at: RevocationStage[];
  /** request_ids of pending approvals bound to the target; they can no longer execute. */
  pending_approvals: string[];
  /** request_ids of executions already running for the target; they are not stopped. */
  in_flight_executions: string[];
  in_flight_side_effects: "not_prevented";
  persistence: "in_memory_single_runtime_instance";
  /** False if recording the authority_revoked audit event failed; the revocation is in effect regardless. */
  audit_recorded: boolean;
}

function capabilityRejectionReason(err: unknown): string {
  if (err instanceof CapabilityVerificationError) {
    switch (err.code) {
      case "INVALID_SIGNATURE": return "capability_authentication_failed";
      case "AGENT_MISMATCH": return "capability_agent_mismatch";
      case "SESSION_MISMATCH": return "capability_session_mismatch";
      case "TOOL_SCOPE_MISMATCH": return "capability_scope_mismatch";
      case "EXPIRED": return "capability_expired";
      case "NOT_YET_VALID": return "capability_not_yet_valid";
      case "MALFORMED_GRANT": return "capability_malformed";
      case "UNSUPPORTED_SCOPE": return "capability_unsupported_scope";
    }
  }
  return "capability_verification_failed";
}

import { ApprovalGrantVerifier, ApprovalGrantV1, ApprovalVerificationError } from "./approval-verifier";
import { Clock } from "./replay-guard";

export class GuardedExecutor {
  private readonly schemaValidator: SchemaValidator;
  private readonly signatureService: SignatureService;
  private readonly replayGuard: ReplayGuard;
  private readonly guardian: Guardian;
  private readonly audit: AuditCollector;
  private readonly correlation: ExecutionCorrelationStore;
  private readonly approvalVerifier: ApprovalGrantVerifier;
  private readonly clock: Clock;
  private readonly capabilityProvider: CapabilityProvider;
  private readonly capabilityVerifier: CapabilityGrantVerifier;
  private readonly approvalFutureSkewMs: number;
  #permitAuthority = Symbol("ExecutionAuthority");
  #gate: ExecutionGate;
  #revocations = new AuthorityRevocationRegistry();
  #inFlight = new Map<number, { sessionId: string; requestId: string; capabilityId: string }>();
  #inFlightSeq = 0;

  // Keyed by: `${session_id}:${request_id}`
  private readonly pendingActions: Map<string, PendingAction> = new Map();

  constructor(
    schemaValidator: SchemaValidator,
    signatureService: SignatureService,
    replayGuard: ReplayGuard,
    guardian: Guardian,
    audit: AuditCollector,
    correlation: ExecutionCorrelationStore,
    approvalVerifier: ApprovalGrantVerifier,
    clock: Clock = { nowMs: () => Date.now() },
    approvalFutureSkewMs: number = 30000,
    capabilityProvider: CapabilityProvider,
    capabilityVerifier: CapabilityGrantVerifier
  ) {
    this.schemaValidator = schemaValidator;
    this.signatureService = signatureService;
    this.replayGuard = replayGuard;
    this.guardian = guardian;
    this.audit = audit;
    this.correlation = correlation;
    this.approvalVerifier = approvalVerifier;
    this.clock = clock;
    this.capabilityProvider = capabilityProvider;
    if (!capabilityProvider) {
      throw new Error("Constructor Invariant Violation: capabilityProvider is required");
    }
    if (!capabilityVerifier) {
      throw new Error("Constructor Invariant Violation: capabilityVerifier is required");
    }
    this.capabilityVerifier = capabilityVerifier;
    if (typeof approvalFutureSkewMs !== 'number' || !Number.isFinite(approvalFutureSkewMs) || approvalFutureSkewMs < 0) {
      throw new Error("approvalFutureSkewMs must be a non-negative finite number");
    }
    this.approvalFutureSkewMs = approvalFutureSkewMs;
    this.#gate = new ExecutionGate(audit, this.#permitAuthority);
  }

  /**
   * Process a single untrusted tool-call request through the full enforcement stack.
   *
   * 0. Validates schema (throws AddressableSchemaError or SchemaValidationError on failure).
   * 0.5. Verifies envelope signature (throws SignatureInvalidError).
   * 1. ReplayGuard checks timestamp or replay violations.
   * 2. Resolves and verifies the scoped capability from authenticated request context.
   * 3. Guardian policy is evaluated.
   * 4. ASK requires tool-bound ApprovalGrantV2; ALLOW proceeds to execution.
   * 5. Execution result passes through correlation and the Result Guardian before delivery.
   */

  private secureOutboundResponse(rawResponse: import("./acs-types").AcsResponseEnvelope, sessionId: string): import("./acs-types").AcsResponseEnvelope {
    let response = this.schemaValidator.validateResponse(rawResponse);
    response = this.signatureService.signResponse(response, sessionId);
    this.schemaValidator.validateResponse(response);
    this.signatureService.verifyResponse(response, sessionId);
    return response;
  }

  async process(input: unknown): Promise<ProcessResult> {
    // Step 0 — Schema validation
    let request: import("./acs-types").AcsToolCallRequest;
    try {
      const validated = this.schemaValidator.validateRequest(input);
      if (validated.method !== "steps/toolCallRequest") {
        throw new Error("Expected toolCallRequest");
      }
      request = validated as import("./acs-types").AcsToolCallRequest;
    } catch (error: unknown) {
      if (error instanceof AddressableSchemaError) {
        const rawResponse: import("./acs-types").AcsResponseEnvelope = {
          jsonrpc: "2.0",
          id: error.rpcId,
          result: {
            type: "final",
            acs_version: "0.1.0",
            request_id: error.requestId,
            decision: "deny",
            reasoning: error.message,
            reason_codes: ["schema_validation_failed"]
          }
        };
        error.acsResponse = this.secureOutboundResponse(rawResponse, error.sessionId);
      }
      throw error;
    }
    const { params } = request;

    // Step 0.5 — Signature verification
    this.signatureService.verifyRequest(request);

    // Step 1 — replay/timestamp gate (throws on any violation)
    this.replayGuard.check(request);

    // Record request after replay passes
    this.audit.record(params.request_id, "tool_call_requested", {
      session_id: params.metadata.session_id,
      tool: params.payload.tool.name,
    });

    // Revoked session: denied before any capability is resolved.
    this.#denyIfRevoked("request", params.request_id, {
      session_id: params.metadata.session_id,
      tool: params.payload.tool.name,
    });



    // Capability verification (WP-06B Strategy A)
    const expectedAgentId = params.metadata.agent_id || "unknown";
    const expectedSessionId = params.metadata.session_id;
    const requestedTool = params.payload.tool.name;

    let rawCap: unknown;
    try {
      rawCap = this.capabilityProvider.resolve({
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        request_id: params.request_id,
        tool: requestedTool
      });
    } catch (e: any) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: "capability_provider_error",
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error("Capability provider error: " + e.message);
    }

    if (!rawCap) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: "missing_capability",
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error("Missing capability");
    }

    let verifiedCapability: CapabilityGrantV1;
    try {
      verifiedCapability = this.capabilityVerifier.verify(rawCap, {
        expectedAgentId,
        expectedSessionId,
        requestedTool
      });
    } catch (err: any) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: capabilityRejectionReason(err),
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error("Capability rejected: " + err.message);
    }

    // One capability_id must name one grant, so that revoking an id is unambiguous.
    if (!this.#revocations.bindCapability(verifiedCapability)) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: "capability_id_conflict",
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error("Capability rejected: capability_id is already bound to a different grant");
    }

    this.#denyIfRevoked("request", params.request_id, {
      session_id: expectedSessionId,
      capability_id: verifiedCapability.capability_id,
      tool: requestedTool,
    });

    this.audit.record(params.request_id, "capability_verified", {
      capability_id: verifiedCapability.capability_id,
      agent_id: expectedAgentId,
      session_id: expectedSessionId,
      tool: requestedTool
    });

    // Step 2 — deterministic Guardian policy (and outbound validation)
    const rawResponse = this.guardian.evaluate(request);
    const response = this.secureOutboundResponse(rawResponse, params.metadata.session_id);

    this.audit.record(params.request_id, "guardian_decision", {
      session_id: params.metadata.session_id,
      decision: response.result.decision,
      reason_codes: response.result.reason_codes,
    });

    // Step 3 — branch on decision
    if (response.result.decision === "deny") {
      this.audit.record(params.request_id, "tool_execution_blocked", { reason: "denied" });
      throw new Error(`Execution blocked (deny): ${response.result.reasoning ?? response.result.reason_codes?.[0]}`);
    }

    if (response.result.decision === "ask") {
      const askDetails = response.result.ask_details;
      if (!askDetails) throw new Error("Missing ask_details for ASK decision");

      if (askDetails.approver.type !== "human") {
        this.audit.record(params.request_id, "tool_execution_blocked", { reason: "unsupported_approver_type" });
        throw new Error("Local profile requires human approval only; agent/service is unsupported.");
      }

      if (askDetails.timeout_disposition === "allow") {
        this.audit.record(params.request_id, "tool_execution_blocked", { reason: "timeout_disposition_allow_rejected" });
        throw new Error("Local profile requires timeout_disposition to be deny or absent; allow is deliberately unsupported.");
      }

      const nowMs = this.clock.nowMs();
      const createdAtMs = nowMs;
      const expiresAtMs = nowMs + (askDetails.timeout_seconds * 1000);
      const key = `${params.metadata.session_id}:${params.request_id}`;
      // Deep clone to prevent caller mutations
      const snapshotRequest = JSON.parse(JSON.stringify(request));
      const snapshotResponse = JSON.parse(JSON.stringify(response));
      const snapshotCapability = JSON.parse(JSON.stringify(verifiedCapability)) as CapabilityGrantV1;
      this.pendingActions.set(key, { request: snapshotRequest, response: snapshotResponse, createdAtMs, expiresAtMs, agentId: expectedAgentId, capability: snapshotCapability });
      this.audit.record(params.request_id, "approval_requested", { session_id: params.metadata.session_id });
      return { status: "pending" };
    }

    // decision === "allow"
    const result = await this.executeAndProcessResult(request, response, verifiedCapability.capability_id);
    return { status: "executed", result };
  }


  private async processResultRequest(signedResultRequest: import("./acs-types").AcsToolCallResultRequest, authority: { sessionId: string; capabilityId: string }): Promise<import("./acs-types").AcsToolCallResult> {
    let request: import("./acs-types").AcsToolCallResultRequest;
    try {
      const validated = this.schemaValidator.validateRequest(signedResultRequest);
      if (validated.method !== "steps/toolCallResult") {
        throw new Error("Unexpected request method in result processing");
      }
      request = validated as import("./acs-types").AcsToolCallResultRequest;
    } catch (error: unknown) {
      if (error instanceof AddressableSchemaError) {
        const rawResponse: import("./acs-types").AcsResponseEnvelope = {
          jsonrpc: "2.0",
          id: error.rpcId,
          result: {
            type: "final",
            acs_version: "0.1.0",
            request_id: error.requestId,
            decision: "deny",
            reasoning: error.message,
            reason_codes: ["schema_validation_failed"]
          }
        };
        error.acsResponse = this.secureOutboundResponse(rawResponse, error.sessionId);
      }
      throw error;
    }
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const requestIdRef = params.payload.request_id_ref;

    this.signatureService.verifyRequest(request);
    this.replayGuard.check(request);
    this.correlation.validateAndConsume(sessionId, requestIdRef, request.params.payload.tool.name, {
      audit: this.audit,
      resultRequestId: params.request_id,
      sessionId,
      tool: request.params.payload.tool.name,
    });

    const rawResponse = this.guardian.evaluateResult(request);
    const response = this.secureOutboundResponse(rawResponse, sessionId);

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

    // Delivery fence: the authority bound to the execution is checked synchronously immediately before
    // the result is handed back to the caller of process()/resolveApproval(). The tool's side effects
    // have already happened and are not undone.
    const revoked = this.#revocationAt("delivery", params.request_id, {
      session_id: authority.sessionId,
      capability_id: authority.capabilityId,
      tool: payload.tool.name,
    }, { request_id_ref: requestIdRef });
    if (revoked) {
      try {
        this.audit.record(params.request_id, "tool_result_withheld", { tool: payload.tool.name, reason: revoked.reason });
      } catch {
        // Audit failure must not turn a withheld result into a delivery.
      }
      return {
        tool: payload.tool,
        request_id_ref: requestIdRef,
        exit_status: "blocked",
        outputs: [{ value: { error: "Output withheld: authority revoked.", code: revoked.reason } }]
      };
    }

    this.audit.record(params.request_id, "tool_result_delivered", { tool: payload.tool.name });
    return payload;
  }

  private async executeAndProcessResult(request: import("./acs-types").AcsToolCallRequest, response: import("./acs-types").AcsResponseEnvelope, capabilityId: string): Promise<import("./acs-types").AcsToolCallResult> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const originalRequestId = params.request_id;

    // Start fence: the last check before the permit is minted and the tool is invoked. From here to the
    // tool invocation there is no asynchronous boundary, so a revocation cannot slip in between.
    this.#denyIfRevoked("start", originalRequestId, { session_id: sessionId, capability_id: capabilityId, tool: toolName });
    const flight = ++this.#inFlightSeq;
    this.#inFlight.set(flight, { sessionId, requestId: originalRequestId, capabilityId });
    try {
      return await this.#runAndProcessResult(request, capabilityId);
    } finally {
      this.#inFlight.delete(flight);
    }
  }

  async #runAndProcessResult(request: import("./acs-types").AcsToolCallRequest, capabilityId: string): Promise<import("./acs-types").AcsToolCallResult> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const originalRequestId = params.request_id;

    let exitStatus: "success" | "failure" | "blocked" | "timeout" = "success";
    let outputs: import("./acs-types").AcsToolCallResult["outputs"] = [];
    try {
      this.correlation.registerExecution(sessionId, originalRequestId, toolName);

      const permit = this.#gate.mintPermit(this.#permitAuthority, sessionId, originalRequestId, toolName);
      const result = await this.#gate.execute(request, permit);

      outputs = result.outputs || [{ value: result }];
      exitStatus = result.exit_status || "success";
    } catch (error: unknown) {
      exitStatus = "failure";
      outputs = [{ value: { error: "Tool execution failed", code: "tool_execution_failed" } }];
      this.audit.record(originalRequestId, "tool_execution_blocked", { error: "failed" });
    }

    const resultRequest: import("./acs-types").AcsToolCallResultRequest = {
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
    const signedResultRequest = this.signatureService.signRequest(resultRequest);
    return this.processResultRequest(signedResultRequest, { sessionId, capabilityId });
  }

  /**
   * Resolve an approval grant (approve or reject).
   */
  /**
   * @param skewMs The maximum allowed future skew for issued_at. Default 30000ms (30s).
   */
  async resolveApproval(input: unknown): Promise<import("./acs-types").AcsToolCallResult | void> {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new Error("Validation Error: input must be a JSON object");
    }
    const rawGrant = input as Record<string, unknown>;
    const sessionId = rawGrant.session_id as string;
    const requestId = rawGrant.request_id as string;
    
    if (!sessionId || !requestId) {
      this.audit.record("unknown", "approval_verification_failed", { reason: "missing_ids" });
      throw new Error("Validation Error: missing session_id or request_id");
    }

    const key = `${sessionId}:${requestId}`;
    const pending = this.pendingActions.get(key);

    if (!pending) {
      this.audit.record(requestId, "approval_verification_failed", { reason: "pending_action_not_found" });
      throw new Error(`No pending action found for session ${sessionId}, request ${requestId}`);
    }

    const trustedApprover = pending.response.result.ask_details!.approver;

    if (trustedApprover.type !== "human") {
      throw new Error(
        "Invariant Violation: pending action approver must be human"
      );
    }

    const trustedContext = {
      expectedSessionId: pending.request.params.metadata.session_id,
      expectedRequestId: pending.request.params.request_id,
      expectedTool: pending.request.params.payload.tool.name,
      expectedApproverType: trustedApprover.type,
      expectedApproverId: trustedApprover.id,
    };

    let grant;
    try {
      grant = this.approvalVerifier.verifyV2(input, trustedContext);
    } catch (err: any) {
      let reason = "approval_verification_failed";
      if (err instanceof ApprovalVerificationError) {
        switch (err.code) {
          case "V1_REJECTED": reason = "v1_rejected"; break;
          case "TOOL_BINDING_MISMATCH": reason = "tool_binding_mismatch"; break;
          case "INVALID_SIGNATURE": reason = "invalid_signature"; break;
          case "WRONG_APPROVER_IDENTITY": reason = "wrong_approver_identity"; break;
          case "MALFORMED_GRANT": reason = "malformed_grant"; break;
          case "SESSION_MISMATCH": reason = "session_mismatch"; break;
          case "REQUEST_MISMATCH": reason = "request_mismatch"; break;
        }
      }
      this.audit.record(requestId, "approval_verification_failed", { 
        reason, 
        session_id: trustedContext.expectedSessionId,
        expected_tool: trustedContext.expectedTool 
      });
      throw err;
    }



    const askDetails = pending.response.result.ask_details!;

    // Freshness check (issued_at)
    const issuedAtMs = Date.parse(grant.issued_at);
    if (issuedAtMs < pending.createdAtMs) {
      throw new Error("Approval grant rejected: issued_at is before ASK creation");
    }
    if (issuedAtMs > this.clock.nowMs() + this.approvalFutureSkewMs) {
      throw new Error("Approval grant rejected: issued_at is unreasonably in the future");
    }

    // Expiry check
    const elapsedMs = this.clock.nowMs() - pending.createdAtMs;
    if (elapsedMs > askDetails.timeout_seconds * 1000) {
      this.pendingActions.delete(key);
      this.audit.record(grant.request_id, "approval_expired", { session_id: grant.session_id });
      throw new Error("Approval grant rejected: pending action has expired");
    }

    // Grant is valid and not expired. Consume pending state.
    this.pendingActions.delete(key);

    if (grant.decision === "reject") {
      this.audit.record(grant.request_id, "human_rejection", {
        approver_type: grant.approver.type,
        approver_id: grant.approver.id,
        session_id: grant.session_id,
        request_id: grant.request_id
      });
      this.audit.record(grant.request_id, "tool_execution_blocked", { reason: "human_rejected" });
      return;
    }

    // decision === "approve"
    const validated = this.schemaValidator.validateRequest(pending.request);
    if (validated.method !== "steps/toolCallRequest") {
      throw new Error("Invalid request method in pending action");
    }
    this.signatureService.verifyRequest(pending.request);

    // Approval fence: re-check the authority the pending action was created under, immediately before
    // execution is allowed. The pending action is already consumed, so a failure here is final.
    const capabilityId = this.#reverifyPendingAuthority(pending);

    this.audit.record(grant.request_id, "human_approval", {
      approver_type: grant.approver.type,
      approver_id: grant.approver.id,
      session_id: grant.session_id,
      request_id: grant.request_id
    });
    return this.executeAndProcessResult(pending.request, pending.response, capabilityId);
  }

  /**
   * Three separate checks, all bound to the original pending request:
   *   1. runtime revocation of its session and of its original capability_id;
   *   2. current validity of the original capability (signature, time window, agent/session/tool);
   *   3. the provider still resolves a valid capability for the identical context.
   * A capability returned by the provider in step 3 is evidence that the context is still authorized;
   * it never replaces the original authority (no regrant contract is defined), and it is itself checked
   * against the revocation registry. Returns the original capability_id the execution stays bound to.
   */
  #reverifyPendingAuthority(pending: PendingAction): string {
    const params = pending.request.params;
    const requestId = params.request_id;
    const sessionId = params.metadata.session_id;
    const tool = params.payload.tool.name;
    const original = pending.capability;
    const reject = (reason: string, message: string): never => {
      this.audit.record(requestId, "capability_rejected", { reason, stage: "approval", agent_id: pending.agentId, session_id: sessionId, tool });
      this.audit.record(requestId, "tool_execution_blocked", { reason });
      throw new Error("Capability rejected at approval: " + message);
    };

    this.#denyIfRevoked("approval", requestId, { session_id: sessionId, capability_id: original.capability_id, tool });

    const ctx: CapabilityContext = { expectedAgentId: pending.agentId, expectedSessionId: sessionId, requestedTool: tool };
    try {
      this.capabilityVerifier.verify(original, ctx);
    } catch (err: any) {
      reject(capabilityRejectionReason(err), err.message);
    }

    let raw: unknown;
    try {
      raw = this.capabilityProvider.resolve({ agent_id: pending.agentId, session_id: sessionId, request_id: requestId, tool });
    } catch (e: any) {
      reject("capability_provider_error", "Capability provider error: " + e.message);
    }
    if (!raw) reject("missing_capability", "Missing capability");
    let current!: CapabilityGrantV1;
    try {
      current = this.capabilityVerifier.verify(raw, ctx);
    } catch (err: any) {
      reject(capabilityRejectionReason(err), err.message);
    }
    if (!this.#revocations.bindCapability(current)) {
      reject("capability_id_conflict", "capability_id is already bound to a different grant");
    }
    this.#denyIfRevoked("approval", requestId, { session_id: sessionId, capability_id: current.capability_id, tool });
    return original.capability_id;
  }

  /**
   * Revoke a capability or a session. Trusted integrator API: it is not reachable through process(),
   * and agent requests cannot invoke it. The revocation takes effect when this call returns its receipt;
   * every request, approval, start and delivery check performed after that point denies the authority.
   * Duplicate calls are idempotent and report the original effective point.
   */
  revoke(input: unknown): RevocationReceiptV1 {
    const target = parseRevocationTarget(input);
    const { record, duplicate } = this.#revocations.revoke(target, this.clock.nowMs());
    const covered = (sessionId: string, capabilityId: string) =>
      target.scope === "session" ? sessionId === target.session_id : capabilityId === target.capability_id;
    const pending_approvals = [...this.pendingActions.values()]
      .filter(p => covered(p.request.params.metadata.session_id, p.capability.capability_id))
      .map(p => p.request.params.request_id)
      .sort();
    const in_flight_executions = [...new Set([...this.#inFlight.values()]
      .filter(f => covered(f.sessionId, f.capabilityId))
      .map(f => f.requestId))]
      .sort();
    const receipt: RevocationReceiptV1 = {
      version: 1,
      revocation_id: record.revocation_id,
      target: { ...record.target },
      status: duplicate ? "already_revoked" : "revoked",
      effective_sequence: record.effective_sequence,
      effective_at: record.effective_at,
      enforced_at: ["request", "approval", "start", "delivery"],
      pending_approvals,
      in_flight_executions,
      in_flight_side_effects: "not_prevented",
      persistence: "in_memory_single_runtime_instance",
      audit_recorded: true,
    };
    try {
      this.audit.record(record.revocation_id, "authority_revoked", {
        revocation_id: record.revocation_id,
        scope: target.scope,
        ...(target.scope === "session" ? { session_id: target.session_id } : { capability_id: target.capability_id }),
        status: receipt.status,
        effective_sequence: record.effective_sequence,
        effective_at: record.effective_at,
        pending_approvals: pending_approvals.length,
        in_flight_executions: in_flight_executions.length,
      });
    } catch {
      // The revocation is already in effect; report the missing evidence instead of undoing it.
      receipt.audit_recorded = false;
    }
    return receipt;
  }

  /** Records enforcement evidence for revoked authority and returns the match; audit failure never re-opens access. */
  #revocationAt(stage: RevocationStage, requestId: string, authority: { session_id: string; capability_id?: string; tool: string }, extra: Record<string, unknown> = {}): RevocationMatch | undefined {
    const match = this.#revocations.check(authority);
    if (!match) return undefined;
    try {
      this.audit.record(requestId, "authority_revocation_enforced", {
        stage,
        decision: "deny",
        reason: match.reason,
        revocation_id: match.record.revocation_id,
        session_id: authority.session_id,
        ...(authority.capability_id !== undefined ? { capability_id: authority.capability_id } : {}),
        tool: authority.tool,
        ...extra,
      });
      if (stage !== "delivery") this.audit.record(requestId, "tool_execution_blocked", { reason: match.reason });
    } catch {
      // Enforcement does not depend on evidence being written.
    }
    return match;
  }

  #denyIfRevoked(stage: Exclude<RevocationStage, "delivery">, requestId: string, authority: { session_id: string; capability_id?: string; tool: string }): void {
    const match = this.#revocationAt(stage, requestId, authority);
    if (match) throw new AuthorityRevokedError(stage, match);
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

