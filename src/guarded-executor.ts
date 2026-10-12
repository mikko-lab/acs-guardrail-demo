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
 *   It records a monotonic, in-memory revocation of a capability, a session or (tenancy mode) a tenant.
 *   In tenancy mode a capability may come with its issuer-signed ancestor chain (docs/ancestor-chains.md); a
 *   capability revocation also covers every execution, pending approval and request whose bound chain contains it.
 *   Revoked authority is denied at the request, approval, start and delivery
 *   boundaries. The start effective point is the tool function call; the
 *   delivery effective point is the fulfilment of the public process() /
 *   resolveApproval() promise. A tool that is already running is NOT stopped
 *   and its side effects are NOT prevented; only its result delivery is withheld.
 *   clearSession() releases session state and never removes a revocation.
 *
 * Cooperative containment (docs/cooperative-containment.md):
 *   Every tool invocation is a managed execution with its own execution_id and an ExecutionContext
 *   (cancellation signal, runtime-mediated commit fence, registered work). A targeted revoke() requests
 *   cancellation of the matching managed executions after the tombstone exists. Only cooperating tools and
 *   effects performed through ctx.commit() are controlled.
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
import { CapabilityGrantVerifier, CapabilityContext, CapabilityVerificationError, CapabilityGrant, VerifiedCapabilityChain, capabilityFingerprint, tenantOf } from "./capability-grant";
import { AuthorityRevocationRegistry, CheckedAuthority, parseRevocationTarget, RevocationMatch, RevocationTarget, RevocationTargetError } from "./authority-revocation";
import { ExecutionSnapshot, ExecutionTerminal, ManagedExecution, ManagedStateStore, ReadonlyManagedState } from "./managed-execution";
import {
  ApprovalReceipt, argumentsDigest, chainValidityAt, chainValidityEnd, compareStartBindings, DEFAULT_PERMIT_TTL_MS,
  DEFAULT_POLICY_APPROVAL_TTL_MS, draftLineage, LifecycleDeniedError, LifecycleDenialReason, LifecycleMode, LifecycleModeError,
  LifecycleOptions, LifecycleStage, lineageIdOf, LineageAuthority, LineageDraft, LineageRecord, LineageSnapshot,
  matchesLineageSnapshot, ownedRequestSnapshot, PermitReceipt, RejectionReceipt, snapshotLineage, startExecutionAuthority,
} from "./approval-lifecycle";

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

/**
 * process() in permit mode (docs/approval-permit-lifecycle.md) never executes: it returns "pending" (Guardian ASK) or
 * "approved" (Guardian ALLOW) with the new lineage_id. audit_recorded is false if the audit record after the
 * lineage's creation failed; the lineage exists regardless.
 */
export type PermitProcessResult =
  | { status: "pending"; lineage_id: string; audit_recorded: boolean }
  | { status: "approved"; lineage_id: string; audit_recorded: boolean };

/** The result type of process() for an executor mode; legacy mode keeps ProcessResult unchanged. */
export type ProcessResultFor<M extends LifecycleMode> = M extends "permit" ? PermitProcessResult : ProcessResult;

/** start() result: the tool ran under the lineage's permit (its result may be withheld or a failure). */
export interface StartResult { status: "executed"; result: AcsToolCallResult; lineage_id: string }

interface PendingAction {
  createdAtMs: number;
  expiresAtMs: number;
  request: AcsToolCallRequest;
  response: AcsResponseEnvelope;
  /** Authority context verified when the ASK was created; the approval is bound to it. */
  agentId: string;
  capability: CapabilityGrant;
  /** The verified ancestor chain of `capability` at the request (parent first); empty for a grant without a parent. */
  ancestors: CapabilityGrant[];
}

/** Result of internal result processing, before the public hand-over check. */
type ResultOutcome =
  | { delivered: false; result: AcsToolCallResult }
  | { delivered: true; result: AcsToolCallResult; resultRequestId: string; requestIdRef: string; authority: BoundAuthority };

/**
 * The authority an execution is bound to at start: request session, original capability, (tenancy mode) its tenant
 * and the capability_ids of its verified ancestor chain (parent first). Immutable after start.
 */
interface BoundAuthority { sessionId: string; capabilityId: string; tenantId: string | undefined; ancestorIds: readonly string[] }

/** Boundary at which revoked authority was enforced. "issue" exists only in permit mode. */
export type RevocationStage = "request" | "approval" | "issue" | "start" | "delivery";

export class AuthorityRevokedError extends Error {
  readonly code = "AUTHORITY_REVOKED";
  readonly stage: RevocationStage;
  readonly reason: RevocationMatch["reason"];
  readonly revocation_id: string;
  /** Permit mode: which check of the stage denied, the early check or the final fence (docs/approval-permit-lifecycle.md). */
  readonly check: "early" | "final" | undefined;
  constructor(stage: RevocationStage, match: RevocationMatch, check?: "early" | "final") {
    super(`Execution blocked (${stage}${check ? `/${check}` : ""}): authority revoked (${match.reason}, ${match.record.revocation_id})`);
    this.name = "AuthorityRevokedError";
    this.stage = stage;
    this.reason = match.reason;
    this.revocation_id = match.record.revocation_id;
    this.check = check;
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
  /** Permit mode only: lineage_ids covered at the effective point that were pending, approved, or issued and unused. */
  pending_lineages?: string[];
  approved_lineages?: string[];
  unused_permits?: string[];
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
      case "MISSING_TENANT": return "capability_missing_tenant";
      case "MALFORMED_CHAIN": return "capability_malformed_chain";
      case "CHAIN_TOO_DEEP": return "capability_chain_too_deep";
      case "CHAIN_REPEATED_ID": return "capability_chain_repeated_id";
      case "CHAIN_LINK_MISMATCH": return "capability_chain_link_mismatch";
      case "TENANT_CHAIN_MISMATCH": return "capability_tenant_chain_mismatch";
      case "CHAIN_ATTENUATION": return "capability_chain_attenuation";
    }
  }
  return "capability_verification_failed";
}

import { ApprovalGrantVerifier, ApprovalGrantV1, ApprovalVerificationError } from "./approval-verifier";
import { Clock } from "./replay-guard";

/**
 * M is the lifecycle mode ("legacy" by default). It is inferred from the constructor's options, so an executor built
 * with { lifecycle: "permit" } has the permit-mode process() result type and existing code keeps ProcessResult.
 */
export class GuardedExecutor<M extends LifecycleMode = "legacy"> {
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
  #inFlight = new Map<number, { sessionId: string; requestId: string; capabilityId: string; tenantId: string | undefined; ancestorIds: readonly string[] }>();
  /** Tenancy mode, taken from the capability verifier (the single source of the mode). */
  readonly #tenancy: boolean;
  #inFlightSeq = 0;
  #store = new ManagedStateStore();
  #writeManagedState = this.#store.issueWriter();
  #managedStateView = this.#store.view();
  #executions = new Map<string, ManagedExecution>();
  #terminalLog: ExecutionTerminal[] = [];
  #executionSeq = 0;
  #commitSeq = 0;
  readonly #mode: LifecycleMode;
  readonly #permitTtlMs: number;
  readonly #policyApprovalTtlMs: number;
  #lineages = new Map<string, LineageRecord>();
  #lineageSeq = 0;
  #permitSeq = 0;

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
    capabilityVerifier: CapabilityGrantVerifier,
    options: LifecycleOptions & { lifecycle?: M } = {}
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
    this.#tenancy = capabilityVerifier.tenancy === true;
    if (typeof approvalFutureSkewMs !== 'number' || !Number.isFinite(approvalFutureSkewMs) || approvalFutureSkewMs < 0) {
      throw new Error("approvalFutureSkewMs must be a non-negative finite number");
    }
    this.approvalFutureSkewMs = approvalFutureSkewMs;
    this.#gate = new ExecutionGate(audit, this.#permitAuthority);
    const mode = options.lifecycle ?? "legacy";
    if (mode !== "legacy" && mode !== "permit") throw new Error("lifecycle must be 'legacy' or 'permit'");
    this.#mode = mode;
    const ttl = (name: string, value: number | undefined, fallback: number): number => {
      if (value === undefined) return fallback;
      if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive finite number`);
      return value;
    };
    this.#permitTtlMs = ttl("permitTtlMs", options.permitTtlMs, DEFAULT_PERMIT_TTL_MS);
    this.#policyApprovalTtlMs = ttl("policyApprovalTtlMs", options.policyApprovalTtlMs, DEFAULT_POLICY_APPROVAL_TTL_MS);
  }

  /** The executor's lifecycle mode, fixed at construction. */
  get lifecycleMode(): LifecycleMode {
    return this.#mode;
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

  /** Step 0 of process() and start(): schema validation of an untrusted tool-call request. */
  #validateToolCallRequest(input: unknown): import("./acs-types").AcsToolCallRequest {
    try {
      const validated = this.schemaValidator.validateRequest(input);
      if (validated.method !== "steps/toolCallRequest") {
        throw new Error("Expected toolCallRequest");
      }
      return validated as import("./acs-types").AcsToolCallRequest;
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
  }

  process(input: unknown): Promise<ProcessResultFor<M>> {
    // The same promise object: no Promise turn is added between the delivery check and the public fulfilment.
    return this.#process(input) as Promise<ProcessResultFor<M>>;
  }

  async #process(input: unknown): Promise<ProcessResult | PermitProcessResult> {
    // Step 0 — Schema validation. Permit mode validates, verifies, evaluates and binds one runtime-owned, frozen
    // snapshot of the request, never the caller's object (docs/approval-permit-lifecycle.md §3.2).
    const request = this.#validateToolCallRequest(this.#mode === "permit" ? ownedRequestSnapshot(input) : input);
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

    // Revoked session (and, in tenancy mode, the tenant the session is already bound to): denied before any
    // capability is resolved.
    this.#denyIfRevoked("request", params.request_id, {
      session_id: params.metadata.session_id,
      tenant_id: this.#revocations.sessionTenant(params.metadata.session_id),
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

    // The provider returns the leaf grant, or (tenancy mode) the leaf with its complete issuer-signed ancestor chain.
    // Every member is verified before anything is bound; a chain is never assembled from grants seen earlier.
    let verifiedChain: VerifiedCapabilityChain;
    try {
      verifiedChain = this.capabilityVerifier.verifyChain(rawCap, {
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
    const verifiedCapability = verifiedChain.leaf;
    // The verified ancestor binding is immutable from here on, before the first callback (audit sink, Guardian) runs.
    // Callbacks only ever receive copies of it, so nothing they do can change the authority.
    const ancestorIds: readonly string[] = Object.freeze(verifiedChain.ancestors.map(a => a.capability_id));

    // The tenant comes only from the verified grant. A request's own tenant_id claim must match it (tenancy mode).
    const tenantId = tenantOf(verifiedCapability);
    if (this.#tenancy && params.tenant_id !== undefined && params.tenant_id !== tenantId) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: "tenant_mismatch",
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error("Capability rejected: the request's tenant_id does not match the grant's tenant");
    }

    // One capability_id must name one grant, so that revoking an id is unambiguous; one session belongs to one tenant.
    // Every member of the chain is checked before any is bound.
    const conflict = this.#bindVerifiedChain(verifiedChain);
    if (conflict) {
      this.audit.record(params.request_id, "capability_rejected", {
        reason: conflict,
        agent_id: expectedAgentId,
        session_id: expectedSessionId,
        tool: requestedTool
      });
      throw new Error(conflict === "capability_id_conflict"
        ? "Capability rejected: capability_id is already bound to a different grant"
        : "Capability rejected: the session is already bound to a different tenant");
    }

    this.#denyIfRevoked("request", params.request_id, {
      session_id: expectedSessionId,
      capability_id: verifiedCapability.capability_id,
      tenant_id: tenantId,
      ancestor_capability_ids: ancestorIds,
      tool: requestedTool,
    });

    // Permit mode: the lineage bindings are copied and frozen here, before the first callback after verification
    // (capability_verified audit, Guardian, guardian_decision audit), so no callback can change what is bound.
    const lineageDraft = this.#mode === "permit"
      ? draftLineage({ agentId: expectedAgentId, sessionId: expectedSessionId, requestId: params.request_id, tool: requestedTool, arguments: params.payload.arguments, leaf: verifiedCapability, ancestors: verifiedChain.ancestors })
      : undefined;
    this.audit.record(params.request_id, "capability_verified", {
      capability_id: verifiedCapability.capability_id,
      agent_id: expectedAgentId,
      session_id: expectedSessionId,
      ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
      ...(ancestorIds.length > 0 ? { ancestor_capability_ids: [...ancestorIds] } : {}),
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

    // Permit mode: ASK and ALLOW both create a lineage at the creation fence; process() never starts a tool.
    if (lineageDraft) return this.#createLineage(params.request_id, response, lineageDraft);

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
      const snapshotCapability = JSON.parse(JSON.stringify(verifiedCapability)) as CapabilityGrant;
      const snapshotAncestors = JSON.parse(JSON.stringify(verifiedChain.ancestors)) as CapabilityGrant[];
      this.pendingActions.set(key, { request: snapshotRequest, response: snapshotResponse, createdAtMs, expiresAtMs, agentId: expectedAgentId, capability: snapshotCapability, ancestors: snapshotAncestors });
      this.audit.record(params.request_id, "approval_requested", { session_id: params.metadata.session_id });
      return { status: "pending" };
    }

    // decision === "allow"
    const outcome = await this.executeAndProcessResult(request, response, { sessionId: expectedSessionId, capabilityId: verifiedCapability.capability_id, tenantId, ancestorIds });
    // Nothing may run between the hand-over check and the return that fulfils the public promise.
    return { status: "executed", result: this.#handOver(outcome) };
  }


  private async processResultRequest(signedResultRequest: import("./acs-types").AcsToolCallResultRequest, authority: BoundAuthority): Promise<ResultOutcome> {
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
        delivered: false,
        result: {
          tool: payload.tool,
          request_id_ref: requestIdRef,
          exit_status: "blocked",
          outputs: [{ value: { error: "Output withheld by policy." } }]
        }
      };
    }

    // Early delivery check in result processing. The binding check is #handOver() at the public API return.
    const outcome: ResultOutcome = { delivered: true, result: payload, resultRequestId: params.request_id, requestIdRef, authority };
    const revoked = this.#revocationAt("delivery", params.request_id, {
      session_id: authority.sessionId,
      capability_id: authority.capabilityId,
      tenant_id: authority.tenantId,
      ancestor_capability_ids: authority.ancestorIds,
      tool: payload.tool.name,
    }, { request_id_ref: requestIdRef, boundary: "result_processing" });
    if (revoked) return { delivered: false, result: this.#withheldForRevocation(outcome, revoked) };

    // Records the runtime's delivery decision. It is decision evidence, not proof of hand-over: a revocation
    // that takes effect after this record (including from within it) is still enforced by #handOver().
    this.audit.record(params.request_id, "tool_result_delivered", { tool: payload.tool.name });
    return outcome;
  }

  /**
   * Delivery effective point. Called synchronously by process(), start() and resolveApproval() after their last await,
   * directly in their return statement, so the check is the last runtime action before the public promise is
   * fulfilled with the result. No callback or Promise transition remains between this check and the hand-over.
   */
  #handOver(outcome: ResultOutcome): import("./acs-types").AcsToolCallResult {
    if (!outcome.delivered) return outcome.result;
    const revoked = this.#revocationAt("delivery", outcome.resultRequestId, {
      session_id: outcome.authority.sessionId,
      capability_id: outcome.authority.capabilityId,
      tenant_id: outcome.authority.tenantId,
      ancestor_capability_ids: outcome.authority.ancestorIds,
      tool: outcome.result.tool.name,
    }, { request_id_ref: outcome.requestIdRef, boundary: "api_return" });
    return revoked ? this.#withheldForRevocation(outcome, revoked) : outcome.result;
  }

  #withheldForRevocation(outcome: Extract<ResultOutcome, { delivered: true }>, revoked: RevocationMatch): import("./acs-types").AcsToolCallResult {
    try {
      this.audit.record(outcome.resultRequestId, "tool_result_withheld", { tool: outcome.result.tool.name, reason: revoked.reason });
    } catch {
      // Audit failure must not turn a withheld result into a delivery.
    }
    return {
      tool: outcome.result.tool,
      request_id_ref: outcome.requestIdRef,
      exit_status: "blocked",
      outputs: [{ value: { error: "Output withheld: authority revoked.", code: revoked.reason } }]
    };
  }

  private async executeAndProcessResult(request: import("./acs-types").AcsToolCallRequest, response: import("./acs-types").AcsResponseEnvelope, bound: BoundAuthority): Promise<ResultOutcome> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const originalRequestId = params.request_id;
    // The execution's authority is frozen here; no later fence resolves a grant or a chain again.
    const authority: BoundAuthority = Object.freeze({ sessionId, capabilityId: bound.capabilityId, tenantId: bound.tenantId, ancestorIds: Object.freeze([...bound.ancestorIds]) });
    const { capabilityId, tenantId, ancestorIds } = authority;

    // Early start check, before correlation and permit state are created. The binding start check runs inside
    // ExecutionGate.execute() immediately before the tool function call (see #runAndProcessResult).
    this.#denyIfRevoked("start", originalRequestId, { session_id: sessionId, capability_id: capabilityId, tenant_id: tenantId, ancestor_capability_ids: ancestorIds, tool: toolName });
    const flight = ++this.#inFlightSeq;
    this.#inFlight.set(flight, { sessionId, requestId: originalRequestId, capabilityId, tenantId, ancestorIds });
    try {
      return await this.#runAndProcessResult(request, authority);
    } finally {
      this.#inFlight.delete(flight);
    }
  }

  async #runAndProcessResult(request: import("./acs-types").AcsToolCallRequest, authority: BoundAuthority): Promise<ResultOutcome> {
    const { capabilityId, tenantId, ancestorIds } = authority;
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const originalRequestId = params.request_id;

    let exitStatus: "success" | "failure" | "blocked" | "timeout" = "success";
    let outputs: import("./acs-types").AcsToolCallResult["outputs"] = [];
    try {
      this.correlation.registerExecution(sessionId, originalRequestId, toolName);

      const permit = this.#gate.mintPermit(this.#permitAuthority, sessionId, originalRequestId, toolName);
      // Start effective point: the tool function call. The guard runs after every callback on the start path
      // (including the tool_execution_started audit record) and immediately before the call. The managed
      // execution is created only after the guard passed, without any callback before the call.
      const result = await this.#gate.execute(request, permit, () => {
        this.#denyIfRevoked("start", originalRequestId, { session_id: sessionId, capability_id: capabilityId, tenant_id: tenantId, ancestor_capability_ids: ancestorIds, tool: toolName });
        return (toolFn, args) => this.#startManagedExecution(originalRequestId, authority).invoke(toolFn, args);
      });

      outputs = result.outputs || [{ value: result }];
      exitStatus = result.exit_status || "success";
    } catch (error: unknown) {
      // A start-fence denial is a decision, not a tool failure: it must not be turned into a result.
      if (error instanceof AuthorityRevokedError) throw error;
      exitStatus = "failure";
      outputs = [{ value: { error: "Tool execution failed", code: "tool_execution_failed" } }];
      this.audit.record(originalRequestId, "tool_execution_blocked", { error: "failed" });
    }

    return this.#submitToolResult(request, exitStatus, outputs, authority);
  }

  /** Builds, signs and processes the runtime's own tool-call result request for a finished (or failed) execution. */
  #submitToolResult(
    request: import("./acs-types").AcsToolCallRequest,
    exitStatus: import("./acs-types").AcsToolCallResult["exit_status"],
    outputs: import("./acs-types").AcsToolCallResult["outputs"],
    authority: BoundAuthority
  ): Promise<ResultOutcome> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
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
          request_id_ref: params.request_id,
          exit_status: exitStatus,
          outputs
        }
      }
    };

    this.audit.record(resultRequest.params.request_id, "tool_result_created", { tool: toolName });
    const signedResultRequest = this.signatureService.signRequest(resultRequest);
    return this.processResultRequest(signedResultRequest, authority);
  }

  /**
   * Resolve an approval grant (approve or reject).
   */
  /**
   * @param skewMs The maximum allowed future skew for issued_at. Default 30000ms (30s).
   */
  async resolveApproval(input: unknown): Promise<import("./acs-types").AcsToolCallResult | void> {
    if (this.#mode === "permit") throw new LifecycleModeError("resolveApproval", "permit");
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
    const bound = this.#reverifyPendingAuthority(pending);

    this.audit.record(grant.request_id, "human_approval", {
      approver_type: grant.approver.type,
      approver_id: grant.approver.id,
      session_id: grant.session_id,
      request_id: grant.request_id
    });
    const outcome = await this.executeAndProcessResult(pending.request, pending.response, bound);
    // Nothing may run between the hand-over check and the return that fulfils the public promise.
    return this.#handOver(outcome);
  }

  /**
   * Three separate checks, all bound to the original pending request:
   *   1. runtime revocation of its session, its original capability_id, its tenant (tenancy mode) and every
   *      ancestor in its chain snapshot;
   *   2. current validity of the original capability and of its ancestor chain snapshot (signatures, time windows,
   *      links, tenant, attenuation; agent/session/tool binding of the leaf);
   *   3. the provider still resolves a valid capability for the identical context.
   * A capability returned by the provider in step 3 is evidence that the context is still authorized;
   * it never replaces the original authority (no regrant contract is defined), and it is itself checked
   * against the revocation registry. In tenancy mode it must carry the original tenant. For a chained original the
   * provider's chain must equal the snapshot member by member (leaf and every ancestor), compared before it is
   * verified. Returns the original authority the execution stays bound to.
   */
  #reverifyPendingAuthority(pending: PendingAction): BoundAuthority {
    const params = pending.request.params;
    const requestId = params.request_id;
    const sessionId = params.metadata.session_id;
    const tool = params.payload.tool.name;
    const original = pending.capability;
    const snapshot = pending.ancestors;
    const ancestorIds: readonly string[] = Object.freeze(snapshot.map(a => a.capability_id));
    const tenantId = tenantOf(original);
    const reject = (reason: string, message: string): never => {
      this.audit.record(requestId, "capability_rejected", { reason, stage: "approval", agent_id: pending.agentId, session_id: sessionId, tool });
      this.audit.record(requestId, "tool_execution_blocked", { reason });
      throw new Error("Capability rejected at approval: " + message);
    };

    this.#denyIfRevoked("approval", requestId, { session_id: sessionId, capability_id: original.capability_id, tenant_id: tenantId, ancestor_capability_ids: ancestorIds, tool });

    const ctx: CapabilityContext = { expectedAgentId: pending.agentId, expectedSessionId: sessionId, requestedTool: tool };
    try {
      this.capabilityVerifier.verifyChain(snapshot.length > 0 ? { kind: "capability_chain", leaf: original, ancestors: snapshot } : original, ctx);
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
    if (!this.#matchesChainSnapshot(raw, original, snapshot)) {
      reject("chain_snapshot_mismatch", "the provider's current capability chain differs from the chain verified at the request");
    }
    let current!: VerifiedCapabilityChain;
    try {
      current = this.capabilityVerifier.verifyChain(raw, ctx);
    } catch (err: any) {
      reject(capabilityRejectionReason(err), err.message);
    }
    if (tenantOf(current.leaf) !== tenantId) {
      reject("tenant_mismatch", "the provider's current capability names a different tenant");
    }
    const conflict = this.#bindVerifiedChain(current);
    if (conflict) reject(conflict, conflict === "capability_id_conflict" ? "capability_id is already bound to a different grant" : "the session is already bound to a different tenant");
    this.#denyIfRevoked("approval", requestId, { session_id: sessionId, capability_id: current.leaf.capability_id, tenant_id: tenantId, ancestor_capability_ids: current.ancestors.map(a => a.capability_id), tool });
    return { sessionId, capabilityId: original.capability_id, tenantId, ancestorIds };
  }

  /**
   * Chain snapshot comparison at approval, on the provider's raw answer (before verification). A grant without
   * ancestors keeps the earlier rule (the current grant may be a re-issued grant for the same context) but must not
   * bring ancestors; a chained grant must come back as the same leaf with the same ancestors, member by member,
   * compared by content fingerprint.
   */
  #matchesChainSnapshot(raw: unknown, original: CapabilityGrant, snapshot: readonly CapabilityGrant[]): boolean {
    const envelope = raw !== null && typeof raw === "object" && !Array.isArray(raw) && (raw as Record<string, unknown>).kind === "capability_chain"
      ? raw as Record<string, unknown> : undefined;
    const leafRaw = envelope ? envelope.leaf : raw;
    const ancestorsRaw = envelope ? envelope.ancestors : [];
    if (!Array.isArray(ancestorsRaw) || ancestorsRaw.length !== snapshot.length) return false;
    if (snapshot.length === 0) return true;
    const same = (member: unknown, verified: CapabilityGrant): boolean => {
      if (member === null || typeof member !== "object" || Array.isArray(member)) return false;
      try {
        return capabilityFingerprint(member as Record<string, unknown>) === capabilityFingerprint(verified);
      } catch {
        return false;
      }
    };
    if (!same(leafRaw, original)) return false;
    return snapshot.every((ancestor, i) => same(ancestorsRaw[i], ancestor));
  }

  /**
   * Binds a verified chain (a single grant is a chain of one). Every member's capability_id is bound to its content
   * (including tenant_id and parent reference) and, in tenancy mode, every member's session to its tenant. All
   * conflicts, with earlier bindings and within the chain, are checked before anything is bound, so a rejected chain
   * binds nothing. Returns the conflict, if any.
   */
  #bindVerifiedChain(chain: VerifiedCapabilityChain): "capability_id_conflict" | "session_tenant_conflict" | undefined {
    const members = [chain.leaf, ...chain.ancestors];
    const sessionTenants = new Map<string, string>();
    for (const member of members) {
      const tenantId = tenantOf(member);
      if (tenantId === undefined) continue;
      const seen = sessionTenants.get(member.session_id);
      if (this.#revocations.sessionTenantConflicts(member.session_id, tenantId) || (seen !== undefined && seen !== tenantId)) return "session_tenant_conflict";
      sessionTenants.set(member.session_id, tenantId);
    }
    const contents = new Map<string, string>();
    for (const member of members) {
      const fingerprint = capabilityFingerprint(member);
      const seen = contents.get(member.capability_id);
      if (this.#revocations.capabilityConflicts(member) || (seen !== undefined && seen !== fingerprint)) return "capability_id_conflict";
      contents.set(member.capability_id, fingerprint);
    }
    for (const member of members) {
      this.#revocations.bindCapability(member);
      const tenantId = tenantOf(member);
      if (tenantId !== undefined) this.#revocations.bindSessionTenant(member.session_id, tenantId);
    }
    return undefined;
  }

  /**
   * Revoke a capability or a session. Trusted integrator API: it is not reachable through process(),
   * and agent requests cannot invoke it. The revocation takes effect when this call returns its receipt;
   * every request, approval, start and delivery check performed after that point denies the authority.
   * Duplicate calls are idempotent and report the original effective point.
   */
  revoke(input: unknown): RevocationReceiptV1 {
    const target = parseRevocationTarget(input);
    if (target.scope === "tenant" && !this.#tenancy) {
      // Without tenancy mode no authority carries a tenant, so a tenant revocation could cover nothing.
      throw new RevocationTargetError("Tenant scope requires tenancy mode (a verifier created with { tenancy: true })");
    }
    const { record, duplicate } = this.#revocations.revoke(target, this.clock.nowMs());
    // A capability revocation covers the capability and every authority whose bound chain contains it (descendants).
    const covered = (sessionId: string, capabilityId: string, tenantId: string | undefined, ancestorIds: readonly string[]) =>
      target.scope === "session" ? sessionId === target.session_id
        : target.scope === "capability" ? capabilityId === target.capability_id || ancestorIds.includes(target.capability_id)
        : tenantId !== undefined && tenantId === target.tenant_id;
    const pending_approvals = [...this.pendingActions.values()]
      .filter(p => covered(p.request.params.metadata.session_id, p.capability.capability_id, tenantOf(p.capability), p.ancestors.map(a => a.capability_id)))
      .map(p => p.request.params.request_id)
      .sort();
    const in_flight_executions = [...new Set([...this.#inFlight.values()]
      .filter(f => covered(f.sessionId, f.capabilityId, f.tenantId, f.ancestorIds))
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
    // Permit mode: the cut's reach into the lifecycle (lineages covered at the effective point, by state).
    const lifecycle = this.#mode === "permit" ? this.#coveredLineages(covered) : undefined;
    if (lifecycle) {
      receipt.enforced_at = ["request", "approval", "issue", "start", "delivery"];
      Object.assign(receipt, lifecycle);
    }
    try {
      this.audit.record(record.revocation_id, "authority_revoked", {
        revocation_id: record.revocation_id,
        scope: target.scope,
        ...(target.scope === "session" ? { session_id: target.session_id }
          : target.scope === "capability" ? { capability_id: target.capability_id }
          : { tenant_id: target.tenant_id }),
        status: receipt.status,
        effective_sequence: record.effective_sequence,
        effective_at: record.effective_at,
        pending_approvals: pending_approvals.length,
        in_flight_executions: in_flight_executions.length,
        ...(lifecycle ? { pending_lineages: lifecycle.pending_lineages.length, approved_lineages: lifecycle.approved_lineages.length, unused_permits: lifecycle.unused_permits.length } : {}),
      });
    } catch {
      // The revocation is already in effect; report the missing evidence instead of undoing it.
      receipt.audit_recorded = false;
    }
    // Cancellation of managed executions runs only now, after the tombstone exists. Listener failures and
    // re-entrant calls are contained per execution and cannot undo the revocation.
    for (const execution of [...this.#executions.values()]) {
      if (!execution.terminal && !execution.cancellationRequested && covered(execution.sessionId, execution.capabilityId, execution.tenantId, execution.ancestorIds)) {
        execution.requestCancellation(record.revocation_id);
      }
    }
    return receipt;
  }

  // ── Approval-permit lifecycle (permit mode, docs/approval-permit-lifecycle.md) ────────────────────────────────────

  /**
   * Creation of a lineage at the end of process() in permit mode. The creation fence F(create) runs here, after the
   * last callback of process() (the guardian_decision audit): revocation of every bound scope and chain validity on
   * the executor clock, then the record is created in the same synchronous segment. Nothing is started.
   */
  #createLineage(requestId: string, response: AcsResponseEnvelope, draft: LineageDraft): PermitProcessResult {
    let approver: { type: "human" | "policy"; id: string };
    let approvalTtlMs: number;
    if (response.result.decision === "ask") {
      const askDetails = response.result.ask_details;
      if (!askDetails) throw new Error("Missing ask_details for ASK decision");
      if (askDetails.approver.type !== "human") {
        this.audit.record(requestId, "tool_execution_blocked", { reason: "unsupported_approver_type" });
        throw new Error("Local profile requires human approval only; agent/service is unsupported.");
      }
      if (askDetails.timeout_disposition === "allow") {
        this.audit.record(requestId, "tool_execution_blocked", { reason: "timeout_disposition_allow_rejected" });
        throw new Error("Local profile requires timeout_disposition to be deny or absent; allow is deliberately unsupported.");
      }
      approver = { type: "human", id: askDetails.approver.id };
      approvalTtlMs = askDetails.timeout_seconds * 1000;
    } else {
      approver = { type: "policy", id: "guardian" };
      approvalTtlMs = this.#policyApprovalTtlMs;
    }

    // F(create): revocation, chain validity; the lineage is new, so the state check is "still absent".
    const nowMs = this.clock.nowMs();
    this.#denyIfLineageRevoked("request", requestId, draft.authority, draft.bindings.tool, "final");
    const validity = chainValidityAt([draft.bindings.leaf, ...draft.bindings.ancestors], nowMs);
    if (validity) throw this.#lifecycleDenial("create", validity, undefined, requestId);
    const record = new LineageRecord(`lineage-${++this.#lineageSeq}`, draft, approver, this.#revocations.nextSequence(), nowMs, nowMs + approvalTtlMs);
    if (approver.type === "policy") {
      record.approvalState = "approved";
      record.approvedSeq = this.#revocations.nextSequence();
      record.approvedBy = approver;
      record.decidedAt = new Date(nowMs).toISOString();
    }
    this.#lineages.set(record.lineageId, record);

    // After the effective point: an audit failure is reported, it never undoes the creation.
    const audit_recorded = this.#recordAfterTransition(requestId, approver.type === "human" ? "approval_requested" : "approval_granted", {
      session_id: draft.bindings.session_id,
      lineage_id: record.lineageId,
      ...(approver.type === "policy" ? { approver_type: "policy", approved_seq: record.approvedSeq } : {}),
    });
    return approver.type === "human"
      ? { status: "pending", lineage_id: record.lineageId, audit_recorded }
      : { status: "approved", lineage_id: record.lineageId, audit_recorded };
  }

  /**
   * Approve a pending lineage with a human ApprovalGrantV3 (decision "approve"). Synchronous: no Promise turn exists
   * between the final fence and the transition. Order (plan §5.4): grant verification, early revocation, snapshot-chain
   * validity, provider re-resolution (the last callback), snapshot comparison, verification and binding of the
   * provider's chain, then F(approve) (revocation, chain validity, approval expiry) and the transition pending -> approved.
   */
  approve(input: unknown): ApprovalReceipt {
    this.#requirePermitMode("approve");
    const { record, grant } = this.#verifyDecision(input, "approve");
    const b = record.bindings;
    this.#reverifyLineageAuthority(record, "approval");
    this.#finalFence(record, "approval", b.request_id, record.approvalExpiresAtMs, () => this.#expireApproval(record, "approval"));
    if (record.approvalState !== "pending") throw this.#lifecycleDenial("approval", "not_pending", record, b.request_id);
    record.approvalState = "approved";
    record.approvedSeq = this.#revocations.nextSequence();
    record.approvedBy = { type: "human", id: grant.approver.id };
    record.decidedAt = new Date(this.clock.nowMs()).toISOString();
    const audit_recorded = this.#recordAfterTransition(b.request_id, "approval_granted", {
      approver_type: "human", approver_id: grant.approver.id, session_id: b.session_id, request_id: b.request_id,
      lineage_id: record.lineageId, approved_seq: record.approvedSeq,
    });
    return { lineage_id: record.lineageId, decision: "approved", approved_seq: record.approvedSeq, approver: { type: "human", id: grant.approver.id }, audit_recorded };
  }

  /**
   * Reject a pending lineage with a human ApprovalGrantV3 (decision "reject"). A reject only removes authority, so
   * revocation and validity are not checked; the state must still be pending.
   */
  reject(input: unknown): RejectionReceipt {
    this.#requirePermitMode("reject");
    const { record, grant } = this.#verifyDecision(input, "reject");
    const b = record.bindings;
    if (record.approvalState !== "pending") throw this.#lifecycleDenial("approval", "not_pending", record, b.request_id);
    record.approvalState = "rejected";
    record.decidedAt = new Date(this.clock.nowMs()).toISOString();
    const audit_recorded = this.#recordAfterTransition(b.request_id, "human_rejection", {
      approver_type: "human", approver_id: grant.approver.id, session_id: b.session_id, request_id: b.request_id, lineage_id: record.lineageId,
    });
    return { lineage_id: record.lineageId, decision: "rejected", approver: { type: "human", id: grant.approver.id }, audit_recorded };
  }

  /**
   * Issue the single-use permit of an approved lineage. Synchronous. Order (plan §5.4): state, early revocation,
   * snapshot-chain validity, provider re-resolution (the last callback), snapshot comparison, verification and
   * binding, then F(issue) (revocation, chain validity, approval expiry) and the transition approved -> issued.
   */
  issuePermit(input: unknown): PermitReceipt {
    this.#requirePermitMode("issuePermit");
    const record = this.#lineageFor(lineageIdOf(input, "issue"), "issue");
    const b = record.bindings;
    if (record.state !== "approved") throw this.#lifecycleDenial("issue", "not_approved", record, b.request_id);
    this.#reverifyLineageAuthority(record, "issue");
    this.#finalFence(record, "issue", b.request_id, record.approvalExpiresAtMs, () => this.#expireApproval(record, "issue"));
    if (record.state !== "approved") throw this.#lifecycleDenial("issue", "not_approved", record, b.request_id);
    const nowMs = this.clock.nowMs();
    record.permitState = "issued";
    record.permitId = `permit-${++this.#permitSeq}`;
    record.permitExpiresAtMs = Math.min(nowMs + this.#permitTtlMs, chainValidityEnd([b.leaf, ...b.ancestors]));
    record.issuedSeq = this.#revocations.nextSequence();
    const expires_at = new Date(record.permitExpiresAtMs).toISOString();
    const audit_recorded = this.#recordAfterTransition(b.request_id, "permit_issued", {
      session_id: b.session_id, lineage_id: record.lineageId, permit_id: record.permitId, issued_seq: record.issuedSeq, expires_at,
    });
    return { lineage_id: record.lineageId, permit_id: record.permitId, issued_seq: record.issuedSeq, expires_at, audit_recorded };
  }

  /**
   * Start the approved request of an issued lineage with a fresh signed request R′ ({ lineage_id, request }). R′ goes
   * through schema, signature and replay checks like any request and must carry an unused request_id. The lineage
   * permit is consumed only at the start effective point: inside the gate's final guard, after the
   * tool_execution_started audit, immediately before the tool function call. A start denied before that point
   * leaves the permit unchanged; a start that passed it consumed the permit even if the tool then fails.
   */
  async start(input: unknown): Promise<StartResult> {
    this.#requirePermitMode("start");
    const record = this.#lineageFor(lineageIdOf(input, "start"), "start");
    const b = record.bindings;
    // Copied once at entry: getters, proxies or later caller mutation cannot change what is checked or invoked.
    let entry: unknown;
    try {
      entry = JSON.parse(JSON.stringify((input as Record<string, unknown>).request));
    } catch {
      throw this.#lifecycleDenial("start", "malformed_lifecycle_call", record, "unknown", { sub_reason: "request is not JSON" });
    }
    const request = this.#validateToolCallRequest(entry);
    const { params } = request;
    const requestId = params.request_id;
    const sessionId = params.metadata.session_id;
    const agentId = params.metadata.agent_id || "unknown";
    const tool = params.payload.tool.name;

    this.signatureService.verifyRequest(request);
    this.replayGuard.check(request);
    this.audit.record(requestId, "tool_call_requested", { session_id: sessionId, tool, lineage_id: record.lineageId });

    // Request-stage revocation of R′'s session and its bound tenant, before the provider is asked.
    this.#denyIfRevoked("request", requestId, { session_id: sessionId, tenant_id: this.#revocations.sessionTenant(sessionId), tool });

    // Provider for R′'s context; its answer must be the lineage's chain snapshot (the only authority comparison at start).
    let raw: unknown;
    try {
      raw = this.capabilityProvider.resolve({ agent_id: agentId, session_id: sessionId, request_id: requestId, tool });
    } catch (e: any) {
      throw this.#lifecycleDenial("start", "capability_provider_error", record, requestId, { sub_reason: String(e?.message ?? e) });
    }
    if (!raw) throw this.#lifecycleDenial("start", "missing_capability", record, requestId);
    if (!matchesLineageSnapshot(raw, b.leaf, b.ancestors)) throw this.#lifecycleDenial("start", "chain_snapshot_mismatch", record, requestId);
    let verified!: VerifiedCapabilityChain;
    try {
      verified = this.capabilityVerifier.verifyChain(raw, { expectedAgentId: agentId, expectedSessionId: sessionId, requestedTool: tool });
    } catch (err: any) {
      throw this.#lifecycleDenial("start", capabilityRejectionReason(err) as LifecycleDenialReason, record, requestId);
    }
    const verifiedTenant = tenantOf(verified.leaf);
    if (this.#tenancy && params.tenant_id !== undefined && params.tenant_id !== verifiedTenant) {
      throw this.#lifecycleDenial("start", "tenant_mismatch", record, requestId);
    }
    const conflict = this.#bindVerifiedChain(verified);
    if (conflict) throw this.#lifecycleDenial("start", conflict, record, requestId);
    const verifiedAncestorIds = verified.ancestors.map(a => a.capability_id);
    this.#denyIfRevoked("request", requestId, { session_id: sessionId, capability_id: verified.leaf.capability_id, tenant_id: verifiedTenant, ancestor_capability_ids: verifiedAncestorIds, tool });
    this.audit.record(requestId, "capability_verified", {
      capability_id: verified.leaf.capability_id,
      agent_id: agentId,
      session_id: sessionId,
      ...(verifiedTenant !== undefined ? { tenant_id: verifiedTenant } : {}),
      ...(verifiedAncestorIds.length > 0 ? { ancestor_capability_ids: verifiedAncestorIds } : {}),
      tool,
      lineage_id: record.lineageId,
    });

    // Binding comparisons of R′, field by field (request_digest is not compared at start).
    const field = compareStartBindings(b, { session_id: sessionId, agent_id: agentId, tenant_id: verifiedTenant, tool, arguments_digest: argumentsDigest(params.payload.arguments) });
    if (field) throw this.#lifecycleDenial("start", "lineage_binding_mismatch", record, requestId, { field });

    // Early lineage-state check (fail fast only; it changes nothing). Expiry is part of F(start) only.
    this.#assertPermitUsable(record, requestId);

    // The execution is bound to the lineage's authority (its chain snapshot), never to the provider's answer.
    const authority: BoundAuthority = startExecutionAuthority(record.draft, verified);
    this.#denyIfLineageRevoked("start", requestId, authority, tool, "early", record.lineageId);

    const outcome = await this.#startLineageExecution(record, request, authority);
    // Nothing may run between the hand-over check and the return that fulfils the public promise.
    return { status: "executed", result: this.#handOver(outcome), lineage_id: record.lineageId };
  }

  /** A frozen snapshot copy of one lineage, or undefined. */
  getLineage(lineageId: string): LineageSnapshot | undefined {
    this.#requirePermitMode("getLineage");
    const record = this.#lineages.get(lineageId);
    return record ? snapshotLineage(record, this.#coveredBy(record.authority)) : undefined;
  }

  /** Frozen snapshot copies of every lineage, in creation order. */
  lineages(): LineageSnapshot[] {
    this.#requirePermitMode("lineages");
    return [...this.#lineages.values()].map(record => snapshotLineage(record, this.#coveredBy(record.authority)));
  }

  /** The last allocated value of the authority sequence shared by revocations and lifecycle transitions. */
  authoritySequence(): number {
    return this.#revocations.currentSequence();
  }

  async #startLineageExecution(record: LineageRecord, request: import("./acs-types").AcsToolCallRequest, authority: BoundAuthority): Promise<ResultOutcome> {
    const { params } = request;
    const sessionId = params.metadata.session_id;
    const toolName = params.payload.tool.name;
    const requestId = params.request_id;
    const flight = ++this.#inFlightSeq;
    this.#inFlight.set(flight, { sessionId, requestId, capabilityId: authority.capabilityId, tenantId: authority.tenantId, ancestorIds: authority.ancestorIds });
    try {
      let consumed = false;
      let exitStatus: "success" | "failure" | "blocked" | "timeout" = "success";
      let outputs: import("./acs-types").AcsToolCallResult["outputs"] = [];
      try {
        this.correlation.registerExecution(sessionId, requestId, toolName);
        const permit = this.#gate.mintPermit(this.#permitAuthority, sessionId, requestId, toolName);
        // Start effective point: F(start) and the consumption run inside the gate's final guard, after every callback
        // of the start path (including the tool_execution_started audit), and the managed execution is created and
        // the tool function called in the same synchronous segment.
        const result = await this.#gate.execute(request, permit, () => {
          this.#finalStartFence(record, requestId, authority);
          consumed = true;
          return (toolFn, args) => {
            const execution = this.#startManagedExecution(requestId, authority);
            record.executionId = execution.id;
            return execution.invoke(toolFn, args);
          };
        });
        outputs = result.outputs || [{ value: result }];
        exitStatus = result.exit_status || "success";
      } catch (error: unknown) {
        // Before the effective point every failure is a denial and the permit is unchanged; after it, the start
        // happened, the permit stays consumed and the failure becomes the execution's result.
        if (!consumed) throw error;
        exitStatus = "failure";
        outputs = [{ value: { error: "Tool execution failed", code: "tool_execution_failed" } }];
        this.audit.record(requestId, "tool_execution_blocked", { error: "failed" });
      }
      return await this.#submitToolResult(request, exitStatus, outputs, authority);
    } finally {
      this.#inFlight.delete(flight);
    }
  }

  /** F(start) and the consumption: revocation, chain validity, permit expiry, then the state check-and-set. No callback. */
  #finalStartFence(record: LineageRecord, requestId: string, authority: BoundAuthority): void {
    this.#finalFence(record, "start", requestId, record.permitExpiresAtMs ?? Infinity, () => this.#expirePermit(record, requestId), authority);
    if (record.permitState !== "issued") throw this.#lifecycleDenial("start", record.permitState === "consumed" ? "permit_consumed" : "permit_not_issued", record, requestId);
    record.permitState = "consumed";
    record.consumedSeq = this.#revocations.nextSequence();
    record.startRequestId = requestId;
  }

  #assertPermitUsable(record: LineageRecord, requestId: string): void {
    const state = record.state;
    if (state === "consumed") throw this.#lifecycleDenial("start", "permit_consumed", record, requestId);
    if (state === "permit_expired") throw this.#lifecycleDenial("start", "permit_expired", record, requestId);
    if (state !== "issued") throw this.#lifecycleDenial("start", "permit_not_issued", record, requestId);
  }

  /**
   * The final fence F(op) of approve, issue and start, on the executor clock: revocation of every bound scope, chain
   * validity of the lineage's snapshot, the operation's own expiry. The caller's state check-and-set follows in the
   * same synchronous segment.
   */
  #finalFence(record: LineageRecord, stage: Exclude<LifecycleStage, "create">, requestId: string, expiresAtMs: number, expire: () => Error, authority: LineageAuthority = record.authority): void {
    const b = record.bindings;
    this.#denyIfLineageRevoked(stage, requestId, authority, b.tool, "final", record.lineageId);
    const nowMs = this.clock.nowMs();
    const validity = chainValidityAt([b.leaf, ...b.ancestors], nowMs);
    if (validity) throw this.#lifecycleDenial(stage, validity, record, requestId);
    if (nowMs >= expiresAtMs) throw expire();
  }

  /**
   * Re-verification of a lineage's authority at approve and issue (§5.2): early revocation, current validity of the
   * snapshot chain, provider re-resolution for the original context, the strict snapshot comparison on the raw
   * answer, verification and first-seen binding of the answer. The answer is evidence only; it never replaces the
   * lineage's authority.
   */
  #reverifyLineageAuthority(record: LineageRecord, stage: "approval" | "issue"): void {
    const b = record.bindings;
    const requestId = b.request_id;
    this.#denyIfLineageRevoked(stage, requestId, record.authority, b.tool, "early", record.lineageId);
    const ctx: CapabilityContext = { expectedAgentId: b.agent_id, expectedSessionId: b.session_id, requestedTool: b.tool };
    try {
      this.capabilityVerifier.verifyChain(b.ancestors.length > 0 ? { kind: "capability_chain", leaf: b.leaf, ancestors: [...b.ancestors] } : b.leaf, ctx);
    } catch (err: any) {
      throw this.#lifecycleDenial(stage, capabilityRejectionReason(err) as LifecycleDenialReason, record, requestId);
    }
    let raw: unknown;
    try {
      raw = this.capabilityProvider.resolve({ agent_id: b.agent_id, session_id: b.session_id, request_id: requestId, tool: b.tool });
    } catch (e: any) {
      throw this.#lifecycleDenial(stage, "capability_provider_error", record, requestId, { sub_reason: String(e?.message ?? e) });
    }
    if (!raw) throw this.#lifecycleDenial(stage, "missing_capability", record, requestId);
    if (!matchesLineageSnapshot(raw, b.leaf, b.ancestors)) throw this.#lifecycleDenial(stage, "chain_snapshot_mismatch", record, requestId);
    let current!: VerifiedCapabilityChain;
    try {
      current = this.capabilityVerifier.verifyChain(raw, ctx);
    } catch (err: any) {
      throw this.#lifecycleDenial(stage, capabilityRejectionReason(err) as LifecycleDenialReason, record, requestId);
    }
    if (tenantOf(current.leaf) !== b.tenant_id) throw this.#lifecycleDenial(stage, "tenant_mismatch", record, requestId);
    const conflict = this.#bindVerifiedChain(current);
    if (conflict) throw this.#lifecycleDenial(stage, conflict, record, requestId);
  }

  /** Lineage lookup, state precondition and ApprovalGrantV3 verification shared by approve() and reject(). */
  #verifyDecision(input: unknown, decision: "approve" | "reject"): { record: LineageRecord; grant: import("./approval-verifier").ApprovalGrantV3 } {
    const record = this.#lineageFor(lineageIdOf(input, "approval"), "approval");
    const b = record.bindings;
    if (record.approvalState !== "pending") throw this.#lifecycleDenial("approval", "not_pending", record, b.request_id);
    let grant: import("./approval-verifier").ApprovalGrantV3;
    try {
      grant = this.approvalVerifier.verifyV3(input, {
        expectedLineageId: record.lineageId,
        expectedSessionId: b.session_id,
        expectedRequestId: b.request_id,
        expectedTool: b.tool,
        expectedRequestDigest: b.request_digest,
        expectedAuthorityFingerprint: b.authority_fingerprint,
        expectedApproverType: "human",
        expectedApproverId: record.approver.id,
      });
    } catch (err: any) {
      const sub_reason = err instanceof ApprovalVerificationError ? err.code.toLowerCase() : "approval_verification_failed";
      try {
        this.audit.record(b.request_id, "approval_verification_failed", { reason: sub_reason, session_id: b.session_id, expected_tool: b.tool, lineage_id: record.lineageId });
      } catch {
        // The denial does not depend on evidence being written.
      }
      throw this.#lifecycleDenial("approval", "approval_verification_failed", record, b.request_id, { sub_reason });
    }
    const verificationFailed = (sub_reason: string) => this.#lifecycleDenial("approval", "approval_verification_failed", record, b.request_id, { sub_reason });
    if (grant.decision !== decision) throw verificationFailed("decision_mismatch");
    const issuedAtMs = Date.parse(grant.issued_at);
    if (issuedAtMs < record.createdAtMs) throw verificationFailed("issued_before_request");
    if (issuedAtMs > this.clock.nowMs() + this.approvalFutureSkewMs) throw verificationFailed("issued_in_future");
    return { record, grant };
  }

  #requirePermitMode(operation: string): void {
    if (this.#mode !== "permit") throw new LifecycleModeError(operation, this.#mode);
  }

  #lineageFor(lineageId: string, stage: LifecycleStage): LineageRecord {
    const record = this.#lineages.get(lineageId);
    if (!record) throw this.#lifecycleDenial(stage, "unknown_lineage", undefined, "unknown", { sub_reason: lineageId });
    return record;
  }

  /** Records the observed approval expiry (the only state change a denied operation makes) and returns the denial. */
  #expireApproval(record: LineageRecord, stage: "approval" | "issue"): LifecycleDeniedError {
    if (record.approvalState === "pending" || (record.approvalState === "approved" && record.permitState === "none")) {
      record.approvalState = "expired";
      try {
        this.audit.record(record.bindings.request_id, "approval_expired", { session_id: record.bindings.session_id, lineage_id: record.lineageId });
      } catch {
        // The recorded expiry stands without its audit record.
      }
    }
    return this.#lifecycleDenial(stage, "approval_expired", record, record.bindings.request_id);
  }

  #expirePermit(record: LineageRecord, requestId: string): LifecycleDeniedError {
    if (record.permitState === "issued") {
      record.permitState = "expired";
      try {
        this.audit.record(requestId, "permit_expired", { session_id: record.bindings.session_id, lineage_id: record.lineageId, permit_id: record.permitId });
      } catch {
        // The recorded expiry stands without its audit record.
      }
    }
    return this.#lifecycleDenial("start", "permit_expired", record, requestId);
  }

  /** Records the denial (best effort) and returns the typed error. A denial never depends on evidence being written. */
  #lifecycleDenial(stage: LifecycleStage, reason: LifecycleDenialReason, record: LineageRecord | undefined, requestId: string, detail?: { field?: import("./approval-lifecycle").BindingField; sub_reason?: string }): LifecycleDeniedError {
    const error = new LifecycleDeniedError(stage, reason, record?.lineageId, detail);
    try {
      this.audit.record(requestId, "lifecycle_operation_denied", {
        stage,
        reason,
        ...(detail?.field ? { field: detail.field } : {}),
        ...(record ? { lineage_id: record.lineageId, session_id: record.bindings.session_id } : {}),
      });
    } catch {
      // Enforcement does not depend on evidence being written.
    }
    return error;
  }

  /** An audit record after an effective point: a failure is reported as missing evidence and never undoes the transition. */
  #recordAfterTransition(requestId: string, type: import("./acs-types").AuditEventType, metadata: Record<string, unknown>): boolean {
    try {
      this.audit.record(requestId, type, metadata);
      return true;
    } catch {
      return false;
    }
  }

  #denyIfLineageRevoked(stage: Exclude<RevocationStage, "delivery">, requestId: string, authority: LineageAuthority, tool: string, check: "early" | "final", lineageId?: string): void {
    const match = this.#revocationAt(stage, requestId, {
      session_id: authority.sessionId,
      capability_id: authority.capabilityId,
      tenant_id: authority.tenantId,
      ancestor_capability_ids: authority.ancestorIds,
      tool,
    }, { check, ...(lineageId ? { lineage_id: lineageId } : {}) });
    if (match) throw new AuthorityRevokedError(stage, match, check);
  }

  #coveredBy(authority: LineageAuthority): { revocation_id: string; reason: string } | null {
    const match = this.#revocations.check({ session_id: authority.sessionId, capability_id: authority.capabilityId, tenant_id: authority.tenantId, ancestor_capability_ids: authority.ancestorIds });
    return match ? { revocation_id: match.record.revocation_id, reason: match.reason } : null;
  }

  #coveredLineages(covered: (sessionId: string, capabilityId: string, tenantId: string | undefined, ancestorIds: readonly string[]) => boolean) {
    const lists = { pending_lineages: [] as string[], approved_lineages: [] as string[], unused_permits: [] as string[] };
    for (const record of this.#lineages.values()) {
      const a = record.authority;
      if (!covered(a.sessionId, a.capabilityId, a.tenantId, a.ancestorIds)) continue;
      const state = record.state;
      if (state === "pending") lists.pending_lineages.push(record.lineageId);
      else if (state === "approved") lists.approved_lineages.push(record.lineageId);
      else if (state === "issued") lists.unused_permits.push(record.lineageId);
    }
    return lists;
  }

  /** Read-only view of the runtime-managed state that ctx.commit() writes (the only A2 commit target). */
  get managedState(): ReadonlyManagedState {
    return this.#managedStateView;
  }

  getExecution(executionId: string): ExecutionSnapshot | undefined {
    return this.#executions.get(executionId)?.snapshot();
  }

  /** Every terminal recorded by this executor, in the order the executions became terminal. */
  terminals(): ExecutionTerminal[] {
    return this.#terminalLog.map(t => ({ ...t }));
  }

  whenTerminal(executionId: string): Promise<ExecutionTerminal> {
    const execution = this.#executions.get(executionId);
    if (!execution) return Promise.reject(new Error(`Unknown execution ${executionId}`));
    return execution.terminalPromise;
  }

  /** Creates the managed execution at the start effective point. Must not run any callback. */
  #startManagedExecution(requestId: string, authority: BoundAuthority): ManagedExecution {
    const { sessionId, capabilityId, tenantId, ancestorIds } = authority;
    const execution: ManagedExecution = new ManagedExecution(`exec-${++this.#executionSeq}`, requestId, sessionId, capabilityId, {
      ...(tenantId !== undefined ? { tenantId } : {}),
      ...(ancestorIds.length > 0 ? { ancestorIds } : {}),
      audit: this.audit,
      // The commit fence checks the authority bound at start (tenant and ancestor chain included); nothing is re-resolved.
      revoked: () => {
        const match = this.#revocations.check({ session_id: sessionId, capability_id: capabilityId, tenant_id: tenantId, ancestor_capability_ids: ancestorIds });
        return match ? { reason: match.reason, revocation_id: match.record.revocation_id } : undefined;
      },
      write: (key, json) => this.#writeManagedState(key, json),
      nextCommitId: () => `commit-${++this.#commitSeq}`,
      onTerminal: terminal => { this.#terminalLog.push(Object.freeze({ ...terminal })); },
    });
    this.#executions.set(execution.id, execution);
    return execution;
  }

  /** Records enforcement evidence for revoked authority and returns the match; audit failure never re-opens access. */
  #revocationAt(stage: RevocationStage, requestId: string, authority: CheckedAuthority & { tool: string }, extra: Record<string, unknown> = {}): RevocationMatch | undefined {
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
        ...(authority.tenant_id !== undefined ? { tenant_id: authority.tenant_id } : {}),
        ...(authority.ancestor_capability_ids?.length ? { ancestor_capability_ids: [...authority.ancestor_capability_ids] } : {}),
        tool: authority.tool,
        ...extra,
      });
      if (stage !== "delivery") this.audit.record(requestId, "tool_execution_blocked", { reason: match.reason });
    } catch {
      // Enforcement does not depend on evidence being written.
    }
    return match;
  }

  #denyIfRevoked(stage: Exclude<RevocationStage, "delivery">, requestId: string, authority: CheckedAuthority & { tool: string }): void {
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

