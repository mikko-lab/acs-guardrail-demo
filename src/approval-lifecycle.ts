/**
 * src/approval-lifecycle.ts
 *
 * Building blocks of the approval-permit lifecycle (permit mode, docs/approval-permit-lifecycle.md). The operations
 * themselves (process, approve, reject, issuePermit, start) live in GuardedExecutor, which owns the revocation
 * registry, the verifier and the execution gate; this module holds what they share and what can be checked on its
 * own: the lineage record and its transitions, the digests a human approval signs, the per-field start binding
 * comparison, the strict chain-snapshot comparison and the chain-validity part of a final fence.
 *
 * Three things stay separate (plan §1): authority validity (verifier and revocation registry), human approval (the
 * approval part of a lineage) and the permit use right (the permit part). Neither approval nor permit can make
 * revoked or invalid authority valid; every operation re-checks authority at its own effective point.
 */
import * as crypto from "crypto";
import { types } from "util";
import { canonicalize } from "json-canonicalize";
import { capabilityFingerprint, tenantOf, type CapabilityGrant } from "./capability-grant";

/** Executor lifecycle mode. "legacy" (the default) is the v0.5.0 behaviour; "permit" is opt-in. */
export type LifecycleMode = "legacy" | "permit";

export interface LifecycleOptions {
  lifecycle?: LifecycleMode;
  /** Permit lifetime from issuance; capped by the end of the chain's validity window (D16). Default 60 s. */
  permitTtlMs?: number;
  /** Approval lifetime of a lineage approved by policy (Guardian ALLOW), which has no ask_details timeout. Default 300 s. */
  policyApprovalTtlMs?: number;
}

export const DEFAULT_PERMIT_TTL_MS = 60_000;
export const DEFAULT_POLICY_APPROVAL_TTL_MS = 300_000;

/** A lifecycle method called in the wrong executor mode (or resolveApproval() in permit mode). */
export class LifecycleModeError extends Error {
  readonly code = "LIFECYCLE_MODE";
  constructor(readonly operation: string, readonly mode: LifecycleMode) {
    super(mode === "permit"
      ? `${operation}() is not available in permit mode; use approve() / reject(), issuePermit() and start()`
      : `${operation}() requires permit mode (an executor created with { lifecycle: "permit" })`);
    this.name = "LifecycleModeError";
  }
}

/** Where a lifecycle denial was decided. Revocation denials use AuthorityRevokedError with the same stage names. */
export type LifecycleStage = "create" | "approval" | "issue" | "start";

export type BindingField = "session" | "agent" | "tenant" | "tool" | "arguments";

export type LifecycleDenialReason =
  | "not_pending"
  | "not_approved"
  | "permit_not_issued"
  | "permit_consumed"
  | "approval_expired"
  | "permit_expired"
  | "unknown_lineage"
  | "approval_verification_failed"
  | "chain_snapshot_mismatch"
  | "lineage_binding_mismatch"
  | "malformed_lifecycle_call"
  /** Re-verification of the authority failed: capability_expired, capability_not_yet_valid, capability_provider_error, ... */
  | `capability_${string}`
  | "missing_capability"
  | "tenant_mismatch"
  | "session_tenant_conflict";

/**
 * A denied lifecycle operation. A denial never changes lifecycle state, except an expiry the operation observed
 * (approval_expired, permit_expired), which it records.
 */
export class LifecycleDeniedError extends Error {
  readonly code = "LIFECYCLE_DENIED";
  constructor(
    readonly stage: LifecycleStage,
    readonly reason: LifecycleDenialReason,
    readonly lineage_id: string | undefined,
    readonly detail?: { field?: BindingField; sub_reason?: string },
  ) {
    super(`Lifecycle ${stage} denied: ${reason}${detail?.field ? `:${detail.field}` : ""}${detail?.sub_reason ? ` (${detail.sub_reason})` : ""}${lineage_id ? ` [${lineage_id}]` : ""}`);
    this.name = "LifecycleDeniedError";
  }

  /** The reason with its field, as reported in the plan (for example "lineage_binding_mismatch:tool"). */
  get qualifiedReason(): string {
    return this.detail?.field ? `${this.reason}:${this.detail.field}` : this.reason;
  }
}

// ── Digests ───────────────────────────────────────────────────────────────────────────────────────────────────────

const sha256 = (text: string): string => crypto.createHash("sha256").update(text).digest("hex");

/** SHA-256 of the canonical JSON (RFC 8785) of a request's arguments, exactly as the request carries them. */
export function argumentsDigest(args: unknown): string {
  return sha256(canonicalize(args));
}

/** SHA-256 of the canonical { agent_id, session_id, tool, arguments } of a request; signed in ApprovalGrantV3. */
export function requestDigest(fields: { agent_id: string; session_id: string; tool: string; arguments: unknown }): string {
  return sha256(canonicalize({ agent_id: fields.agent_id, session_id: fields.session_id, tool: fields.tool, arguments: fields.arguments }));
}

/** SHA-256 over the content fingerprints of the leaf and its ancestors (parent first); signed in ApprovalGrantV3. */
export function authorityFingerprint(leaf: CapabilityGrant, ancestors: readonly CapabilityGrant[]): string {
  return sha256(canonicalize([capabilityFingerprint(leaf), ...ancestors.map(a => capabilityFingerprint(a))]));
}

// ── Start binding comparison (§5.1) ───────────────────────────────────────────────────────────────────────────────

export interface StartBindings {
  session_id: string;
  agent_id: string;
  tenant_id: string | undefined;
  tool: string;
  arguments_digest: string;
}

/**
 * Compares the fields of a fresh start request R′ with the lineage, one field at a time, in a fixed order. Returns
 * the first field that differs, or null. request_digest is deliberately not compared at start (§5.1.2): equal fields
 * imply an equal digest, and each field comparison stays the only check that separates its field.
 */
export function compareStartBindings(lineage: StartBindings, candidate: StartBindings): BindingField | null {
  if (candidate.session_id !== lineage.session_id) return "session";
  if (candidate.agent_id !== lineage.agent_id) return "agent";
  if (candidate.tenant_id !== lineage.tenant_id) return "tenant";
  if (candidate.tool !== lineage.tool) return "tool";
  if (candidate.arguments_digest !== lineage.arguments_digest) return "arguments";
  return null;
}

// ── Chain snapshot comparison and validity ────────────────────────────────────────────────────────────────────────

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) && !types.isProxy(value);

/**
 * Strict snapshot comparison on the provider's raw answer, before it is verified: the answer must carry the lineage's
 * leaf and exactly its ancestors, member by member, compared by content fingerprint. Unlike the legacy approval
 * comparison, the leaf is always compared, also for a grant without ancestors: a re-issued grant is another
 * authority. Anything that cannot be read or compared (a thenable, a Proxy, a different length, a member whose
 * fingerprint cannot be computed) does not match (fail closed).
 */
export function matchesLineageSnapshot(raw: unknown, leaf: CapabilityGrant, ancestors: readonly CapabilityGrant[]): boolean {
  if (!isPlainObject(raw) || typeof raw.then === "function") return false;
  const envelope = raw.kind === "capability_chain" ? raw : undefined;
  const leafRaw = envelope ? envelope.leaf : raw;
  const ancestorsRaw = envelope ? envelope.ancestors : [];
  if (!Array.isArray(ancestorsRaw) || types.isProxy(ancestorsRaw) || ancestorsRaw.length !== ancestors.length) return false;
  const same = (member: unknown, bound: CapabilityGrant): boolean => {
    if (!isPlainObject(member)) return false;
    try {
      return capabilityFingerprint(member) === capabilityFingerprint(bound);
    } catch {
      return false;
    }
  };
  if (!same(leafRaw, leaf)) return false;
  return ancestors.every((ancestor, i) => same(ancestorsRaw[i], ancestor));
}

/**
 * The chain-validity part of a final fence: every member's validity window must contain `nowMs` (issued_at <= now <
 * expires_at, as the verifier checks). Returns the denial reason, or undefined. Leaf first, then the ancestors.
 */
export function chainValidityAt(members: readonly CapabilityGrant[], nowMs: number): "capability_expired" | "capability_not_yet_valid" | undefined {
  for (const member of members) {
    const issuedAt = Date.parse(member.issued_at);
    const expiresAt = Date.parse(member.expires_at);
    if (!(nowMs >= issuedAt)) return "capability_not_yet_valid";
    if (!(nowMs < expiresAt)) return "capability_expired";
  }
  return undefined;
}

/** The end of the chain's validity window: the earliest expires_at of its members. */
export function chainValidityEnd(members: readonly CapabilityGrant[]): number {
  return Math.min(...members.map(m => Date.parse(m.expires_at)));
}

// ── Lineage record ────────────────────────────────────────────────────────────────────────────────────────────────

export type ApprovalState = "pending" | "approved" | "rejected" | "expired";
export type PermitState = "none" | "issued" | "consumed" | "expired";
export type LifecycleState = "pending" | "approved" | "issued" | "consumed" | "rejected" | "approval_expired" | "permit_expired";

/** The authority an execution started from a lineage is bound to (GuardedExecutor's BoundAuthority shape). */
export interface LineageAuthority {
  readonly sessionId: string;
  readonly capabilityId: string;
  readonly tenantId: string | undefined;
  readonly ancestorIds: readonly string[];
}

/** Immutable bindings, fixed and frozen at creation, before the first callback after verification. */
export interface LineageBindings {
  readonly agent_id: string;
  readonly session_id: string;
  readonly tenant_id: string | undefined;
  readonly tool: string;
  readonly arguments_digest: string;
  /** The chain snapshot: the leaf and its ordered ancestors (parent first), deep-frozen copies. */
  readonly leaf: CapabilityGrant;
  readonly ancestors: readonly CapabilityGrant[];
  /** Approval context: compared only at approve and reject. */
  readonly request_id: string;
  readonly request_digest: string;
  readonly authority_fingerprint: string;
}

/** The part of a lineage prepared from the verified request before the callbacks of process() run. */
export interface LineageDraft {
  readonly bindings: LineageBindings;
  readonly authority: LineageAuthority;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value as object)) deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/**
 * Prepares the bindings of a lineage from a verified request and its verified chain. Everything is copied and frozen
 * here, so no later callback (audit sink, Guardian) can change what the lineage binds.
 */
export function draftLineage(input: {
  agentId: string;
  sessionId: string;
  requestId: string;
  tool: string;
  arguments: unknown;
  leaf: CapabilityGrant;
  ancestors: readonly CapabilityGrant[];
}): LineageDraft {
  const leaf = deepFreeze(clone(input.leaf));
  const ancestors = deepFreeze(clone([...input.ancestors]));
  const args = clone(input.arguments);
  const tenantId = tenantOf(leaf);
  const bindings: LineageBindings = deepFreeze({
    agent_id: input.agentId,
    session_id: input.sessionId,
    tenant_id: tenantId,
    tool: input.tool,
    arguments_digest: argumentsDigest(args),
    leaf,
    ancestors,
    request_id: input.requestId,
    request_digest: requestDigest({ agent_id: input.agentId, session_id: input.sessionId, tool: input.tool, arguments: args }),
    authority_fingerprint: authorityFingerprint(leaf, ancestors),
  });
  const authority: LineageAuthority = Object.freeze({
    sessionId: input.sessionId,
    capabilityId: leaf.capability_id,
    tenantId,
    ancestorIds: Object.freeze(ancestors.map(a => a.capability_id)),
  });
  return { bindings, authority };
}

/**
 * The execution authority of a start: always the lineage's own authority (its chain snapshot A), never the provider's
 * answer for the start request. The provider's verified chain is passed in only so that the choice of source is
 * explicit at the call site and checkable on its own (plan §5.2, §7.5, M71); it is evidence that the context is still
 * authorized and is not used here.
 */
export function startExecutionAuthority(lineage: LineageDraft, _providerChain: { leaf: CapabilityGrant; ancestors: readonly CapabilityGrant[] }): LineageAuthority {
  return lineage.authority;
}

/** Mutable lifecycle state of one lineage. Only GuardedExecutor changes it, at an operation's effective point. */
export class LineageRecord {
  approvalState: ApprovalState = "pending";
  approvedSeq: number | undefined;
  approvedBy: { type: "human" | "policy"; id: string } | undefined;
  decidedAt: string | undefined;
  permitState: PermitState = "none";
  permitId: string | undefined;
  permitExpiresAtMs: number | undefined;
  issuedSeq: number | undefined;
  consumedSeq: number | undefined;
  executionId: string | undefined;
  startRequestId: string | undefined;

  constructor(
    readonly lineageId: string,
    readonly draft: LineageDraft,
    readonly approver: Readonly<{ type: "human" | "policy"; id: string }>,
    readonly createdSeq: number,
    readonly createdAtMs: number,
    readonly approvalExpiresAtMs: number,
  ) {
    Object.freeze(this.approver);
  }

  get bindings(): LineageBindings { return this.draft.bindings; }
  get authority(): LineageAuthority { return this.draft.authority; }

  get state(): LifecycleState {
    if (this.approvalState === "rejected") return "rejected";
    if (this.approvalState === "expired") return "approval_expired";
    if (this.approvalState === "pending") return "pending";
    if (this.permitState === "none") return "approved";
    if (this.permitState === "expired") return "permit_expired";
    return this.permitState;
  }
}

export interface LineageSnapshot {
  lineage_id: string;
  state: LifecycleState;
  bindings: {
    agent_id: string;
    session_id: string;
    tenant_id?: string;
    tool: string;
    arguments_digest: string;
    capability_id: string;
    ancestor_capability_ids: string[];
    request_id: string;
    request_digest: string;
    authority_fingerprint: string;
  };
  approval: {
    state: ApprovalState;
    approver: { type: "human" | "policy"; id: string };
    created_seq: number;
    created_at: string;
    expires_at: string;
    approved_seq?: number;
    decided_at?: string;
  };
  permit: {
    state: PermitState;
    permit_id?: string;
    expires_at?: string;
    issued_seq?: number;
    consumed_seq?: number;
    execution_id?: string;
    start_request_id?: string;
  };
  /** Derived from the revocation registry at read time; revocation is not a lifecycle state. */
  covered_by: { revocation_id: string; reason: string } | null;
}

/** A deep-frozen copy of a lineage; nothing a caller does with it reaches the runtime's record. */
export function snapshotLineage(record: LineageRecord, coveredBy: { revocation_id: string; reason: string } | null): LineageSnapshot {
  const b = record.bindings;
  const iso = (ms: number) => new Date(ms).toISOString();
  const snapshot: LineageSnapshot = {
    lineage_id: record.lineageId,
    state: record.state,
    bindings: {
      agent_id: b.agent_id,
      session_id: b.session_id,
      ...(b.tenant_id !== undefined ? { tenant_id: b.tenant_id } : {}),
      tool: b.tool,
      arguments_digest: b.arguments_digest,
      capability_id: b.leaf.capability_id,
      ancestor_capability_ids: b.ancestors.map(a => a.capability_id),
      request_id: b.request_id,
      request_digest: b.request_digest,
      authority_fingerprint: b.authority_fingerprint,
    },
    approval: {
      state: record.approvalState,
      approver: { ...record.approver },
      created_seq: record.createdSeq,
      created_at: iso(record.createdAtMs),
      expires_at: iso(record.approvalExpiresAtMs),
      ...(record.approvedSeq !== undefined ? { approved_seq: record.approvedSeq } : {}),
      ...(record.decidedAt !== undefined ? { decided_at: record.decidedAt } : {}),
    },
    permit: {
      state: record.permitState,
      ...(record.permitId !== undefined ? { permit_id: record.permitId } : {}),
      ...(record.permitExpiresAtMs !== undefined ? { expires_at: iso(record.permitExpiresAtMs) } : {}),
      ...(record.issuedSeq !== undefined ? { issued_seq: record.issuedSeq } : {}),
      ...(record.consumedSeq !== undefined ? { consumed_seq: record.consumedSeq } : {}),
      ...(record.executionId !== undefined ? { execution_id: record.executionId } : {}),
      ...(record.startRequestId !== undefined ? { start_request_id: record.startRequestId } : {}),
    },
    covered_by: coveredBy ? { ...coveredBy } : null,
  };
  return deepFreeze(snapshot);
}

// ── Receipts ──────────────────────────────────────────────────────────────────────────────────────────────────────

export interface ApprovalReceipt {
  lineage_id: string;
  decision: "approved";
  approved_seq: number;
  approver: { type: "human"; id: string };
  /** False if recording the approval_granted audit event failed; the approval stands regardless. */
  audit_recorded: boolean;
}

export interface RejectionReceipt {
  lineage_id: string;
  decision: "rejected";
  approver: { type: "human"; id: string };
  audit_recorded: boolean;
}

export interface PermitReceipt {
  lineage_id: string;
  permit_id: string;
  issued_seq: number;
  expires_at: string;
  audit_recorded: boolean;
}

/** Validates the untrusted { lineage_id } / { lineage_id, request } argument of issuePermit() and start(). */
export function lineageIdOf(input: unknown, stage: LifecycleStage): string {
  if (!isPlainObject(input)) throw new LifecycleDeniedError(stage, "malformed_lifecycle_call", undefined, { sub_reason: "input must be an object" });
  const id = input.lineage_id;
  if (typeof id !== "string" || id.length === 0 || id.length > 256) {
    throw new LifecycleDeniedError(stage, "malformed_lifecycle_call", undefined, { sub_reason: "lineage_id must be a non-empty string" });
  }
  return id;
}
