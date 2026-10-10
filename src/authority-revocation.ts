/**
 * src/authority-revocation.ts
 *
 * Explicit, monotonic authority revocation for one in-process runtime instance.
 *
 * Scope of this version (see docs/authority-revocation.md):
 *   - Targets: a capability (by capability_id), a session (by session_id) or, in tenancy mode, a tenant
 *     (by tenant_id, covering every grant, session and execution bound to it, including ones first seen later).
 *   - State is in memory only. It is not persistent, not distributed and not
 *     shared between processes; a process restart forgets every revocation.
 *   - Revocation is monotonic: there is no un-revoke, and clearing session
 *     state (GuardedExecutor.clearSession) does not touch this registry.
 *   - The registry only answers "is this authority revoked?". It does not stop
 *     a running tool or prevent a side effect that a running tool performs.
 *
 * The registry also binds every capability_id to the exact content of the first
 * signed grant seen with that id, so that one id cannot silently refer to two
 * different authorities (a revocation of an id must mean one thing). The content
 * includes the tenant_id of a version 2 grant. In tenancy mode it also binds every
 * runtime session_id to the tenant of the first verified grant that names it, so a
 * session belongs to exactly one tenant.
 */
import { createHash } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import type { CapabilityGrant } from "./capability-grant";

export type RevocationTarget =
  | { scope: "capability"; capability_id: string }
  | { scope: "session"; session_id: string }
  | { scope: "tenant"; tenant_id: string };

export type RevocationReason = "capability_revoked" | "session_revoked" | "tenant_revoked";

/** The authority checked at a revocation fence. tenant_id is the start-time or grant-bound tenant, never a request claim. */
export interface CheckedAuthority {
  session_id: string;
  capability_id?: string;
  tenant_id?: string;
}

export interface RevocationRecord {
  revocation_id: string;
  target: RevocationTarget;
  /** Registry-local, strictly increasing order of first revocation. */
  effective_sequence: number;
  /** Runtime clock time of the first revocation. */
  effective_at: string;
}

export interface RevocationMatch {
  reason: RevocationReason;
  record: RevocationRecord;
}

export class RevocationTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevocationTargetError";
  }
}

const MAX_ID_LENGTH = 256;

/** Validates and normalises an untrusted target object; unknown scopes (agent, ...) are rejected. */
export function parseRevocationTarget(input: unknown): RevocationTarget {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new RevocationTargetError("Revocation target must be an object");
  }
  const raw = input as Record<string, unknown>;
  const id = (key: string): string => {
    const value = raw[key];
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_ID_LENGTH) {
      throw new RevocationTargetError(`Revocation target ${key} must be a non-empty string of at most ${MAX_ID_LENGTH} characters`);
    }
    return value;
  };
  const only = (keys: string[]) => {
    for (const key of Object.keys(raw)) {
      if (!keys.includes(key)) throw new RevocationTargetError(`Unexpected revocation target field: ${key}`);
    }
  };
  if (raw.scope === "capability") {
    only(["scope", "capability_id"]);
    return { scope: "capability", capability_id: id("capability_id") };
  }
  if (raw.scope === "session") {
    only(["scope", "session_id"]);
    return { scope: "session", session_id: id("session_id") };
  }
  if (raw.scope === "tenant") {
    only(["scope", "tenant_id"]);
    return { scope: "tenant", tenant_id: id("tenant_id") };
  }
  throw new RevocationTargetError("Unsupported revocation scope: only 'capability', 'session' and 'tenant' are supported");
}

export const revocationIdFor = (target: RevocationTarget): string =>
  target.scope === "capability" ? `capability:${target.capability_id}`
    : target.scope === "session" ? `session:${target.session_id}`
    : `tenant:${target.tenant_id}`;

/** Content fingerprint of a verified grant, excluding its signature. It covers every other field, including tenant_id. */
export function capabilityFingerprint(grant: CapabilityGrant): string {
  const { signature: _signature, ...body } = grant;
  return createHash("sha256").update(canonicalize(body)).digest("hex");
}

export class AuthorityRevocationRegistry {
  private readonly capabilities = new Map<string, RevocationRecord>();
  private readonly sessions = new Map<string, RevocationRecord>();
  private readonly tenants = new Map<string, RevocationRecord>();
  private readonly capabilityBindings = new Map<string, string>();
  private readonly sessionTenants = new Map<string, string>();
  private sequence = 0;

  /** Records the revocation if it is new; returns the original record and whether this call was a duplicate. */
  revoke(target: RevocationTarget, nowMs: number): { record: RevocationRecord; duplicate: boolean } {
    const store = target.scope === "capability" ? this.capabilities : target.scope === "session" ? this.sessions : this.tenants;
    const key = target.scope === "capability" ? target.capability_id : target.scope === "session" ? target.session_id : target.tenant_id;
    const existing = store.get(key);
    if (existing) return { record: existing, duplicate: true };
    const record: RevocationRecord = {
      revocation_id: revocationIdFor(target),
      target: { ...target },
      effective_sequence: ++this.sequence,
      effective_at: new Date(nowMs).toISOString(),
    };
    store.set(key, record);
    return { record, duplicate: false };
  }

  /**
   * Any applicable record denies. When several apply, the broadest scope is reported (tenant, then session, then
   * capability), so the reason is deterministic.
   */
  check(authority: CheckedAuthority): RevocationMatch | undefined {
    if (authority.tenant_id !== undefined) {
      const tenant = this.tenants.get(authority.tenant_id);
      if (tenant) return { reason: "tenant_revoked", record: tenant };
    }
    const session = this.sessions.get(authority.session_id);
    if (session) return { reason: "session_revoked", record: session };
    if (authority.capability_id !== undefined) {
      const capability = this.capabilities.get(authority.capability_id);
      if (capability) return { reason: "capability_revoked", record: capability };
    }
    return undefined;
  }

  /**
   * Binds capability_id to the content of the first verified grant with that id.
   * Returns false if the id is already bound to different content.
   */
  bindCapability(grant: CapabilityGrant): boolean {
    const fingerprint = capabilityFingerprint(grant);
    const bound = this.capabilityBindings.get(grant.capability_id);
    if (bound === undefined) {
      this.capabilityBindings.set(grant.capability_id, fingerprint);
      return true;
    }
    return bound === fingerprint;
  }

  /** The tenant a session is bound to, if any (tenancy mode). */
  sessionTenant(sessionId: string): string | undefined {
    return this.sessionTenants.get(sessionId);
  }

  /** True if the session is already bound to a different tenant. */
  sessionTenantConflicts(sessionId: string, tenantId: string): boolean {
    const bound = this.sessionTenants.get(sessionId);
    return bound !== undefined && bound !== tenantId;
  }

  /**
   * Binds a session to the tenant of the first verified grant that names it. Monotonic: returns false and changes
   * nothing if the session is already bound to a different tenant.
   */
  bindSessionTenant(sessionId: string, tenantId: string): boolean {
    if (this.sessionTenantConflicts(sessionId, tenantId)) return false;
    this.sessionTenants.set(sessionId, tenantId);
    return true;
  }
}
