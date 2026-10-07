/**
 * src/authority-revocation.ts
 *
 * Explicit, monotonic authority revocation for one in-process runtime instance.
 *
 * Scope of this version (see docs/authority-revocation.md):
 *   - Targets: a capability (by capability_id) or a session (by session_id).
 *   - State is in memory only. It is not persistent, not distributed and not
 *     shared between processes; a process restart forgets every revocation.
 *   - Revocation is monotonic: there is no un-revoke, and clearing session
 *     state (GuardedExecutor.clearSession) does not touch this registry.
 *   - The registry only answers "is this authority revoked?". It does not stop
 *     a running tool or prevent a side effect that a running tool performs.
 *
 * The registry also binds every capability_id to the exact content of the first
 * signed grant seen with that id, so that one id cannot silently refer to two
 * different authorities (a revocation of an id must mean one thing).
 */
import { createHash } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import type { CapabilityGrantV1 } from "./capability-grant";

export type RevocationTarget =
  | { scope: "capability"; capability_id: string }
  | { scope: "session"; session_id: string };

export type RevocationReason = "capability_revoked" | "session_revoked";

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

/** Validates and normalises an untrusted target object; unknown scopes (tenant, agent, ...) are rejected. */
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
  throw new RevocationTargetError("Unsupported revocation scope: only 'capability' and 'session' are supported");
}

export const revocationIdFor = (target: RevocationTarget): string =>
  target.scope === "capability" ? `capability:${target.capability_id}` : `session:${target.session_id}`;

/** Content fingerprint of a verified grant, excluding its signature. */
export function capabilityFingerprint(grant: CapabilityGrantV1): string {
  const { signature: _signature, ...body } = grant;
  return createHash("sha256").update(canonicalize(body)).digest("hex");
}

export class AuthorityRevocationRegistry {
  private readonly capabilities = new Map<string, RevocationRecord>();
  private readonly sessions = new Map<string, RevocationRecord>();
  private readonly capabilityBindings = new Map<string, string>();
  private sequence = 0;

  /** Records the revocation if it is new; returns the original record and whether this call was a duplicate. */
  revoke(target: RevocationTarget, nowMs: number): { record: RevocationRecord; duplicate: boolean } {
    const store = target.scope === "capability" ? this.capabilities : this.sessions;
    const key = target.scope === "capability" ? target.capability_id : target.session_id;
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

  /** Session revocation is reported first when both apply, so the reason is deterministic. */
  check(authority: { session_id: string; capability_id?: string }): RevocationMatch | undefined {
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
  bindCapability(grant: CapabilityGrantV1): boolean {
    const fingerprint = capabilityFingerprint(grant);
    const bound = this.capabilityBindings.get(grant.capability_id);
    if (bound === undefined) {
      this.capabilityBindings.set(grant.capability_id, fingerprint);
      return true;
    }
    return bound === fingerprint;
  }
}
