/**
 * src/replay-guard.ts
 *
 * ACS v0.1.0 §10.3 replay protection for the Phase 2 demo.
 *
 * Implemented semantics (MUST in §10.3):
 *   - Reject timestamps outside the configured skew window with
 *     TIMESTAMP_OUT_OF_WINDOW (-32006).
 *   - Reject duplicate request_id values within the same session_id with
 *     REPLAY_DETECTED (-32005).
 *   - Same request_id in a different session is NOT a replay.
 *
 * State retention (corrected from prior design):
 *   Accepted request_ids are retained for the in-memory lifetime of their
 *   session — NOT pruned on a time window. This matches ACS §10.3: a
 *   duplicate request_id must be rejected for the entire session duration,
 *   even if the replay arrives with a fresh timestamp long after the original.
 *
 *   The caller is responsible for ending a session by calling clearSession().
 *   In this demo, session lifecycle is simplified: full ACS sessionStart /
 *   sessionEnd hook handling is out of scope. GuardedExecutor exposes
 *   clearSession() for tests and the demo to call explicitly.
 *
 *   A prior design pruned entries after skewWindowMs * 2, which would have
 *   allowed a replay within a long-lived session after the prune window
 *   elapsed. That design was incorrect for session-scoped replay protection
 *   and has been removed.
 *
 *   Memory bound: one Set<request_id> per active session. Sessions must be
 *   cleared explicitly. A production deployment should wire clearSession()
 *   to ACS sessionEnd events and back state with a persistent store.
 *
 * Deliberately NOT implemented (documented deviations):
 *   - Nonce replay detection (SHOULD in §10.3, deferred to a future phase).
 *   - skew_window_ms negotiated via ServerHello handshake (not implemented;
 *     window is locally configured).
 *   - Persistent/distributed state (in-memory only; does not survive restart).
 *
 * Security ordering (§10.3):
 *   1. Parse timestamp.
 *   2. Check skew.
 *   3. Check duplicate request_id within session.
 *   4. Record accepted request_id.
 *   A rejected request NEVER reaches Guardian evaluation.
 *   Timestamp is validated BEFORE request_id is recorded, so a stale or
 *   future-skewed request cannot "poison" a valid request_id.
 */

import { AcsToolCallRequest } from "./acs-types";
import { AuditCollector } from "./audit";

// ── ACS error codes (§17.1) ───────────────────────────────────────────────

export const ACS_ERROR_REPLAY_DETECTED = -32005;
export const ACS_ERROR_TIMESTAMP_OUT_OF_WINDOW = -32006;

export class ReplayGuardError extends Error {
  readonly code: number;
  readonly reason_code: string;
  readonly data: Record<string, unknown>;

  constructor(
    code: number,
    reason_code: string,
    message: string,
    data: Record<string, unknown> = {}
  ) {
    super(message);
    this.name = "ReplayGuardError";
    this.code = code;
    this.reason_code = reason_code;
    this.data = data;
  }
}

// ── Clock interface — injectable for deterministic tests ──────────────────

export interface Clock {
  nowMs(): number;
}

export const systemClock: Clock = {
  nowMs: () => Date.now(),
};

// ── ReplayGuard ───────────────────────────────────────────────────────────

export interface ReplayGuardOptions {
  /** Skew tolerance in ms. Default 300000 (5 min), per ACS §10.3. */
  skewWindowMs?: number;
  /** Injectable clock for deterministic tests. */
  clock?: Clock;
  /** Audit collector for rejection events. */
  audit?: AuditCollector;
}

export class ReplayGuard {
  private readonly skewWindowMs: number;
  private readonly clock: Clock;
  private readonly audit: AuditCollector | undefined;

  /**
   * session_id → Set<request_id>.
   *
   * Entries are retained for the lifetime of the session, not time-pruned.
   * Call clearSession(sessionId) when a session ends to release memory.
   */
  private readonly seenIds: Map<string, Set<string>> = new Map();

  constructor(options: ReplayGuardOptions = {}) {
    this.skewWindowMs = options.skewWindowMs ?? 300_000;
    this.clock = options.clock ?? systemClock;
    this.audit = options.audit;
  }

  /**
   * Check a request against replay and timestamp rules.
   *
   * Throws ReplayGuardError on any violation.
   * Returns void on success, after recording the request_id.
   *
   * Security ordering guaranteed:
   *   parse → skew-check → duplicate-check → record
   */
  check(request: AcsToolCallRequest): void {
    const { request_id, timestamp, metadata } = request.params;
    const session_id = metadata.session_id;
    const nowMs = this.clock.nowMs();

    // ── 1 & 2: Parse timestamp and check skew ────────────────────────────
    const requestMs = Date.parse(timestamp);
    if (isNaN(requestMs)) {
      // Local validation — no separate ACS code for unparseable timestamp;
      // we reuse TIMESTAMP_OUT_OF_WINDOW as the closest match.
      this.audit?.record(request_id, "timestamp_rejected", {
        session_id,
        reason_code: "TIMESTAMP_INVALID",
        raw: timestamp,
      });
      throw new ReplayGuardError(
        ACS_ERROR_TIMESTAMP_OUT_OF_WINDOW,
        "TIMESTAMP_INVALID",
        `Timestamp is not a valid ISO 8601 date-time: ${JSON.stringify(timestamp)}`
      );
    }

    const deltaMs = requestMs - nowMs;
    if (Math.abs(deltaMs) > this.skewWindowMs) {
      this.audit?.record(request_id, "timestamp_rejected", {
        session_id,
        reason_code: "TIMESTAMP_OUT_OF_WINDOW",
        delta_ms: deltaMs,
        skew_window_ms: this.skewWindowMs,
      });
      throw new ReplayGuardError(
        ACS_ERROR_TIMESTAMP_OUT_OF_WINDOW,
        "TIMESTAMP_OUT_OF_WINDOW",
        `Timestamp is ${deltaMs > 0 ? "too far in the future" : "too old"} ` +
          `(delta ${deltaMs} ms, window ±${this.skewWindowMs} ms).`,
        { skew_window_ms: this.skewWindowMs, delta_ms: deltaMs }
      );
    }

    // ── 3: Check duplicate request_id within this session ────────────────
    const sessionSet = this.seenIds.get(session_id);
    if (sessionSet?.has(request_id)) {
      this.audit?.record(request_id, "replay_rejected", {
        session_id,
        reason_code: "REPLAY_DETECTED",
      });
      throw new ReplayGuardError(
        ACS_ERROR_REPLAY_DETECTED,
        "REPLAY_DETECTED",
        `Duplicate request_id "${request_id}" detected within session "${session_id}".`
      );
    }

    // ── 4: Record accepted request_id (only after all checks pass) ────────
    if (!this.seenIds.has(session_id)) {
      this.seenIds.set(session_id, new Set());
    }
    this.seenIds.get(session_id)!.add(request_id);
  }

  /**
   * Release all replay state for the given session.
   *
   * Must be called when a session ends. In this demo, session lifecycle is
   * managed explicitly by the caller. A production deployment should wire
   * this to ACS sessionEnd events.
   *
   * Clearing session A does not affect any other session.
   */
  clearSession(sessionId: string): void {
    this.seenIds.delete(sessionId);
  }
}
