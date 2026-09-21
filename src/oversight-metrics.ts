/**
 * src/oversight-metrics.ts
 *
 * Runtime oversight metrics for ACS Guardrail Demo v0.2.0 — WP-02.
 *
 * Computes read-only metrics from the existing AuditCollector event stream.
 * This is a post-hoc observability layer: it reads audit events and derives
 * aggregate counts, rates, and latencies. It has no influence on Guardian
 * decisions, execution policy, replay semantics, or human approval logic.
 *
 * A metrics computation error never changes a security decision because
 * metrics are derived from already-recorded events, not from the live
 * enforcement path.
 *
 * ── Metric sources ───────────────────────────────────────────────────────────
 *
 *  A. Decision distribution  ← guardian_decision events
 *     (metadata.decision: "allow" | "deny" | "ask")
 *     Note: result_guardian_decision (result-gate) is a different decision
 *     domain and is NOT included in request-gate decision counts.
 *
 *  B. Escalation rate        ← guardian_decision where decision === "ask"
 *                               divided by total guardian_decision count
 *
 *  C. Decision latency       ← tool_call_requested.timestamp →
 *                               guardian_decision.timestamp (same request_id)
 *     Measures the interval from when a request passes replay/schema/sig
 *     checks (tool_call_requested) to when Guardian records its verdict.
 *
 *     Correlation key: session_id + request_id (composite key).
 *     ReplayGuard guarantees request_id uniqueness only within a session.
 *     Therefore, metrics use a composite key to correlate events. If an event
 *     is missing session_id in its metadata, it is excluded from latency
 *     calculations to prevent cross-correlation errors.
 *
 *     Duplicate policy: if two events with the same composite key
 *     (session_id:request_id) and event_type appear, the FIRST occurrence wins.
 *     This is deterministic and conservative.
 *
 *     Negative latency policy: if guardian_decision timestamp precedes
 *     tool_call_requested timestamp (possible if audit events are recorded
 *     out of order or clocks are skewed), that pair is excluded from latency
 *     statistics rather than producing a negative value.
 *
 *  D. Human review latency   ← approval_requested.timestamp →
 *                               (human_approval | human_rejection).timestamp
 *                               (same request_id)
 *     - completed_reviews: resolved by human_approval or human_rejection
 *     - pending_reviews: approval_requested with no terminal event yet
 *     - expired_reviews: approval_expired (NOT a human review completion;
 *       excluded from review latency statistics)
 *     Latency = time from approval_requested to human_approval or
 *     human_rejection only. approval_expired is counted separately.
 *
 *  E. Correlation failures   ← correlation_failed events
 *     (metadata.reason: "unresolved_request_id_ref" | "tool_name_mismatch")
 *
 * ── Coverage — not implemented ───────────────────────────────────────────────
 *   Observed guardian coverage cannot be measured reliably from the current
 *   audit event model without additional instrumentation.
 *
 *   In GuardedExecutor.process(), every request that passes replay/schema/sig
 *   checks produces BOTH a tool_call_requested event AND a guardian_decision
 *   event in immediate succession with no branching between them. This means
 *   the ratio tool_call_requested ∩ guardian_decision / tool_call_requested
 *   is trivially 100% by construction — it measures the code path, not
 *   external supervisory coverage. Reporting it would be misleading.
 *
 *   A meaningful coverage metric would require observability of execution
 *   attempts that bypass GuardedExecutor, which is not available from the
 *   current in-process audit event stream. This is deferred to a future phase
 *   that includes cross-process or network-level telemetry.
 *
 * ── Zero-denominator policy ──────────────────────────────────────────────────
 *   All rate fields return 0 when the denominator is 0 (no NaN, no Infinity).
 */

import { AuditCollector } from "./audit";
import { AuditEvent } from "./acs-types";

// ── Snapshot types ────────────────────────────────────────────────────────────

export interface DecisionLatencyStats {
  count: number;
  min_ms: number | null;
  max_ms: number | null;
  average_ms: number | null;
}

export interface HumanReviewStats {
  /** ASKs resolved by human_approval or human_rejection. */
  completed_reviews: number;
  /** ASKs with no terminal event yet. */
  pending_reviews: number;
  /** ASKs that timed out (approval_expired). NOT included in completed_reviews. */
  expired_reviews: number;
  /**
   * Mean time from approval_requested to human_approval or human_rejection.
   * Null when completed_reviews === 0.
   * approval_expired events are NOT included in this average.
   */
  average_review_latency_ms: number | null;
  min_review_latency_ms: number | null;
  max_review_latency_ms: number | null;
}

export interface CorrelationFailureStats {
  correlation_failure_count: number;
  unresolved_request_id_ref_count: number;
  tool_name_mismatch_count: number;
}

export interface OversightMetricsSnapshot {
  // A. Decision distribution (request gate only)
  allow_count: number;
  deny_count: number;
  ask_count: number;
  total_decisions: number;
  allow_rate: number;
  deny_rate: number;
  ask_rate: number;

  // B. Escalation rate
  escalation_rate: number;

  // C. Decision latency
  decision_latency: DecisionLatencyStats;

  // D. Human review latency
  human_review: HumanReviewStats;

  // E. Correlation failures
  correlation_failures: CorrelationFailureStats;
}

// ── OversightMetrics ──────────────────────────────────────────────────────────

export class OversightMetrics {
  private readonly audit: AuditCollector;

  constructor(audit: AuditCollector) {
    this.audit = audit;
  }

  /**
   * Compute and return a point-in-time snapshot of all oversight metrics.
   * This is a pure read operation: it does not modify the AuditCollector
   * or any runtime state.
   */
  getSnapshot(): OversightMetricsSnapshot {
    const events = this.audit.getEvents();
    return {
      ...computeDecisionDistribution(events),
      ...computeDecisionLatency(events),
      ...computeHumanReview(events),
      correlation_failures: computeCorrelationFailures(events),
    };
  }
}

// ── Internal computation functions ───────────────────────────────────────────
// These are exported for unit-testability without requiring a full AuditCollector.

/**
 * A. Decision distribution + B. Escalation rate.
 * Source: guardian_decision events (request gate only).
 */
export function computeDecisionDistribution(events: AuditEvent[]): {
  allow_count: number;
  deny_count: number;
  ask_count: number;
  total_decisions: number;
  allow_rate: number;
  deny_rate: number;
  ask_rate: number;
  escalation_rate: number;
} {
  let allow_count = 0;
  let deny_count = 0;
  let ask_count = 0;

  for (const ev of events) {
    if (ev.event_type !== "guardian_decision") continue;
    const decision = ev.metadata?.decision;
    if (decision === "allow") allow_count++;
    else if (decision === "deny") deny_count++;
    else if (decision === "ask") ask_count++;
    // Unknown decision values are silently ignored (resilience requirement).
  }

  const total_decisions = allow_count + deny_count + ask_count;
  const safe = total_decisions > 0;

  return {
    allow_count,
    deny_count,
    ask_count,
    total_decisions,
    allow_rate: safe ? allow_count / total_decisions : 0,
    deny_rate: safe ? deny_count / total_decisions : 0,
    ask_rate: safe ? ask_count / total_decisions : 0,
    escalation_rate: safe ? ask_count / total_decisions : 0,
  };
}

/**
 * C. Decision latency.
 * Source: tool_call_requested → guardian_decision pairs (same request_id).
 *
 * Correlation key: session_id + request_id. Events missing session_id are excluded.
 * Duplicate policy: first occurrence of each (event_type, session_id:request_id) wins.
 * Negative latency policy: pairs where guardian_decision timestamp precedes
 *   tool_call_requested timestamp are excluded (not clamped to zero).
 * Incomplete pairs: excluded from latency statistics.
 */
export function computeDecisionLatency(events: AuditEvent[]): {
  decision_latency: DecisionLatencyStats;
} {
  const requestedAt = new Map<string, number>();
  const decidedAt = new Map<string, number>();

  for (const ev of events) {
    const tsMs = Date.parse(ev.timestamp);
    if (isNaN(tsMs)) continue;
    
    const sessionId = ev.metadata?.session_id;
    if (typeof sessionId !== "string") continue;
    
    const key = `${sessionId}:${ev.request_id}`;

    if (ev.event_type === "tool_call_requested") {
      if (!requestedAt.has(key)) {
        requestedAt.set(key, tsMs);
      }
    } else if (ev.event_type === "guardian_decision") {
      if (!decidedAt.has(key)) {
        decidedAt.set(key, tsMs);
      }
    }
  }

  const latencies: number[] = [];
  for (const [key, startMs] of requestedAt) {
    const endMs = decidedAt.get(key);
    if (endMs === undefined) continue;
    const delta = endMs - startMs;
    // Exclude negative deltas: out-of-order or clock-skew artefacts.
    if (delta < 0) continue;
    latencies.push(delta);
  }

  if (latencies.length === 0) {
    return {
      decision_latency: { count: 0, min_ms: null, max_ms: null, average_ms: null },
    };
  }

  return {
    decision_latency: {
      count: latencies.length,
      min_ms: Math.min(...latencies),
      max_ms: Math.max(...latencies),
      average_ms: latencies.reduce((a, b) => a + b, 0) / latencies.length,
    },
  };
}

/**
 * D. Human review latency.
 *
 * Terminal event classification:
 *   human_approval    → completed_reviews (included in latency)
 *   human_rejection   → completed_reviews (included in latency)
 *   approval_expired  → expired_reviews   (NOT included in latency)
 *
 * pending_reviews: approval_requested with no terminal event.
 *
 * Negative latency policy: same as decision latency — negative deltas
 * are excluded rather than clamped.
 */
export function computeHumanReview(events: AuditEvent[]): {
  human_review: HumanReviewStats;
} {
  const askedAt = new Map<string, number>();
  // human resolution timestamps (approval or rejection only)
  const resolvedAt = new Map<string, number>();
  const expiredIds = new Set<string>();

  for (const ev of events) {
    const tsMs = Date.parse(ev.timestamp);
    if (isNaN(tsMs)) continue;

    const sessionId = ev.metadata?.session_id;
    if (typeof sessionId !== "string") continue;
    
    const key = `${sessionId}:${ev.request_id}`;

    if (ev.event_type === "approval_requested") {
      if (!askedAt.has(key)) {
        askedAt.set(key, tsMs);
      }
    } else if (ev.event_type === "human_approval" || ev.event_type === "human_rejection") {
      if (!resolvedAt.has(key)) {
        resolvedAt.set(key, tsMs);
      }
    } else if (ev.event_type === "approval_expired") {
      expiredIds.add(key);
    }
  }

  let pending_reviews = 0;
  let expired_reviews = 0;
  const latencies: number[] = [];

  for (const [key, startMs] of askedAt) {
    if (expiredIds.has(key) && !resolvedAt.has(key)) {
      // Expired with no human resolution.
      expired_reviews++;
    } else {
      const endMs = resolvedAt.get(key);
      if (endMs === undefined) {
        pending_reviews++;
      } else {
        const delta = endMs - startMs;
        // Exclude negative deltas.
        if (delta >= 0) latencies.push(delta);
      }
    }
  }

  const completed_reviews = latencies.length;

  if (completed_reviews === 0) {
    return {
      human_review: {
        completed_reviews: 0,
        pending_reviews,
        expired_reviews,
        average_review_latency_ms: null,
        min_review_latency_ms: null,
        max_review_latency_ms: null,
      },
    };
  }

  return {
    human_review: {
      completed_reviews,
      pending_reviews,
      expired_reviews,
      average_review_latency_ms: latencies.reduce((a, b) => a + b, 0) / completed_reviews,
      min_review_latency_ms: Math.min(...latencies),
      max_review_latency_ms: Math.max(...latencies),
    },
  };
}

/**
 * E. Correlation failures.
 * Source: correlation_failed events.
 */
export function computeCorrelationFailures(events: AuditEvent[]): CorrelationFailureStats {
  let correlation_failure_count = 0;
  let unresolved_request_id_ref_count = 0;
  let tool_name_mismatch_count = 0;

  for (const ev of events) {
    if (ev.event_type !== "correlation_failed") continue;
    correlation_failure_count++;
    const reason = ev.metadata?.reason;
    if (reason === "unresolved_request_id_ref") unresolved_request_id_ref_count++;
    else if (reason === "tool_name_mismatch") tool_name_mismatch_count++;
    // Unknown reasons: counted in total, not in breakdown (resilience).
  }

  return {
    correlation_failure_count,
    unresolved_request_id_ref_count,
    tool_name_mismatch_count,
  };
}
