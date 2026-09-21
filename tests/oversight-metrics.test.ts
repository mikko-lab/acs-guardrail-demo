/**
 * tests/oversight-metrics.test.ts
 *
 * Unit tests for OversightMetrics / WP-02.
 *
 * Strategy: test each computation function in isolation using synthetic
 * AuditEvent arrays, then test OversightMetrics.getSnapshot() end-to-end
 * via AuditCollector.
 */

import { AuditCollector } from "../src/audit";
import { AuditEvent } from "../src/acs-types";
import {
  OversightMetrics,
  computeDecisionDistribution,
  computeDecisionLatency,
  computeHumanReview,
  computeCorrelationFailures,
} from "../src/oversight-metrics";

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeEvent(
  event_type: AuditEvent["event_type"],
  request_id: string,
  metadata?: Record<string, unknown>,
  timestamp?: string,
): AuditEvent {
  const md = metadata ? { ...metadata } : {};
  if (md.session_id === undefined) {
    md.session_id = "test-session";
  }
  return {
    timestamp: timestamp ?? new Date().toISOString(),
    request_id,
    event_type,
    metadata: md,
  };
}

function ts(baseMs: number, deltaMs: number = 0): string {
  return new Date(baseMs + deltaMs).toISOString();
}

// ─────────────────────────────────────────────────────────────────────────────
// A + B: Decision distribution and escalation rate
// ─────────────────────────────────────────────────────────────────────────────

describe("A+B: computeDecisionDistribution", () => {
  it("empty events → all counts zero, all rates zero (no NaN, no Infinity)", () => {
    const r = computeDecisionDistribution([]);
    expect(r.allow_count).toBe(0);
    expect(r.deny_count).toBe(0);
    expect(r.ask_count).toBe(0);
    expect(r.total_decisions).toBe(0);
    expect(r.allow_rate).toBe(0);
    expect(r.deny_rate).toBe(0);
    expect(r.ask_rate).toBe(0);
    expect(r.escalation_rate).toBe(0);
    expect(Number.isFinite(r.allow_rate)).toBe(true);
    expect(Number.isFinite(r.escalation_rate)).toBe(true);
  });

  it("single ALLOW decision", () => {
    const events = [makeEvent("guardian_decision", "req-1", { decision: "allow" })];
    const r = computeDecisionDistribution(events);
    expect(r.allow_count).toBe(1);
    expect(r.deny_count).toBe(0);
    expect(r.ask_count).toBe(0);
    expect(r.total_decisions).toBe(1);
    expect(r.allow_rate).toBe(1);
    expect(r.deny_rate).toBe(0);
    expect(r.ask_rate).toBe(0);
  });

  it("ALLOW + DENY + ASK: counts and rates correct", () => {
    const events = [
      makeEvent("guardian_decision", "req-1", { decision: "allow" }),
      makeEvent("guardian_decision", "req-2", { decision: "deny" }),
      makeEvent("guardian_decision", "req-3", { decision: "ask" }),
      makeEvent("guardian_decision", "req-4", { decision: "allow" }),
    ];
    const r = computeDecisionDistribution(events);
    expect(r.allow_count).toBe(2);
    expect(r.deny_count).toBe(1);
    expect(r.ask_count).toBe(1);
    expect(r.total_decisions).toBe(4);
    expect(r.allow_rate).toBeCloseTo(0.5);
    expect(r.deny_rate).toBeCloseTo(0.25);
    expect(r.ask_rate).toBeCloseTo(0.25);
  });

  it("rates sum to 1 for mixed decisions", () => {
    const events = [
      makeEvent("guardian_decision", "r1", { decision: "allow" }),
      makeEvent("guardian_decision", "r2", { decision: "deny" }),
      makeEvent("guardian_decision", "r3", { decision: "ask" }),
    ];
    const r = computeDecisionDistribution(events);
    expect(r.allow_rate + r.deny_rate + r.ask_rate).toBeCloseTo(1);
  });

  it("non-guardian_decision events are ignored", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", { tool: "x" }),
      makeEvent("guardian_decision", "req-2", { decision: "deny" }),
      makeEvent("tool_execution_started", "req-1"),
    ];
    const r = computeDecisionDistribution(events);
    expect(r.total_decisions).toBe(1);
    expect(r.deny_count).toBe(1);
  });

  it("unknown decision value is ignored (resilience)", () => {
    const events = [
      makeEvent("guardian_decision", "req-1", { decision: "allow" }),
      makeEvent("guardian_decision", "req-2", { decision: "unknown_future_value" }),
    ];
    const r = computeDecisionDistribution(events);
    expect(r.total_decisions).toBe(1);
    expect(r.allow_count).toBe(1);
  });

  it("result_guardian_decision events are NOT counted (separate domain)", () => {
    const events = [
      makeEvent("result_guardian_decision", "req-1", { decision: "allow" }),
      makeEvent("result_guardian_decision", "req-2", { decision: "deny" }),
    ];
    const r = computeDecisionDistribution(events);
    expect(r.total_decisions).toBe(0);
  });
});

describe("B: escalation_rate", () => {
  it("all ASK → escalation_rate = 1", () => {
    const events = [
      makeEvent("guardian_decision", "r1", { decision: "ask" }),
      makeEvent("guardian_decision", "r2", { decision: "ask" }),
    ];
    expect(computeDecisionDistribution(events).escalation_rate).toBe(1);
  });

  it("no ASK → escalation_rate = 0", () => {
    const events = [
      makeEvent("guardian_decision", "r1", { decision: "allow" }),
      makeEvent("guardian_decision", "r2", { decision: "deny" }),
    ];
    expect(computeDecisionDistribution(events).escalation_rate).toBe(0);
  });

  it("2 ASK of 5 total → escalation_rate = 0.4", () => {
    const events = [
      makeEvent("guardian_decision", "r1", { decision: "allow" }),
      makeEvent("guardian_decision", "r2", { decision: "deny" }),
      makeEvent("guardian_decision", "r3", { decision: "allow" }),
      makeEvent("guardian_decision", "r4", { decision: "ask" }),
      makeEvent("guardian_decision", "r5", { decision: "ask" }),
    ];
    expect(computeDecisionDistribution(events).escalation_rate).toBeCloseTo(0.4);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C: Decision latency
// ─────────────────────────────────────────────────────────────────────────────

describe("C: computeDecisionLatency", () => {
  const BASE = 1_700_000_000_000;

  it("empty events → count 0, nulls", () => {
    const r = computeDecisionLatency([]);
    expect(r.decision_latency.count).toBe(0);
    expect(r.decision_latency.min_ms).toBeNull();
    expect(r.decision_latency.max_ms).toBeNull();
    expect(r.decision_latency.average_ms).toBeNull();
  });

  it("single complete pair → correct latency", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 42)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.min_ms).toBe(42);
    expect(r.decision_latency.max_ms).toBe(42);
    expect(r.decision_latency.average_ms).toBe(42);
  });

  it("zero latency (same timestamp) → 0, included", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 0)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.min_ms).toBe(0);
    expect(r.decision_latency.average_ms).toBe(0);
  });

  it("multiple pairs → min/max/average correct", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 10)),
      makeEvent("tool_call_requested", "req-2", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-2", { decision: "deny" }, ts(BASE, 20)),
      makeEvent("tool_call_requested", "req-3", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-3", { decision: "ask" }, ts(BASE, 30)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(3);
    expect(r.decision_latency.min_ms).toBe(10);
    expect(r.decision_latency.max_ms).toBe(30);
    expect(r.decision_latency.average_ms).toBeCloseTo(20);
  });

  it("tool_call_requested without guardian_decision → excluded from latency", () => {
    const events = [
      makeEvent("tool_call_requested", "req-orphan", {}, ts(BASE)),
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 15)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.average_ms).toBe(15);
  });

  it("guardian_decision without matching tool_call_requested → excluded", () => {
    const events = [
      makeEvent("guardian_decision", "req-orphan", { decision: "deny" }, ts(BASE)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(0);
    expect(r.decision_latency.average_ms).toBeNull();
  });

  it("malformed timestamp → that event skipped, valid pairs computed normally", () => {
    const events = [
      makeEvent("tool_call_requested", "req-bad", {}, "not-a-date"),
      makeEvent("guardian_decision", "req-bad", { decision: "allow" }, ts(BASE)),
      makeEvent("tool_call_requested", "req-good", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-good", { decision: "allow" }, ts(BASE, 50)),
    ];
    const r = computeDecisionLatency(events);
    // req-bad: requestedAt not set (bad ts) → excluded
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.average_ms).toBe(50);
  });

  // ── Ordering: events out of order ─────────────────────────────────────────

  it("events in reverse order → pairs still formed correctly", () => {
    // guardian_decision appears before tool_call_requested in the array,
    // but timestamps are correct: requested at BASE, decided at BASE+25.
    const events = [
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 25)),
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.min_ms).toBe(25);
  });

  it("negative latency (guardian_decision timestamp before tool_call_requested) → pair excluded", () => {
    // Simulates clock skew or out-of-order recording where decision ts < request ts.
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE, 100)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 50)), // earlier!
      // valid pair alongside
      makeEvent("tool_call_requested", "req-2", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-2", { decision: "deny" }, ts(BASE, 40)),
    ];
    const r = computeDecisionLatency(events);
    // req-1 has negative delta → excluded; req-2 is valid
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.average_ms).toBe(40);
  });

  // ── Multi-session: same request_id in different sessions ──────────────────

  it("multi-session cross-correlation: same request_id from two sessions are isolated", () => {
    // Tests that correlation uses (session_id + request_id).
    const BASE2 = BASE + 10_000;
    const events = [
      // Session A: request_id="shared-id", latency=100ms
      makeEvent("tool_call_requested", "shared-id", { session_id: "sess-A" }, ts(BASE)),
      makeEvent("guardian_decision", "shared-id", { session_id: "sess-A", decision: "allow" }, ts(BASE, 100)),
      // Session B: same request_id "shared-id" (collision scenario), latency=200ms
      makeEvent("tool_call_requested", "shared-id", { session_id: "sess-B" }, ts(BASE2)),
      makeEvent("guardian_decision", "shared-id", { session_id: "sess-B", decision: "deny" }, ts(BASE2, 200)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(2);
    expect(r.decision_latency.min_ms).toBe(100);
    expect(r.decision_latency.max_ms).toBe(200);
    expect(r.decision_latency.average_ms).toBe(150);
  });
  
  it("events missing session_id are ignored for latency correlation", () => {
    const events = [
      // Valid pair
      makeEvent("tool_call_requested", "req-1", { session_id: "sess-1" }, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { session_id: "sess-1", decision: "allow" }, ts(BASE, 50)),
      // Missing session_id
      { event_type: "tool_call_requested" as const, request_id: "req-2", timestamp: ts(BASE), metadata: {} },
      { event_type: "guardian_decision" as const, request_id: "req-2", timestamp: ts(BASE, 100), metadata: { decision: "deny" } },
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1); // Only req-1
    expect(r.decision_latency.average_ms).toBe(50);
  });

  // ── Duplicates ────────────────────────────────────────────────────────────

  it("duplicate tool_call_requested for same request_id → first wins (deterministic)", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE, 5000)), // duplicate
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 50)),
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.min_ms).toBe(50); // from first occurrence
  });

  it("duplicate guardian_decision for same request_id → first wins (deterministic)", () => {
    const events = [
      makeEvent("tool_call_requested", "req-1", {}, ts(BASE)),
      makeEvent("guardian_decision", "req-1", { decision: "allow" }, ts(BASE, 30)),
      makeEvent("guardian_decision", "req-1", { decision: "deny" }, ts(BASE, 9000)), // dup
    ];
    const r = computeDecisionLatency(events);
    expect(r.decision_latency.count).toBe(1);
    expect(r.decision_latency.min_ms).toBe(30);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D: Human review latency — corrected semantics
// ─────────────────────────────────────────────────────────────────────────────

describe("D: computeHumanReview", () => {
  const BASE = 1_700_000_000_000;

  it("empty events → all zero, nulls", () => {
    const r = computeHumanReview([]);
    expect(r.human_review.completed_reviews).toBe(0);
    expect(r.human_review.pending_reviews).toBe(0);
    expect(r.human_review.expired_reviews).toBe(0);
    expect(r.human_review.average_review_latency_ms).toBeNull();
    expect(r.human_review.min_review_latency_ms).toBeNull();
    expect(r.human_review.max_review_latency_ms).toBeNull();
  });

  it("pending ASK (no resolution) → pending_reviews = 1", () => {
    const events = [makeEvent("approval_requested", "req-1")];
    const r = computeHumanReview(events);
    expect(r.human_review.pending_reviews).toBe(1);
    expect(r.human_review.completed_reviews).toBe(0);
    expect(r.human_review.expired_reviews).toBe(0);
    expect(r.human_review.average_review_latency_ms).toBeNull();
  });

  it("ASK → human_approval = completed_reviews (not expired)", () => {
    const events = [
      makeEvent("approval_requested", "req-1", undefined, ts(BASE)),
      makeEvent("human_approval", "req-1", {}, ts(BASE, 200)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(1);
    expect(r.human_review.expired_reviews).toBe(0);
    expect(r.human_review.pending_reviews).toBe(0);
    expect(r.human_review.average_review_latency_ms).toBe(200);
  });

  it("ASK → human_rejection = completed_reviews", () => {
    const events = [
      makeEvent("approval_requested", "req-1", undefined, ts(BASE)),
      makeEvent("human_rejection", "req-1", {}, ts(BASE, 150)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(1);
    expect(r.human_review.average_review_latency_ms).toBe(150);
  });

  it("ASK → approval_expired = expired_reviews, NOT completed_reviews", () => {
    const events = [
      makeEvent("approval_requested", "req-1", undefined, ts(BASE)),
      makeEvent("approval_expired", "req-1", {}, ts(BASE, 300_000)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.expired_reviews).toBe(1);
    expect(r.human_review.completed_reviews).toBe(0);
    expect(r.human_review.pending_reviews).toBe(0);
    // Expiry latency does NOT appear in human review latency stats
    expect(r.human_review.average_review_latency_ms).toBeNull();
    expect(r.human_review.min_review_latency_ms).toBeNull();
    expect(r.human_review.max_review_latency_ms).toBeNull();
  });

  it("expired review does NOT affect human review average", () => {
    const events = [
      makeEvent("approval_requested", "req-human", undefined, ts(BASE)),
      makeEvent("human_approval", "req-human", {}, ts(BASE, 100)),
      makeEvent("approval_requested", "req-expired", undefined, ts(BASE)),
      makeEvent("approval_expired", "req-expired", {}, ts(BASE, 999_999)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(1);
    expect(r.human_review.expired_reviews).toBe(1);
    expect(r.human_review.average_review_latency_ms).toBe(100); // only req-human
  });

  it("pending does NOT distort averages when mixed with completed", () => {
    const events = [
      makeEvent("approval_requested", "req-approved", undefined, ts(BASE)),
      makeEvent("human_approval", "req-approved", {}, ts(BASE, 100)),
      makeEvent("approval_requested", "req-pending", undefined, ts(BASE)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(1);
    expect(r.human_review.pending_reviews).toBe(1);
    expect(r.human_review.average_review_latency_ms).toBe(100);
  });

  it("mixed scenario: completed + expired + pending", () => {
    const events = [
      makeEvent("approval_requested", "req-approved", undefined, ts(BASE)),
      makeEvent("human_approval", "req-approved", {}, ts(BASE, 100)),
      makeEvent("approval_requested", "req-rejected", undefined, ts(BASE)),
      makeEvent("human_rejection", "req-rejected", {}, ts(BASE, 300)),
      makeEvent("approval_requested", "req-expired", undefined, ts(BASE)),
      makeEvent("approval_expired", "req-expired", {}, ts(BASE, 600_000)),
      makeEvent("approval_requested", "req-pending", undefined, ts(BASE)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(2);
    expect(r.human_review.expired_reviews).toBe(1);
    expect(r.human_review.pending_reviews).toBe(1);
    expect(r.human_review.min_review_latency_ms).toBe(100);
    expect(r.human_review.max_review_latency_ms).toBe(300);
    expect(r.human_review.average_review_latency_ms).toBeCloseTo(200);
  });

  it("multiple completed reviews → min/max/average correct", () => {
    const events = [
      makeEvent("approval_requested", "req-1", undefined, ts(BASE)),
      makeEvent("human_approval", "req-1", {}, ts(BASE, 100)),
      makeEvent("approval_requested", "req-2", undefined, ts(BASE)),
      makeEvent("human_rejection", "req-2", {}, ts(BASE, 200)),
      makeEvent("approval_requested", "req-3", undefined, ts(BASE)),
      makeEvent("human_approval", "req-3", {}, ts(BASE, 300)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(3);
    expect(r.human_review.pending_reviews).toBe(0);
    expect(r.human_review.expired_reviews).toBe(0);
    expect(r.human_review.min_review_latency_ms).toBe(100);
    expect(r.human_review.max_review_latency_ms).toBe(300);
    expect(r.human_review.average_review_latency_ms).toBeCloseTo(200);
  });

  it("resolution without matching approval_requested → not counted", () => {
    const events = [makeEvent("human_approval", "req-orphan", {})];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(0);
    expect(r.human_review.pending_reviews).toBe(0);
    expect(r.human_review.expired_reviews).toBe(0);
  });

  it("negative review latency (clock skew) → pair excluded from stats", () => {
    const events = [
      makeEvent("approval_requested", "req-skewed", undefined, ts(BASE, 500)),
      makeEvent("human_approval", "req-skewed", {}, ts(BASE, 0)), // before request
      makeEvent("approval_requested", "req-good", undefined, ts(BASE)),
      makeEvent("human_approval", "req-good", {}, ts(BASE, 120)),
    ];
    const r = computeHumanReview(events);
    // req-skewed excluded (negative delta); req-good counted
    expect(r.human_review.completed_reviews).toBe(1);
    expect(r.human_review.average_review_latency_ms).toBe(120);
  });

  it("multi-session cross-correlation: same request_id from two sessions are isolated", () => {
    const BASE2 = BASE + 10_000;
    const events = [
      makeEvent("approval_requested", "shared-id", { session_id: "sess-A" }, ts(BASE)),
      makeEvent("human_approval", "shared-id", { session_id: "sess-A" }, ts(BASE, 200)),
      makeEvent("approval_requested", "shared-id", { session_id: "sess-B" }, ts(BASE2)),
      makeEvent("human_rejection", "shared-id", { session_id: "sess-B" }, ts(BASE2, 400)),
    ];
    const r = computeHumanReview(events);
    expect(r.human_review.completed_reviews).toBe(2);
    expect(r.human_review.average_review_latency_ms).toBe(300);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E: Correlation failures
// ─────────────────────────────────────────────────────────────────────────────

describe("E: computeCorrelationFailures", () => {
  it("empty events → all zero", () => {
    const r = computeCorrelationFailures([]);
    expect(r.correlation_failure_count).toBe(0);
    expect(r.unresolved_request_id_ref_count).toBe(0);
    expect(r.tool_name_mismatch_count).toBe(0);
  });

  it("unresolved_request_id_ref reason", () => {
    const events = [
      makeEvent("correlation_failed", "ref-1", { reason: "unresolved_request_id_ref" }),
    ];
    const r = computeCorrelationFailures(events);
    expect(r.correlation_failure_count).toBe(1);
    expect(r.unresolved_request_id_ref_count).toBe(1);
    expect(r.tool_name_mismatch_count).toBe(0);
  });

  it("tool_name_mismatch reason", () => {
    const events = [makeEvent("correlation_failed", "ref-1", { reason: "tool_name_mismatch" })];
    const r = computeCorrelationFailures(events);
    expect(r.correlation_failure_count).toBe(1);
    expect(r.tool_name_mismatch_count).toBe(1);
    expect(r.unresolved_request_id_ref_count).toBe(0);
  });

  it("mixed reasons → correct breakdown", () => {
    const events = [
      makeEvent("correlation_failed", "ref-1", { reason: "unresolved_request_id_ref" }),
      makeEvent("correlation_failed", "ref-2", { reason: "unresolved_request_id_ref" }),
      makeEvent("correlation_failed", "ref-3", { reason: "tool_name_mismatch" }),
    ];
    const r = computeCorrelationFailures(events);
    expect(r.correlation_failure_count).toBe(3);
    expect(r.unresolved_request_id_ref_count).toBe(2);
    expect(r.tool_name_mismatch_count).toBe(1);
  });

  it("unknown reason counted in total, not in breakdown (resilience)", () => {
    const events = [makeEvent("correlation_failed", "ref-1", { reason: "future_reason" })];
    const r = computeCorrelationFailures(events);
    expect(r.correlation_failure_count).toBe(1);
    expect(r.unresolved_request_id_ref_count).toBe(0);
    expect(r.tool_name_mismatch_count).toBe(0);
  });

  it("non-correlation_failed events are ignored", () => {
    const events = [
      makeEvent("guardian_decision", "req-1", { decision: "deny" }),
      makeEvent("tool_execution_blocked", "req-1", { reason: "denied" }),
    ];
    expect(computeCorrelationFailures(events).correlation_failure_count).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Coverage — removed; verify snapshot does not expose coverage field
// ─────────────────────────────────────────────────────────────────────────────

describe("Coverage: not implemented in WP-02", () => {
  it("OversightMetricsSnapshot has no coverage field", () => {
    const audit = new AuditCollector();
    const m = new OversightMetrics(audit);
    const s = m.getSnapshot();
    expect((s as unknown as Record<string, unknown>)["coverage"]).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// OversightMetrics.getSnapshot() end-to-end via AuditCollector
// ─────────────────────────────────────────────────────────────────────────────

describe("OversightMetrics.getSnapshot()", () => {
  it("empty AuditCollector → all-zero snapshot with no NaN or Infinity", () => {
    const audit = new AuditCollector();
    const m = new OversightMetrics(audit);
    const s = m.getSnapshot();

    expect(s.allow_count).toBe(0);
    expect(s.deny_count).toBe(0);
    expect(s.ask_count).toBe(0);
    expect(s.total_decisions).toBe(0);
    expect(s.escalation_rate).toBe(0);
    expect(s.decision_latency.count).toBe(0);
    expect(s.decision_latency.average_ms).toBeNull();
    expect(s.human_review.completed_reviews).toBe(0);
    expect(s.human_review.pending_reviews).toBe(0);
    expect(s.human_review.expired_reviews).toBe(0);
    expect(s.human_review.average_review_latency_ms).toBeNull();
    expect(s.correlation_failures.correlation_failure_count).toBe(0);

    for (const val of [s.allow_rate, s.deny_rate, s.ask_rate, s.escalation_rate]) {
      expect(Number.isNaN(val)).toBe(false);
      expect(Number.isFinite(val)).toBe(true);
    }
  });

  it("snapshot is deterministic: same events → same result", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "guardian_decision", { decision: "allow" });
    audit.record("req-2", "guardian_decision", { decision: "deny" });

    const m = new OversightMetrics(audit);
    const s1 = m.getSnapshot();
    const s2 = m.getSnapshot();

    expect(s1.allow_count).toBe(s2.allow_count);
    expect(s1.deny_count).toBe(s2.deny_count);
    expect(s1.total_decisions).toBe(s2.total_decisions);
  });

  it("getSnapshot() does not modify AuditCollector state", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "guardian_decision", { decision: "allow" });
    const before = audit.getEvents().length;

    const m = new OversightMetrics(audit);
    m.getSnapshot();

    expect(audit.getEvents().length).toBe(before);
  });

  it("full scenario: ALLOW + DENY + ASK + approval + rejection + expiry + correlation failure", () => {
    const audit = new AuditCollector();

    audit.record("req-1", "tool_call_requested", { session_id: "sess-1", tool: "read_record" });
    audit.record("req-1", "guardian_decision", { session_id: "sess-1", decision: "allow" });

    audit.record("req-2", "tool_call_requested", { session_id: "sess-1", tool: "bad_tool" });
    audit.record("req-2", "guardian_decision", { session_id: "sess-1", decision: "deny" });

    // ASK → human approval
    audit.record("req-3", "tool_call_requested", { session_id: "sess-1", tool: "update_record" });
    audit.record("req-3", "guardian_decision", { session_id: "sess-1", decision: "ask" });
    audit.record("req-3", "approval_requested", { session_id: "sess-1" });
    audit.record("req-3", "human_approval", { session_id: "sess-1", approver_id: "demo-operator" });

    // ASK → human rejection
    audit.record("req-4", "tool_call_requested", { session_id: "sess-1", tool: "delete_record" });
    audit.record("req-4", "guardian_decision", { session_id: "sess-1", decision: "ask" });
    audit.record("req-4", "approval_requested", { session_id: "sess-1" });
    audit.record("req-4", "human_rejection", { session_id: "sess-1" });

    // ASK → expiry
    audit.record("req-5", "tool_call_requested", { session_id: "sess-1", tool: "write_record" });
    audit.record("req-5", "guardian_decision", { session_id: "sess-1", decision: "ask" });
    audit.record("req-5", "approval_requested", { session_id: "sess-1" });
    audit.record("req-5", "approval_expired", { session_id: "sess-1" });

    // ASK → pending
    audit.record("req-6", "tool_call_requested", { session_id: "sess-1", tool: "read_record" });
    audit.record("req-6", "guardian_decision", { session_id: "sess-1", decision: "ask" });
    audit.record("req-6", "approval_requested", { session_id: "sess-1" });

    // Correlation failure
    audit.record("ref-x", "correlation_failed", {
      session_id: "sess-1",
      request_id_ref: "req-old",
      tool: "read_record",
      disposition: "deny",
      reason: "unresolved_request_id_ref",
    });

    const m = new OversightMetrics(audit);
    const s = m.getSnapshot();

    // A
    expect(s.allow_count).toBe(1);
    expect(s.deny_count).toBe(1);
    expect(s.ask_count).toBe(4);
    expect(s.total_decisions).toBe(6);

    // B
    expect(s.escalation_rate).toBeCloseTo(4 / 6);

    // D
    expect(s.human_review.completed_reviews).toBe(2); // approval + rejection
    expect(s.human_review.expired_reviews).toBe(1);
    expect(s.human_review.pending_reviews).toBe(1);

    // E
    expect(s.correlation_failures.correlation_failure_count).toBe(1);
    expect(s.correlation_failures.unresolved_request_id_ref_count).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Isolation
// ─────────────────────────────────────────────────────────────────────────────

describe("Isolation", () => {
  it("metrics from two AuditCollectors are independent", () => {
    const audit1 = new AuditCollector();
    audit1.record("req-1", "guardian_decision", { session_id: "sess-1", decision: "allow" });

    const audit2 = new AuditCollector();
    audit2.record("req-2", "guardian_decision", { session_id: "sess-2", decision: "deny" });

    const m1 = new OversightMetrics(audit1);
    const m2 = new OversightMetrics(audit2);

    expect(m1.getSnapshot().allow_count).toBe(1);
    expect(m1.getSnapshot().deny_count).toBe(0);
    expect(m2.getSnapshot().allow_count).toBe(0);
    expect(m2.getSnapshot().deny_count).toBe(1);
  });
});
