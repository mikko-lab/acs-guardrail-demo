import { setup, makeRequest, fresh, toUuid } from "./eval-setup";
import { OversightMetrics } from "../../src/oversight-metrics";

describe("Domain I: Oversight metrics as evaluation evidence", () => {
  const BASE_TIME = Date.now();

  it("EVAL-I1: accurate metrics snapshot for multi-path scenario", async () => {
    const { executor, audit, correlation, clock, testSigner } = setup(BASE_TIME);
    
    // 1. ALLOW
    await executor.process(makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-allow" }, clock));
    
    // 2. DENY
    clock.currentMs += 1000;
    await expect(executor.process(makeRequest({ tool: "delete_record", sessionId: "sess-1", requestId: "req-deny" }, clock))).rejects.toThrow();
    
    // 3. ASK + approve
    clock.currentMs += 1000;
    const reqAskApprove = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-ask-approve" }, clock);
    await executor.process(reqAskApprove);
    const grantApprove = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-ask-approve"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +100), decision: "approve"
    });
    await executor.resolveApproval(grantApprove);
    
    // 4. ASK + reject
    clock.currentMs += 1000;
    const reqAskReject = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-ask-reject" }, clock);
    await executor.process(reqAskReject);
    const grantReject = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-ask-reject"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs(), +100), decision: "reject"
    });
    await executor.resolveApproval(grantReject);
    
    // 5. ASK + expiry
    clock.currentMs += 1000;
    const reqAskExpiry = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-ask-expiry" }, clock);
    await executor.process(reqAskExpiry);
    clock.currentMs += 20 * 60 * 1000; // expire
    const grantLate = testSigner.sign({
      version: 2, tool: "update_record", session_id: toUuid("sess-1"), request_id: toUuid("req-ask-expiry"),
      approver: { type: "human", id: "demo-operator" }, issued_at: fresh(clock.nowMs()), decision: "approve"
    });
    await expect(executor.resolveApproval(grantLate)).rejects.toThrow(/expired/);
    
    // 6. ASK (remains pending)
    clock.currentMs += 1000;
    const reqAskPending = makeRequest({ tool: "update_record", sessionId: "sess-1", requestId: "req-ask-pending" }, clock);
    await executor.process(reqAskPending);

    // 7. correlation_failed (simulate an attacker trying to consume unknown ref)
    const ctx = { audit, resultRequestId: "res-fail", sessionId: toUuid("sess-1"), tool: "read_record" };
    expect(() => correlation.validateAndConsume(toUuid("sess-1"), toUuid("unknown-ref"), "read_record", ctx)).toThrow();
    
    // Check metrics
    const metrics = new OversightMetrics(audit);
    const snap = metrics.getSnapshot();
    
    expect(snap.allow_count).toBe(1);
    expect(snap.deny_count).toBe(1);
    expect(snap.ask_count).toBe(4); // approve, reject, expiry, pending
    
    expect(snap.human_review.completed_reviews).toBe(2); // approve + reject
    expect(snap.human_review.expired_reviews).toBe(1); // expiry
    expect(snap.human_review.pending_reviews).toBe(1); // pending
    
    expect(snap.correlation_failures.correlation_failure_count).toBe(1);
    expect(snap.correlation_failures.unresolved_request_id_ref_count).toBe(1);
    
    expect(snap.escalation_rate).toBe(4 / 6);
  });
});
