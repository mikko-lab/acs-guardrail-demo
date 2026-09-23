import { fresh, makeRequest, setup } from "./eval-setup";

describe("Concurrent authority isolation (EVAL-J1..J3)", () => {
  it("EVAL-J1 same-session concurrent ALLOW and DENY decisions remain request-local", async () => {
    const { executor, audit, clock } = setup(Date.now());

    const allowedRequest = makeRequest(
      {
        tool: "read_record",
        sessionId: "concurrency-session",
        requestId: "concurrency-allow",
      },
      clock
    );

    const deniedRequest = makeRequest(
      {
        tool: "delete_record",
        sessionId: "concurrency-session",
        requestId: "concurrency-deny",
      },
      clock
    );

    const [allowedResult, deniedResult] = await Promise.allSettled([
      executor.process(allowedRequest),
      executor.process(deniedRequest),
    ]);

    expect(allowedResult.status).toBe("fulfilled");
    if (allowedResult.status === "fulfilled") {
      expect(allowedResult.value.status).toBe("executed");
    }

    expect(deniedResult.status).toBe("rejected");
    if (deniedResult.status === "rejected") {
      expect(String(deniedResult.reason)).toMatch(/Execution blocked \(deny\)/);
    }

    const events = audit.getEvents();
    const allowedId = allowedRequest.params.request_id;
    const deniedId = deniedRequest.params.request_id;

    expect(
      events.some(
        (event) =>
          event.request_id === allowedId &&
          event.event_type === "guardian_decision" &&
          event.metadata?.decision === "allow"
      )
    ).toBe(true);

    expect(
      events.some(
        (event) =>
          event.request_id === deniedId &&
          event.event_type === "guardian_decision" &&
          event.metadata?.decision === "deny"
      )
    ).toBe(true);

    expect(
      events.filter(
        (event) =>
          event.request_id === allowedId &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(1);

    expect(
      events.filter(
        (event) =>
          event.request_id === deniedId &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(0);
  });

  it("EVAL-J2 concurrent ASK actions in one session remain independently bound", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());

    const requestA = makeRequest(
      {
        tool: "update_record",
        sessionId: "approval-race-session",
        requestId: "approval-race-a",
      },
      clock
    );

    const requestB = makeRequest(
      {
        tool: "update_record",
        sessionId: "approval-race-session",
        requestId: "approval-race-b",
      },
      clock
    );

    const [pendingA, pendingB] = await Promise.all([
      executor.process(requestA),
      executor.process(requestB),
    ]);

    expect(pendingA.status).toBe("pending");
    expect(pendingB.status).toBe("pending");

    const grantA = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: requestA.params.metadata.session_id,
      request_id: requestA.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs()),
    });

    const approvedA = await executor.resolveApproval(grantA);
    expect(approvedA?.exit_status).toBe("success");

    let events = audit.getEvents();

    expect(
      events.filter(
        (event) =>
          event.request_id === requestA.params.request_id &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(1);

    expect(
      events.filter(
        (event) =>
          event.request_id === requestB.params.request_id &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(0);

    const rejectB = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "reject",
      session_id: requestB.params.metadata.session_id,
      request_id: requestB.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs()),
    });

    await expect(executor.resolveApproval(rejectB)).resolves.toBeUndefined();

    events = audit.getEvents();

    expect(
      events.filter(
        (event) =>
          event.request_id === requestB.params.request_id &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(0);

    expect(
      events.some(
        (event) =>
          event.request_id === requestB.params.request_id &&
          event.event_type === "human_rejection"
      )
    ).toBe(true);
  });

  it("EVAL-J3 duplicate concurrent approval consumes pending authority exactly once", async () => {
    const { executor, audit, clock, testSigner } = setup(Date.now());

    const request = makeRequest(
      {
        tool: "update_record",
        sessionId: "duplicate-approval-session",
        requestId: "duplicate-approval-request",
      },
      clock
    );

    const pending = await executor.process(request);
    expect(pending.status).toBe("pending");

    const grant = testSigner.sign({
      version: 2,
      tool: "update_record",
      decision: "approve",
      session_id: request.params.metadata.session_id,
      request_id: request.params.request_id,
      approver: { type: "human", id: "demo-operator" },
      issued_at: fresh(clock.nowMs()),
    });

    const outcomes = await Promise.allSettled([
      executor.resolveApproval(grant),
      executor.resolveApproval(grant),
    ]);

    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);

    const events = audit.getEvents();

    expect(
      events.filter(
        (event) =>
          event.request_id === request.params.request_id &&
          event.event_type === "human_approval"
      )
    ).toHaveLength(1);

    expect(
      events.filter(
        (event) =>
          event.request_id === request.params.request_id &&
          event.event_type === "tool_execution_started"
      )
    ).toHaveLength(1);
  });
});
