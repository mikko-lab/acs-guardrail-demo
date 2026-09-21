import { setup, makeRequest, fresh, toUuid } from "./eval-setup";

describe("Domain B: Replay and Duplicate Attempts", () => {
  const BASE_TIME = Date.now();

  it("EVAL-B1: same request twice in same session is blocked", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    
    // Attempt replay
    await expect(executor.process(req)).rejects.toThrow(/Duplicate request_id/);
    const events = audit.getEvents();
    expect(events.filter(e => e.event_type === "tool_call_requested").length).toBe(1);
    expect(events.filter(e => e.event_type === "guardian_decision").length).toBe(1);
  });

  it("EVAL-B2: same request_id in different session is allowed (architectural isolation)", async () => {
    const { executor, clock } = setup(BASE_TIME);
    const req1 = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "shared-id" }, clock);
    await executor.process(req1);
    
    const req2 = makeRequest({ tool: "read_record", sessionId: "sess-2", requestId: "shared-id" }, clock);
    const res = await executor.process(req2);
    expect(res).toBeDefined();
  });

  it("EVAL-B3: consumed correlation ref throws on reuse", async () => {
    const { executor, correlation, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req); // registers execution
    
    // It's consumed internally by process(), so it's ALREADY consumed!
    // Since process() consumes it internally, trying to consume it again will fail!
    expect(() => correlation.validateAndConsume(toUuid("sess-1"), toUuid("req-1"), "read_record")).toThrow(/already consumed/);
  });

  it("EVAL-B4: replay failure does not open alternate execution path", async () => {
    const { executor, audit, clock } = setup(BASE_TIME);
    const req = makeRequest({ tool: "read_record", sessionId: "sess-1", requestId: "req-1" }, clock);
    await executor.process(req);
    await expect(executor.process(req)).rejects.toThrow(/Duplicate request_id/);
    
    const events = audit.getEvents();
    expect(events.filter(e => e.event_type === "tool_execution_started").length).toBe(1); // Only the first one
  });
});
