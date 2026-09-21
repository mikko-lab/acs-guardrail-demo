import { setup, makeRequest, fresh } from "./eval-setup";

describe("Domain C: Correlation Attacks", () => {
  const BASE_TIME = Date.now();

  it("EVAL-C1: unknown request_id_ref is blocked", async () => {
    const { correlation, audit } = setup(BASE_TIME);
    
    // Simulate consuming an unknown reference directly on the store
    const ctx = { audit, resultRequestId: "res-1", sessionId: "sess-1", tool: "read_record" };
    expect(() => correlation.validateAndConsume("sess-1", "unknown-ref", "read_record", ctx)).toThrow(/Unknown/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed" && e.metadata?.reason === "unresolved_request_id_ref")).toBe(true);
  });

  it("EVAL-C2: consumed request_id_ref is blocked", async () => {
    const { correlation, audit } = setup(BASE_TIME);
    correlation.registerExecution("sess-1", "req-1", "read_record");
    
    const ctx = { audit, resultRequestId: "res-1", sessionId: "sess-1", tool: "read_record" };
    correlation.validateAndConsume("sess-1", "req-1", "read_record", ctx); // first consume OK
    
    expect(() => correlation.validateAndConsume("sess-1", "req-1", "read_record", ctx)).toThrow(/already consumed/); // second fails
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed" && e.metadata?.reason === "unresolved_request_id_ref")).toBe(true);
  });

  it("EVAL-C3: wrong tool name is blocked", async () => {
    const { correlation, audit } = setup(BASE_TIME);
    correlation.registerExecution("sess-1", "req-1", "read_record");
    
    const ctx = { audit, resultRequestId: "res-1", sessionId: "sess-1", tool: "update_record" };
    expect(() => correlation.validateAndConsume("sess-1", "req-1", "update_record", ctx)).toThrow(/Tool name mismatch/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed" && e.metadata?.reason === "tool_name_mismatch")).toBe(true);
  });

  it("EVAL-C4: request_id_ref from another session is blocked", async () => {
    const { correlation, audit } = setup(BASE_TIME);
    // Session A registers req-1
    correlation.registerExecution("sess-A", "req-1", "read_record");
    
    // Session B tries to consume req-1
    const ctx = { audit, resultRequestId: "res-1", sessionId: "sess-B", tool: "read_record" };
    expect(() => correlation.validateAndConsume("sess-B", "req-1", "read_record", ctx)).toThrow(/Unknown/);
    
    const events = audit.getEvents();
    expect(events.some(e => e.event_type === "correlation_failed")).toBe(true);
  });
});
