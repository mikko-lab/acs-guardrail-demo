import { Guardian } from "../src/guardian";
import type { AcsToolCallRequest } from "../src/acs-types";

describe("Guardian deterministic decisions", () => {
  const guardian = new Guardian();

  /** Build a minimal valid ACS request with params nesting. */
  const createRequest = (tool: string, reqId = "dca0d958-d13c-4e49-818f-cf2592b094bc"): AcsToolCallRequest => ({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "call-test",
    params: {
      acs_version: "0.1.0",
      request_id: reqId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "test-agent", session_id: "session-test" },
      payload: {
        tool: { name: tool },
        // ACS ToolArgumentValue shape: each argument is { value: ... }
        arguments: {},
      },
    },
  });

  // ── Shape: request uses params nesting ────────────────────────────
  it("request shape uses params (not flat root)", () => {
    const req = createRequest("read_record");
    expect(req.params).toBeDefined();
    expect(req.params.acs_version).toBe("0.1.0");
    expect(req.params.metadata.agent_id).toBe("test-agent");
    expect(req.params.metadata.session_id).toBe("session-test");
    // Fields must NOT be at the envelope root
    expect((req as unknown as Record<string, unknown>)["acs_version"]).toBeUndefined();
    expect((req as unknown as Record<string, unknown>)["request_id"]).toBeUndefined();
  });

  // ── Shape: response uses ACS field names ──────────────────────────
  it("response uses decision field (not disposition)", () => {
    const env = guardian.evaluate(createRequest("read_record"));
    expect(env.result.decision).toBeDefined();
    expect((env.result as unknown as Record<string, unknown>)["disposition"]).toBeUndefined();
  });

  it("response envelope is jsonrpc 2.0 with id echoing request id", () => {
    const req = createRequest("read_record");
    const env = guardian.evaluate(req);
    expect(env.jsonrpc).toBe("2.0");
    expect(env.id).toBe(req.id);
  });

  it("result type is 'final'", () => {
    const env = guardian.evaluate(createRequest("read_record"));
    expect(env.result.type).toBe("final");
  });

  // ── Decision values ───────────────────────────────────────────────
  it("allows read_record", () => {
    const env = guardian.evaluate(createRequest("read_record"));
    expect(env.result.decision).toBe("allow");
  });

  it("asks for update_record", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.decision).toBe("ask");
  });

  it("denies unknown tools", () => {
    const env = guardian.evaluate(createRequest("delete_record"));
    expect(env.result.decision).toBe("deny");
  });

  // ── reasoning field (required on deny and ask) ───────────────────
  it("deny includes reasoning", () => {
    const env = guardian.evaluate(createRequest("delete_record"));
    expect(env.result.reasoning).toBeTruthy();
    expect(typeof env.result.reasoning).toBe("string");
  });

  it("ask includes reasoning", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.reasoning).toBeTruthy();
    expect(typeof env.result.reasoning).toBe("string");
  });

  // ── reason_codes: string[] ────────────────────────────────────────
  it("allow carries reason_codes array", () => {
    const env = guardian.evaluate(createRequest("read_record"));
    expect(Array.isArray(env.result.reason_codes)).toBe(true);
    expect((env.result.reason_codes ?? []).length).toBeGreaterThan(0);
  });

  it("deny carries reason_codes array", () => {
    const env = guardian.evaluate(createRequest("delete_record"));
    expect(Array.isArray(env.result.reason_codes)).toBe(true);
  });

  it("ask carries reason_codes array", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(Array.isArray(env.result.reason_codes)).toBe(true);
  });

  // ── ask_details (required when decision === ask) ──────────────────
  it("ask includes ask_details", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    const ad = env.result.ask_details;
    expect(ad).toBeDefined();
  });

  it("ask_details.approver.type is human", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.ask_details?.approver.type).toBe("human");
  });

  it("ask_details.approver.id is non-empty", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.ask_details?.approver.id).toBeTruthy();
  });

  it("ask_details.question is non-empty", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.ask_details?.question).toBeTruthy();
  });

  it("ask_details.timeout_seconds is a positive integer", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    const t = env.result.ask_details?.timeout_seconds ?? 0;
    expect(Number.isInteger(t)).toBe(true);
    expect(t).toBeGreaterThan(0);
  });

  it("ask_details.timeout_disposition is deny", () => {
    const env = guardian.evaluate(createRequest("update_record"));
    expect(env.result.ask_details?.timeout_disposition).toBe("deny");
  });

  // ── allow does NOT carry ask_details ─────────────────────────────
  it("allow does not carry ask_details", () => {
    const env = guardian.evaluate(createRequest("read_record"));
    expect(env.result.ask_details).toBeUndefined();
  });
});
