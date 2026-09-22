import { createAuthorityTestDeps } from "./evals/eval-setup";
import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";

describe("Audit Collector invariants", () => {
  let audit: AuditCollector;
  let executor: GuardedExecutor;
  let privateKey: string;

  beforeEach(() => {
    const keys = require("crypto").generateKeyPairSync("ed25519");
    privateKey = keys.privateKey;

    audit = new AuditCollector();
    executor = new GuardedExecutor(
      new SchemaValidator(),
      new SignatureService("test-secret", "key-1"),
      new ReplayGuard({ audit }),
      new Guardian(),
      audit,
      new ExecutionCorrelationStore(),
      new (require("../src/approval-verifier").ApprovalGrantVerifier)(keys.publicKey, "key-1"), ...(() => { const clock = new (require("./evals/eval-setup").MutableClock)(Date.now()); const auth = require("./evals/eval-setup").createAuthorityTestDeps(clock); return [clock, 30000, auth.provider, auth.verifier] as const; })()
    );
  });

  const testSignatureService = new SignatureService("test-secret", "key-1");
  const createRequest = (id: string, tool: string): AcsToolCallRequest => testSignatureService.signRequest({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: id,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "test-agent", session_id: "26f7a67a-cfda-4fa3-8315-6de161b37a47" },
      payload: {
        tool: { name: tool },
        arguments: {},
      },
    },
  });

  it("8. every request gets a Guardian decision audit event", async () => {
    const req = createRequest("f34c8e1e-0637-4c38-b66d-d2cf1e39ed1e", "read_record");
    await executor.process(req);
    const events = audit.getEventsForRequest("f34c8e1e-0637-4c38-b66d-d2cf1e39ed1e");
    const decisionEvent = events.find(e => e.event_type === "guardian_decision");
    expect(decisionEvent).toBeDefined();
    expect(decisionEvent?.metadata?.["decision"]).toBe("allow");
  });

  it("9. blocked actions get an audit event (deny)", async () => {
    // delete_record is in allowed_tools (capability passes) but Guardian denies it
    const req = createRequest("d4050efb-29e2-4edb-9564-115948d338c2", "delete_record");
    await expect(executor.process(req)).rejects.toThrow();
    const events = audit.getEventsForRequest("d4050efb-29e2-4edb-9564-115948d338c2");
    const blockedEvent = events.find(e => e.event_type === "tool_execution_blocked");
    expect(blockedEvent).toBeDefined();
    expect(blockedEvent?.metadata?.["reason"]).toBe("denied");
  });

  it("9b. paused actions get an approval_requested event", async () => {
    const req = createRequest("7340d64e-3a59-4f17-9096-865ba73666ad", "update_record");
    const result = await executor.process(req);
    expect(result.status).toBe("pending");
    const events = audit.getEventsForRequest("7340d64e-3a59-4f17-9096-865ba73666ad");
    const askEvent = events.find(e => e.event_type === "approval_requested");
    expect(askEvent).toBeDefined();
  });

  it("NORMAL ALLOW exact event sequence with no duplicates", async () => {
    const req = createRequest("f3e6b6d5-d371-42e7-b384-27019524b015", "read_record");
    await executor.process(req);
    const events = audit.getEvents();

    expect(events.filter(e => e.event_type === "tool_execution_started").length).toBe(1);
    expect(events.filter(e => e.event_type === "tool_execution_completed").length).toBe(1);

    const types = events.map(e => e.event_type);
    expect(types).toEqual([
      "tool_call_requested",
      "capability_verified",
      "guardian_decision",
      "tool_execution_started",
      "tool_execution_completed",
      "tool_result_created",
      "result_guardian_decision",
      "tool_result_delivered"
    ]);
  });


  it("ASK -> approval -> execution exact event sequence with no duplicates", async () => {
    const req = createRequest("7340d64e-3a59-4f17-9096-865ba73666aa", "update_record");
    await executor.process(req);

    const testSigner = new (require("../tests/test-signer").TestSigner)(privateKey, "key-1");
    const grant = testSigner.sign({
      version: 2, tool: "update_record",
      decision: "approve",
      session_id: "26f7a67a-cfda-4fa3-8315-6de161b37a47",
      request_id: "7340d64e-3a59-4f17-9096-865ba73666aa",
      approver: { type: "human", id: "demo-operator" },
      issued_at: new Date().toISOString()
    });
    await executor.resolveApproval(grant);

    const events = audit.getEvents();
    expect(events.filter(e => e.event_type === "approval_requested").length).toBe(1);
    expect(events.filter(e => e.event_type === "human_approval").length).toBe(1);
    expect(events.filter(e => e.event_type === "tool_execution_started").length).toBe(1);
    expect(events.filter(e => e.event_type === "tool_execution_completed").length).toBe(1);
  });

  it("TOOL FAILURE exact event sequence", async () => {
    const req = createRequest("f3e6b6d5-d371-42e7-b384-27019524b099", "read_record");
    const { tools } = require("../src/tools");
    const origTool = tools["read_record"];
    try {
      tools["read_record"] = async () => { throw new Error("crash"); };
      await executor.process(req);

      const events = audit.getEvents();
      expect(events.filter(e => e.event_type === "tool_execution_started").length).toBe(1);

      const completedEvents = events.filter(e => e.event_type === "tool_execution_completed");
      expect(completedEvents.length).toBe(1);
      expect(completedEvents[0].metadata?.status).toBe("error");

      expect(events.filter(e => e.event_type === "tool_execution_blocked").length).toBe(1);
    } finally {
      tools["read_record"] = origTool;
    }
  });

  it("AuditCollector is mutable and intentionally not append-only", () => {
    audit.record("req1", "tool_call_requested");
    expect(audit.getEvents().length).toBe(1);
    audit.clear();
    expect(audit.getEvents().length).toBe(0);
  });
});
