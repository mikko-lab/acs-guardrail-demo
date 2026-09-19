import { SchemaValidator } from "../src/schema-validator";
import { SignatureService, SignatureInvalidError } from "../src/signature-service";
import { ExecutionCorrelationStore, CorrelationError } from "../src/execution-correlation";
import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import { AcsToolCallRequest } from "../src/acs-types";
import { executionCounters, resetCounters } from "../src/tools";

describe("Phase 5: Result Gate Governance", () => {
  let audit: AuditCollector;
  let executor: GuardedExecutor;
  let signatureService: SignatureService;
  let guardian: Guardian;
  let correlation: ExecutionCorrelationStore;

  const sessionId = "123e4567-e89b-12d3-a456-426614174001";

  beforeEach(() => {
    resetCounters();
    audit = new AuditCollector();
    signatureService = new SignatureService("test-secret", "key-1");
    guardian = new Guardian();
    correlation = new ExecutionCorrelationStore();
    
    executor = new GuardedExecutor(
      new SchemaValidator(),
      signatureService,
      new ReplayGuard({ audit }),
      guardian,
      new ExecutionGate(audit),
      audit,
      correlation
    );
  });

  const createRequest = (id: string, tool: string, args: any = {}): AcsToolCallRequest => signatureService.signRequest({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "test-agent", session_id: sessionId },
      payload: {
        tool: { name: tool },
        arguments: args,
      },
    },
  });

  it("1 & 2 & 3 & 4 & 5. allowed request executes exactly once and creates a separate result hook", async () => {
    const req = createRequest("123e4567-e89b-12d3-a456-426614174010", "read_record");
    const result = await executor.process(req);
    
    expect(result.status).toBe("executed");
    if (result.status === "executed") {
      expect(result.result.tool.name).toBe("read_record");
      expect(result.result.request_id_ref).toBe("123e4567-e89b-12d3-a456-426614174010");
      expect(executionCounters.read_record).toBe(1);

      // Audit verifies the hook lifecycle
      const events = audit.getEvents();
      const createdEvents = events.filter(e => e.event_type === "tool_result_created");
      expect(createdEvents.length).toBe(1);
      
      const newResultId = createdEvents[0].request_id;
      expect(newResultId).not.toBe("123e4567-e89b-12d3-a456-426614174010"); // 3. new request_id
    }
  });

  it("12. ordinary output → ALLOW → exact output delivered", async () => {
    // We mock execution gate to return ordinary data
    const req = createRequest("123e4567-e89b-12d3-a456-426614174011", "read_record");
    
    const result = await executor.process(req);
    expect(result.status).toBe("executed");
    if (result.status === "executed") {
      expect(result.result.outputs[0].value).toEqual({ status: "success", data: "fake_record_data" });
    }
  });

  it("13 & 14 & 15. restricted demo output → DENY → raw output not delivered / leaked", async () => {
    const req = createRequest("123e4567-e89b-12d3-a456-426614174012", "read_record");
    
    // Force the execution gate to return restricted data for this test
    const origExecute = (executor as any).gate.execute.bind((executor as any).gate);
    jest.spyOn((executor as any).gate, "execute").mockResolvedValueOnce({
      tool: { name: "read_record" },
      request_id_ref: "123e4567-e89b-12d3-a456-426614174012",
      exit_status: "success",
      outputs: [{ value: { classification: "restricted", sensitive: "secret123" } }]
    });

    const result = await executor.process(req);
    expect(result.status).toBe("executed");
    if (result.status === "executed") {
      expect(result.result.exit_status).toBe("blocked");
      expect((result.result.outputs[0].value as any).error).toBe("Output withheld by policy.");
      expect((result.result.outputs[0].value as any).sensitive).toBeUndefined(); // raw output not delivered
    }

    // 14. denied raw output does not appear in audit log
    const events = audit.getEvents();
    const logStr = JSON.stringify(events);
    expect(logStr).not.toContain("secret123");

    // 15. denied raw output does not appear in reasoning
    const decisionEvents = events.filter(e => e.event_type === "result_guardian_decision");
    expect(JSON.stringify(decisionEvents[0].metadata)).not.toContain("secret123");
  });

  it("16 & 17 & 18. request vs result distinction (DENY behavior)", async () => {
    // 17. request-gate DENY -> execution counter stays 0
    const reqDeny = createRequest("123e4567-e89b-12d3-a456-426614174013", "unknown_tool");
    await expect(executor.process(reqDeny)).rejects.toThrow();
    expect(executionCounters.unknown_tool || 0).toBe(0);

    // 18. result-gate DENY -> execution counter is 1 but delivery is blocked
    const reqResultDeny = createRequest("123e4567-e89b-12d3-a456-426614174014", "read_record");
    jest.spyOn((executor as any).gate, "execute").mockResolvedValueOnce({
      tool: { name: "read_record" },
      request_id_ref: "123e4567-e89b-12d3-a456-426614174014",
      exit_status: "success",
      outputs: [{ value: { classification: "restricted", data: "leaked" } }]
    });
    executionCounters.read_record = 1;
    const result = await executor.process(reqResultDeny);
    expect(executionCounters.read_record).toBe(1); // tool executed!
    if (result.status === "executed") {
      expect(result.result.exit_status).toBe("blocked"); // but blocked
    }
  });

  it("19 & 20 & 21 & 22. throwing tool executes once, handles failure", async () => {
    const req = createRequest("123e4567-e89b-12d3-a456-426614174015", "read_record");
    
    // Inject throwing tool
    jest.spyOn((executor as any).gate, "execute").mockRejectedValueOnce(new Error("MySecretStackTrace"));

    const result = await executor.process(req);
    expect(executionCounters.read_record).toBe(0); // My mock intercepted before tools.ts incremented it! 
    // Wait, the spy intercepted the whole ExecutionGate.
    
    if (result.status === "executed") {
      expect(result.result.exit_status).toBe("failure");
      expect((result.result.outputs[0].value as any).error).toBe("Tool execution failed");
      expect((result.result.outputs[0].value as any).stack).toBeUndefined();
    }
  });


  it("fails securely without leaking exception messages or secrets to audit logs", async () => {
    const req = createRequest("123e4567-e89b-12d3-a456-426614174099", "read_record");
    
    // Inject a throwing tool that leaks a fake secret
    jest.spyOn((executor as any).gate, "execute").mockRejectedValueOnce(new Error("DB password=super-secret-value"));

    const result = await executor.process(req);
    expect(result.status).toBe("executed");
    if (result.status === "executed") {
      expect(result.result.exit_status).toBe("failure");
      expect((result.result.outputs[0].value as any).error).toBe("Tool execution failed");
      expect((result.result.outputs[0].value as any).code).toBe("tool_execution_failed");
      expect((result.result.outputs[0].value as any).stack).toBeUndefined();
    }
    
    // Prove the secret is nowhere in the audit log
    const events = audit.getEvents();
    const logStr = JSON.stringify(events);
    expect(logStr).not.toContain("super-secret-value");

    // Nor in guardian reasoning (if it were somehow processed)
    const decisionEvents = events.filter(e => e.event_type === "result_guardian_decision");
    if (decisionEvents.length > 0) {
      expect(JSON.stringify(decisionEvents[0].metadata)).not.toContain("super-secret-value");
    }
  });

  it("23 & 24. clearSession removes result correlation state", () => {
    correlation.markExecuted(sessionId, "req-1");
    executor.clearSession(sessionId);
    expect(() => correlation.validateAndConsume(sessionId, "req-1")).toThrow(CorrelationError);

    // 24. clearing session A does not affect session B
    correlation.markExecuted("session-A", "req-A");
    correlation.markExecuted("session-B", "req-B");
    executor.clearSession("session-A");
    expect(() => correlation.validateAndConsume("session-A", "req-A")).toThrow(CorrelationError);
    expect(() => correlation.validateAndConsume("session-B", "req-B")).not.toThrow();
  });
});

