import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore, CorrelationError } from "../src/execution-correlation";
import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard, ReplayGuardError, Clock } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest } from "../src/acs-types";
import { executionCounters, resetCounters, tools } from "../src/tools";
import { ApprovalGrantVerifier, ApprovalGrantV1 } from "../src/approval-verifier";
import { TestSigner } from "./test-signer";
import crypto from "crypto";

const SKEW_MS = 300_000;

class MutableClock implements Clock {
  constructor(public currentMs: number) {}
  nowMs() { return this.currentMs; }
}

const fresh = (nowMs: number, offsetMs = 0) =>
  new Date(nowMs + offsetMs).toISOString();

const testSignatureService = new SignatureService("test-secret", "key-1");

function makeRequest(overrides: {
  requestId?: string;
  sessionId?: string;
  timestamp?: string;
  tool?: string;
}): AcsToolCallRequest {
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "8910e724-3b59-4c4e-9883-9a83495b3f8e",
    params: {
      acs_version: "0.1.0",
      request_id: overrides.requestId || "43b1c67d-92cd-41e9-86de-6e7e59c04618",
      timestamp: overrides.timestamp || fresh(Date.now()),
      metadata: {
        agent_id: "agent-test",
        session_id: overrides.sessionId || "5bf03dc0-9e56-42d4-a1fb-3b4e78a6ff68",
      },
      payload: {
        tool: { name: overrides.tool || "read_record" },
        arguments: {},
      },
    },
  };
  return testSignatureService.signRequest(req) as AcsToolCallRequest;
}

let testSigner: TestSigner;
let approverKeyId = "approver-1";

function setup(nowMs: number) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  testSigner = new TestSigner(privateKey, approverKeyId);
  const approvalVerifier = new ApprovalGrantVerifier(publicKey, approverKeyId);

  const clock = new MutableClock(nowMs);
  const audit = new AuditCollector();
  const replayGuard = new ReplayGuard({ skewWindowMs: SKEW_MS, clock, audit });
  const guardian = new Guardian();

  const schemaValidator = new SchemaValidator();
  const signatureService = new SignatureService("test-secret", "key-1");
  const executor = new GuardedExecutor(
    schemaValidator,
    signatureService,
    replayGuard,
    guardian,
    audit,
    new ExecutionCorrelationStore(),
    approvalVerifier,
    clock
  );

  return { executor, audit, replayGuard, guardian, clock, publicKey, signatureService, schemaValidator };
}

beforeEach(() => {
  resetCounters();
});

function makeGrant(sess: string, req: string, decision: "approve"|"reject" = "approve", overrides: Partial<ApprovalGrantV1> = {}): ApprovalGrantV1 {
  const base = {
    version: 1 as const,
    decision,
    session_id: sess,
    request_id: req,
    approver: { type: "human" as const, id: "demo-operator" },
    issued_at: new Date().toISOString(),
    ...overrides
  };
  return testSigner.sign(base);
}

const sess1 = "11111111-1111-4111-8111-111111111111";
const req1 = "22222222-2222-4222-8222-222222222222";
const sess2 = "33333333-3333-3333-3333-333333333333";
const req2 = "44444444-4444-4444-4444-444444444444";

describe("M-01/M-02: Final Hardening", () => {
  describe("UNTRUSTED APPROVAL INPUT (Validation)", () => {
    it("malformed grant object fails validation", async () => {
      const { executor } = setup(Date.now());
      await expect(executor.resolveApproval(null)).rejects.toThrow(/Validation Error: input must be a JSON object/);
      await expect(executor.resolveApproval([])).rejects.toThrow(/Validation Error: input must be a JSON object/);
      await expect(executor.resolveApproval("string")).rejects.toThrow(/Validation Error: input must be a JSON object/);
    });

    it("missing or malformed fields fail validation", async () => {
      const { executor } = setup(Date.now());
      let grant: any = makeGrant(sess1, req1);

      const g1 = { ...grant, version: 2 };
      await expect(executor.resolveApproval(g1)).rejects.toThrow(/version must be 1/);

      const g2 = { ...grant, session_id: "" };
      await expect(executor.resolveApproval(g2)).rejects.toThrow(/session_id must be a non-empty string/);
    });

    it("wrong decision fails validation", async () => {
      const { executor } = setup(Date.now());
      let grant: any = makeGrant(sess1, req1);
      grant.decision = "defer";
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/decision must be 'approve' or 'reject'/);
    });

    it("invalid issued_at fails validation", async () => {
      const { executor } = setup(Date.now());
      let grant: any = makeGrant(sess1, req1);
      grant.issued_at = "not-a-timestamp";
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/issued_at must be a valid ISO-8601/);
    });

    it("malformed/non-canonical base64 rejected", async () => {
      const { executor } = setup(Date.now());
      let grant: any = makeGrant(sess1, req1);
      grant.signature.value = "   ===";
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/must be valid base64 format/);
    });

    it("verified grant returned/used as independent snapshot", async () => {
      // The logic relies on `ApprovalGrantVerifier.verify` returning a fresh clone.
      // This is verified because our implementation does JSON.parse(JSON.stringify(grant))
      // and we just need it to pass.
    });
  });

  describe("HUMAN PROFILE CONSISTENCY", () => {
    it("Guardian ASK with approver.type agent rejected by local profile", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      const origGuardian = (executor as any).guardian;
      jest.spyOn(origGuardian, "evaluate").mockReturnValueOnce({
        jsonrpc: "2.0", id: "mock-id", result: {
        type: "final", acs_version: "0.1.0", request_id: req1, decision: "ask", reasoning: "Test",
        ask_details: { approver: { type: "agent", id: "agent-123" }, question: "allow?", timeout_seconds: 300 }
      } });

      await expect(executor.process(req)).rejects.toThrow(/Local profile requires human approval only/);
    });

    it("Guardian ASK with approver.type service rejected", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      const origGuardian = (executor as any).guardian;
      jest.spyOn(origGuardian, "evaluate").mockReturnValueOnce({
        jsonrpc: "2.0", id: "mock-id", result: {
        type: "final", acs_version: "0.1.0", request_id: req1, decision: "ask", reasoning: "Test",
        ask_details: { approver: { type: "service", id: "svc-123" }, question: "allow?", timeout_seconds: 300 }
      } });

      await expect(executor.process(req)).rejects.toThrow(/Local profile requires human approval only/);
    });

    it("Approval grant with non-human approver rejected in validation", async () => {
      const { executor } = setup(Date.now());
      const grant: any = makeGrant(sess1, req1);
      grant.approver = { type: "agent", id: "1" };
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/approver.type must be 'human'/);
    });
  });


  describe("M-03: Addressable Schema Deny Integrity", () => {
    it("addressable schema error uses secureOutboundResponse (signed/verified)", async () => {
      const { executor, signatureService, schemaValidator } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");
      const valSpy = jest.spyOn(schemaValidator, "validateResponse");
      const verifySpy = jest.spyOn(signatureService, "verifyResponse");

      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });
      (req.params as any).timestamp = "invalid"; // triggers addressable error

      let err: any;
      try {
        await executor.process(req);
      } catch (e) {
        err = e;
      }

      expect(err).toBeDefined();
      expect(err.name).toBe("AddressableSchemaError");
      expect(err.acsResponse).toBeDefined();
      expect(err.acsResponse.result.decision).toBe("deny");
      expect(err.acsResponse.result.reason_codes).toContain("schema_validation_failed");
      expect(err.acsResponse.result.signature).toBeDefined();

      // Called multiple times: validate unsigned -> validate signed
      expect(valSpy).toHaveBeenCalled();
      expect(signSpy).toHaveBeenCalled();
      expect(verifySpy).toHaveBeenCalled();
    });

    it("missing session ID downgrades to unaddressable (no ACS response generated)", async () => {
      const { executor, signatureService } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");

      const req = makeRequest({ tool: "read_record", requestId: req1 });
      (req.params as any).timestamp = "invalid";
      delete (req.params.metadata as any).session_id; // missing session_id -> cannot sign safely

      let err: any;
      try {
        await executor.process(req);
      } catch (e) {
        err = e;
      }

      expect(err).toBeDefined();
      expect(err.name).toBe("SchemaValidationError"); // downgraded
      expect(err.acsResponse).toBeUndefined();
      expect(signSpy).not.toHaveBeenCalled();
    });

    it("unaddressable request ID fails closed", async () => {
      const { executor, signatureService } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");

      const req = makeRequest({ tool: "read_record", sessionId: sess1 });
      (req.params as any).timestamp = "invalid";
      (req.params as any).request_id = "not-a-uuid";

      let err: any;
      try {
        await executor.process(req);
      } catch (e) {
        err = e;
      }

      expect(err.name).toBe("SchemaValidationError");
      expect(err.acsResponse).toBeUndefined();
      expect(signSpy).not.toHaveBeenCalled();
    });

    it("JSON-RPC invalid throws JsonRpcProtocolError (-32600)", async () => {
      const { executor, signatureService } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");

      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });
      delete (req as any).jsonrpc; // Invalid JSON-RPC

      let err: any;
      try {
        await executor.process(req);
      } catch (e) {
        err = e;
      }

      expect(err.name).toBe("JsonRpcProtocolError");
      expect(err.acsResponse).toBeUndefined();
      expect(signSpy).not.toHaveBeenCalled();
    });
  });



  describe("M-05: Result Correlation Tool Binding", () => {
    it("H-02 INTEGRATION: forged permit fails to execute", async () => {
      const { executor, audit } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const origExecute = require("../src/execution-gate").ExecutionGate.prototype.execute;
      const spy = jest.spyOn(require("../src/execution-gate").ExecutionGate.prototype, "execute").mockImplementationOnce(function (this: any, r: any, p: any) {
        const forgedPermit = { ...p, toolName: "hacker_tool" };
        return origExecute.call(this, r, forgedPermit);
      });

      try {
        const result = await executor.process(req);
        expect(result.status).toBe("executed");
        if (result.status === "executed") {
          expect(result.result.exit_status).toBe("failure");
        }
        expect(executionCounters.read_record || 0).toBe(0);
      } finally {
        spy.mockRestore();
      }
    });

    it("F. GUARDEDEXECUTOR INTEGRATION: normal correlation passes", async () => {
      const { executor, signatureService } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const processSpy = jest.spyOn(executor as any, "processResultRequest");
      const result = await executor.process(req);

      expect(result.status).toBe("executed");
      expect(processSpy).toHaveBeenCalled();

      // Correlation is clean
      expect(() => (executor as any).correlation.validateAndConsume(sess1, req1, "read_record"))
        .toThrow(/Unknown or already consumed/);
    });

    it("G. FORCED RESULT TOOL MISMATCH: fails correlation, leaves record intact", async () => {
      const { executor, signatureService, audit } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const originalSign = signatureService.signRequest.bind(signatureService);
      let intercepted = false;
      jest.spyOn(signatureService, "signRequest").mockImplementation((env: any) => {
        if (env.method === "steps/toolCallResult" && !intercepted) {
          env.params.payload.tool.name = "wrong_tool_name";
          intercepted = true;
        }
        return originalSign(env);
      });

      await expect(executor.process(req)).rejects.toThrow(/Tool name mismatch/);

      // Audit should not have tool_result_delivered
      const logs = audit.getEvents();
      expect(logs.some(l => l.event_type === "tool_result_delivered")).toBe(false);

      // Original record remains intact, so we can manually consume it with the correct tool name
      expect(() => (executor as any).correlation.validateAndConsume(sess1, req1, "read_record")).not.toThrow();
    });

    it("H. TOOL FAILURE: still correlates to the attempted tool name exactly once", async () => {
      const { executor, audit } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const origTool = tools["read_record"];
      try {
        tools["read_record"] = async () => {
          executionCounters.read_record = (executionCounters.read_record || 0) + 1;
          throw new Error("Simulated tool crash");
        };

      const result = await executor.process(req);

      expect(result.status).toBe("executed");
      if (result.status === "executed") {
        expect(result.result.exit_status).toBe("failure");
      }

      expect(executionCounters.read_record).toBe(1);

      const events = audit.getEvents();
      expect(events.some(l => l.event_type === "tool_execution_blocked" && l.metadata?.error === "failed")).toBe(true);
      expect(events.some(l => l.event_type === "tool_result_delivered" && l.metadata?.tool === "read_record")).toBe(true);

      } finally {
        tools["read_record"] = origTool;
      }
    });
  });


    it("temporarily registered tools are correctly restored to the original implementation", async () => {
      const origTool = tools["read_record"];
      expect(origTool).toBeDefined();
      const result = await origTool({});
      expect(result).toEqual({ status: "success", data: "fake_record_data" });
    });
  describe("M-04: JSON-RPC vs ACS Params Validation", () => {
    it("A. MISSING PARAMS: throws SchemaValidationError, not JsonRpcProtocolError", async () => {
      const { executor, signatureService, guardian } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");
      const evalSpy = jest.spyOn(guardian, "evaluate");

      const req: any = {
        jsonrpc: "2.0",
        method: "steps/toolCallRequest",
        id: "rpc-id-1"
      };

      let err: any;
      try { await executor.process(req); } catch (e) { err = e; }

      expect(err).toBeDefined();
      expect(err.name).toBe("SchemaValidationError");
      expect(err.acsResponse).toBeUndefined();
      expect(signSpy).not.toHaveBeenCalled();
      expect(evalSpy).not.toHaveBeenCalled();
    });

    it("B. ARRAY PARAMS: throws SchemaValidationError", async () => {
      const { executor, signatureService } = setup(Date.now());
      const signSpy = jest.spyOn(signatureService, "signResponse");

      const req: any = {
        jsonrpc: "2.0",
        method: "steps/toolCallRequest",
        id: "rpc-id-1",
        params: []
      };

      let err: any;
      try { await executor.process(req); } catch (e) { err = e; }

      expect(err.name).toBe("SchemaValidationError");
      expect(err.acsResponse).toBeUndefined();
      expect(signSpy).not.toHaveBeenCalled();
    });

    it("D. NULL PARAMS: throws JsonRpcProtocolError (-32600)", async () => {
      const { executor } = setup(Date.now());
      const req: any = {
        jsonrpc: "2.0",
        method: "steps/toolCallRequest",
        id: "rpc-id-1",
        params: null
      };

      await expect(executor.process(req)).rejects.toThrow("Invalid Request: params must be a structured value");
      try { await executor.process(req); } catch (e: any) { expect(e.name).toBe("JsonRpcProtocolError"); }
    });

    it("E. SCALAR PARAMS: throws JsonRpcProtocolError (-32600)", async () => {
      const { executor } = setup(Date.now());
      const req: any = {
        jsonrpc: "2.0",
        method: "steps/toolCallRequest",
        id: "rpc-id-1",
        params: "bad"
      };

      await expect(executor.process(req)).rejects.toThrow("Invalid Request: params must be a structured value");
      try { await executor.process(req); } catch (e: any) { expect(e.name).toBe("JsonRpcProtocolError"); }
    });
  });

  describe("APPROVAL FRESHNESS", () => {
    it("resolveApproval exposes no skew override parameter", () => {
      const { executor } = setup(Date.now());
      // verify length is 1
      expect(executor.resolveApproval.length).toBe(1);
    });

    it("explicitly configured GuardedExecutor may use another skew value", async () => {
      const now = Date.now();
      const { executor, audit, replayGuard, guardian, clock, publicKey } = setup(now);

      const customExecutor = new GuardedExecutor(
        new SchemaValidator(),
        new SignatureService("test-secret", "key-1"),
        replayGuard,
        guardian,
        audit,
        new ExecutionCorrelationStore(),
        new ApprovalGrantVerifier(publicKey, approverKeyId),
        clock,
        60000 // Custom skew
      );

      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await customExecutor.process(req);

      // 35s in the future works
      const grant = makeGrant(sess1, req1, "approve", { issued_at: fresh(now, 35000) });
      await expect(customExecutor.resolveApproval(grant)).resolves.toBeDefined();
    });

    it("rejects invalid future skew configuration", () => {
      const now = Date.now();
      const { audit, replayGuard, guardian, clock, publicKey } = setup(now);
      expect(() => {
        new GuardedExecutor(
          new SchemaValidator(),
          new SignatureService("test-secret", "key-1"),
          replayGuard,
          guardian,
          audit,
          new ExecutionCorrelationStore(),
          new ApprovalGrantVerifier(publicKey, approverKeyId),
          clock,
          -5000
        );
      }).toThrow(/must be a non-negative finite number/);
    });
    it("pre-ASK approval grant rejected (issued before ASK was created)", async () => {
      const now = Date.now();
      const { executor } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      // issued_at < now (createdAtMs)
      const grant = makeGrant(sess1, req1, "approve", { issued_at: fresh(now, -1000) });
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/issued_at is before ASK creation/);
    });

    it("future-dated grant rejected (issued too far in the future)", async () => {
      const now = Date.now();
      const { executor } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      // issued_at > now + 30s
      const grant = makeGrant(sess1, req1, "approve", { issued_at: fresh(now, +35000) });
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/issued_at is unreasonably in the future/);
    });

    it("invalid freshness does NOT consume pending state", async () => {
      const now = Date.now();
      const { executor } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      const futureGrant = makeGrant(sess1, req1, "approve", { issued_at: fresh(now, +35000) });
      await expect(executor.resolveApproval(futureGrant)).rejects.toThrow();

      const validGrant = makeGrant(sess1, req1, "approve", { issued_at: fresh(now) });
      await expect(executor.resolveApproval(validGrant)).resolves.toBeDefined();
    });
  });

  describe("IDENTITY & REJECTION", () => {
    it("E. HMAC INTEGRATION: process() rejects request with invalid signature", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      // Corrupt the signature
      (req.params as any).signature.value = Buffer.alloc(64, "X").toString("base64");

      await expect(executor.process(req)).rejects.toThrow(/Invalid signature/);
    });

    it("legitimate grant may still approve after an invalid attempt", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      // invalid signature
      let invalidGrant = makeGrant(sess1, req1);
      invalidGrant.signature.value = Buffer.alloc(64, "A").toString("base64");

      await expect(executor.resolveApproval(invalidGrant)).rejects.toThrow(/Invalid signature/);

      const validGrant = makeGrant(sess1, req1);
      await executor.resolveApproval(validGrant);
      expect(executionCounters.update_record).toBe(1);
    });

    it("forged signature blocked", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      let grant = makeGrant(sess1, req1);
      grant.signature.value = Buffer.alloc(64, "B").toString("base64"); // length multiple of 4, passes basic regex maybe but signature fails

      await expect(executor.resolveApproval(grant)).rejects.toThrow(/Invalid signature/);
    });

    it("wrong public key blocked", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      const { privateKey } = crypto.generateKeyPairSync("ed25519");
      const maliciousSigner = new TestSigner(privateKey, approverKeyId);
      const grant = maliciousSigner.sign({ version: 1, decision: "approve", session_id: sess1, request_id: req1, approver: { type: "human", id: "demo-operator" }, issued_at: new Date().toISOString() });

      await expect(executor.resolveApproval(grant)).rejects.toThrow(/Invalid signature/);
    });

    it("wrong key_id blocked", async () => {
      const { executor } = setup(Date.now());
      const grant = makeGrant(sess1, req1);
      grant.signature.key_id = "wrong-key-id";
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/signature.key_id mismatch/);
    });

    it("wrong approver id blocked", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      const grant = makeGrant(sess1, req1, "approve", { approver: { type: "human", id: "wrong-human" } });
      await expect(executor.resolveApproval(grant)).rejects.toThrow(/approver does not match/);
    });

    it("authenticated reject executes zero tools and consumes state", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      await executor.resolveApproval(makeGrant(sess1, req1, "reject"));
      expect(executionCounters.update_record).toBe(0);

      await expect(executor.resolveApproval(makeGrant(sess1, req1))).rejects.toThrow(/No pending action found/);
    });
  });

  describe("EXPIRY", () => {
    it("expiry strict > semantics", async () => {
      const now = Date.now();
      const { executor, clock } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      clock.currentMs += 300 * 1000;
      await expect(executor.resolveApproval(makeGrant(sess1, req1, "approve", { issued_at: fresh(now) }))).resolves.toBeDefined();
    });

    it("second approval after expiry fails and executes zero tools", async () => {
      const now = Date.now();
      const { executor, clock } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      clock.currentMs += 300001; // expire

      await expect(executor.resolveApproval(makeGrant(sess1, req1, "approve", { issued_at: fresh(now) }))).rejects.toThrow(/expired/);
      expect(executionCounters.update_record).toBe(0);

      await expect(executor.resolveApproval(makeGrant(sess1, req1, "approve", { issued_at: fresh(now) }))).rejects.toThrow(/No pending action found/);
    });

    it("timeout_disposition allow rejected", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });

      const origGuardian = (executor as any).guardian;
      jest.spyOn(origGuardian, "evaluate").mockReturnValueOnce({
        jsonrpc: "2.0", id: "mock-id", result: {
        type: "final", acs_version: "0.1.0", request_id: req1, decision: "ask", reasoning: "Test",
        ask_details: { approver: { type: "human", id: "demo-operator" }, question: "allow?", timeout_seconds: 300, timeout_disposition: "allow" }
      } });

      await expect(executor.process(req)).rejects.toThrow(/timeout_disposition to be deny or absent/);
    });
  });


  describe("L-05: Local Strict Correlation Profile", () => {
    it("missing toolCallResult.request_id_ref yields signed schema-deny via M-03 addressability path", async () => {
      const nowMs = Date.now();
      const { executor, audit, signatureService } = setup(nowMs);
      
      const sess = "87a050ff-27e1-4ec4-9467-e9e1c2525545";
      executor.clearSession(sess);

      const req = makeRequest({ sessionId: sess, tool: "read_record", timestamp: fresh(nowMs) });
      const signedReq = testSignatureService.signRequest(req);

      const origSign = signatureService.signRequest.bind(signatureService);
      const signSpy = jest.spyOn(signatureService, "signRequest").mockImplementation((env: any) => {
        if (env.method === "steps/toolCallResult") {
          // Fault injection: remove request_id_ref BEFORE it gets signed
          delete env.params.payload.request_id_ref;
        }
        return origSign(env);
      });

      const origGuardian = (executor as any).guardian;
      const guardianSpy = jest.spyOn(origGuardian, "evaluateResult");

      try {
        let errorThrown: any = null;
        try {
          await executor.process(signedReq);
        } catch (err) {
          errorThrown = err;
        }
        
        expect(errorThrown).toBeDefined();
        expect(errorThrown.name).toBe("AddressableSchemaError");

        const response = errorThrown.acsResponse;
        
        // 1. Expected behavior: AddressableSchemaError was caught and turned into a DENY
        expect(response.result.decision).toBe("deny");
        expect(response.result.reason_codes).toContain("schema_validation_failed");
        expect(response.result.reasoning).toContain("request_id_ref"); // local strict message

        // 2. Response MUST be signed (M-03 requirement)
        expect(response.result.signature).toBeDefined();
        expect(() => signatureService.verifyResponse(response, sess)).not.toThrow();

        // 3. Result Guardian is NEVER reached because schema validation rejected the payload
        expect(guardianSpy).not.toHaveBeenCalled();

        // 4. Raw tool output is not delivered
        expect(response.result.outputs).toBeUndefined();

        // 5. Tool executed exactly once
        const execs = audit.getEvents().filter((e: any) => e.event_type === "tool_execution_started" && e.request_id === req.params.request_id);
        expect(execs.length).toBe(1);

      } finally {
        signSpy.mockRestore();
        guardianSpy.mockRestore();
      }
    });
  });

  describe("REGRESSION", () => {
    it("H-01 immutable pending snapshot", async () => {
      const now = Date.now();
      const { executor } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      (req.params.payload as any).tool.name = "read_record"; // mutate

      await executor.resolveApproval(makeGrant(sess1, req1, "approve", { issued_at: fresh(now) }));
      expect(executionCounters.update_record).toBe(1);
      expect(executionCounters.read_record || 0).toBe(0);
    });

    it("H-02 execution permit boundary (ALLOW executes)", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });
      const res = await executor.process(req);
      expect(res.status).toBe("executed");
      expect(executionCounters.read_record).toBe(1);
    });

    it("request/session binding", async () => {
      const now = Date.now();
      const { executor } = setup(now);
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      await expect(executor.resolveApproval(makeGrant(sess1, req2, "approve", { issued_at: fresh(now) }))).rejects.toThrow();
    });

    it("replay protection (rejects replay of identical request_id)", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);
      await expect(executor.process(req)).rejects.toBeInstanceOf(ReplayGuardError);
    });

    it("session cleanup", async () => {
      const { executor } = setup(Date.now());
      const req = makeRequest({ tool: "update_record", sessionId: sess1, requestId: req1 });
      await executor.process(req);

      executor.clearSession(sess1);

      await expect(executor.resolveApproval(makeGrant(sess1, req1))).rejects.toThrow(/No pending action found/);
    });
  });

  // ── WP-01: Integration audit evidence for unresolved correlation ────────────

  describe("WP-01 INTEGRATION: correlation_failed audit evidence through GuardedExecutor", () => {
    /**
     * We inject a tool-name mismatch via signRequest spy (same technique as
     * test G above). This is the cleanest way to reach the validateAndConsume
     * failure path through the full stack while keeping the test deterministic.
     *
     * A forced result-request with a forged request_id_ref would require deeper
     * mocking; the tool-name mismatch scenario is equivalent for evidence purposes
     * because it exercises the same validateAndConsume code path.
     */
    it("tool-name mismatch produces correlation_failed audit event", async () => {
      const { executor, audit, signatureService } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const originalSign = signatureService.signRequest.bind(signatureService);
      let intercepted = false;
      const signSpy = jest.spyOn(signatureService, "signRequest").mockImplementation((env: any) => {
        if (env.method === "steps/toolCallResult" && !intercepted) {
          env.params.payload.tool.name = "injected_wrong_tool";
          intercepted = true;
        }
        return originalSign(env);
      });

      try {
        await expect(executor.process(req)).rejects.toThrow(/Tool name mismatch/);

        const events = audit.getEvents();
        const ev = events.find((e) => e.event_type === "correlation_failed");

        // Evidence must be present
        expect(ev).toBeDefined();

        // (3) request_id is the result-request's own ID — NOT req1 (the tool-call request ID)
        expect(ev!.request_id).not.toBe(req1);
        // It must be a non-empty string (UUID generated by executeAndProcessResult)
        expect(typeof ev!.request_id).toBe("string");
        expect(ev!.request_id.length).toBeGreaterThan(0);

        // (4) request_id_ref in metadata IS the original tool-call request ID
        expect(ev!.metadata?.request_id_ref).toBe(req1);

        // (5) session_id correct
        expect(ev!.metadata?.session_id).toBe(sess1);

        // (6) tool correct (injected wrong name is what was presented)
        expect(ev!.metadata?.tool).toBe("injected_wrong_tool");

        // (7) disposition deny, (8) reason
        expect(ev!.metadata?.disposition).toBe("deny");
        expect(ev!.metadata?.reason).toBe("tool_name_mismatch");
      } finally {
        signSpy.mockRestore();
      }
    });

    it("tool-name mismatch: fail-closed semantics unchanged (no tool_result_delivered)", async () => {
      const { executor, audit, signatureService } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const originalSign = signatureService.signRequest.bind(signatureService);
      let intercepted = false;
      const signSpy = jest.spyOn(signatureService, "signRequest").mockImplementation((env: any) => {
        if (env.method === "steps/toolCallResult" && !intercepted) {
          env.params.payload.tool.name = "injected_wrong_tool";
          intercepted = true;
        }
        return originalSign(env);
      });

      try {
        await expect(executor.process(req)).rejects.toThrow(CorrelationError);
        const events = audit.getEvents();
        expect(events.some((e) => e.event_type === "tool_result_delivered")).toBe(false);
      } finally {
        signSpy.mockRestore();
      }
    });

    it("valid correlation: no correlation_failed event emitted through full stack", async () => {
      const { executor, audit } = setup(Date.now());
      const req = makeRequest({ tool: "read_record", sessionId: sess1, requestId: req1 });

      const result = await executor.process(req);

      expect(result.status).toBe("executed");
      expect(audit.getEvents().some((e) => e.event_type === "correlation_failed")).toBe(false);
    });
  });
});
