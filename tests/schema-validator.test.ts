import { SchemaValidator, AddressableSchemaError, SchemaValidationError, JsonRpcProtocolError } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import { executionCounters, resetCounters } from "../src/tools";

const testSignatureService = new SignatureService("test-secret", "key-1");
const validBaseRequest = testSignatureService.signRequest({
  jsonrpc: "2.0",
  method: "steps/toolCallRequest",
  id: "call-1",
  params: {
    acs_version: "0.1.0",
    request_id: "123e4567-e89b-12d3-a456-426614174000",
    timestamp: new Date().toISOString(),
    metadata: {
      agent_id: "agent-1",
      session_id: "123e4567-e89b-12d3-a456-426614174001"
    },
    payload: {
      tool: { name: "read_record" },
      arguments: { arg1: { value: "test" } }
    }
  }
});

describe("Schema Validator - JSON-RPC & ACS Boundaries", () => {
  let validator: SchemaValidator;

  beforeEach(() => {
    validator = new SchemaValidator();
  });

  const validate = (req: unknown) => validator.validateRequest(req);

  describe("1. JSON-RPC layer (-32600)", () => {
    it("missing jsonrpc -> -32600", () => {
      const req = { ...validBaseRequest };
      delete (req as any).jsonrpc;
      expect(() => validate(req)).toThrow(JsonRpcProtocolError);
    });

    it("jsonrpc '1.0' -> -32600", () => {
      const req = { ...validBaseRequest, jsonrpc: "1.0" };
      expect(() => validate(req)).toThrow(JsonRpcProtocolError);
    });

    it("missing method -> -32600", () => {
      const req = { ...validBaseRequest };
      delete (req as any).method;
      expect(() => validate(req)).toThrow(JsonRpcProtocolError);
    });

    it("invalid method type -> -32600", () => {
      const req = { ...validBaseRequest, method: 123 };
      expect(() => validate(req)).toThrow(JsonRpcProtocolError);
    });

    it("invalid id object -> -32600", () => {
      const req = { ...validBaseRequest, id: {} };
      expect(() => validate(req)).toThrow(JsonRpcProtocolError);
    });
  });

  describe("2. ACS Envelope & Payload layer", () => {
    it("valid request envelope passes", () => {
      expect(() => validate(validBaseRequest)).not.toThrow();
    });

    it("valid JSON-RPC + missing acs_version fails ACS validation", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      delete req.params.acs_version;
      expect(() => validate(req)).toThrow(AddressableSchemaError);
    });

    it("valid JSON-RPC + malformed timestamp fails ACS validation", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      req.params.timestamp = "not-a-date";
      expect(() => validate(req)).toThrow(AddressableSchemaError);
    });

    it("valid JSON-RPC + invalid tool payload fails ACS validation", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      delete req.params.payload.tool.name;
      expect(() => validate(req)).toThrow(AddressableSchemaError);
    });
  });

  describe("3. Strict Correlation (UUID required for DENY)", () => {
    it("valid UUID params.request_id + ACS-invalid payload may produce a schema-valid deny", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      req.params.timestamp = "invalid"; // breaks schema
      let err: any;
      try { validate(req); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(AddressableSchemaError);
      expect(err.requestId).toBe("123e4567-e89b-12d3-a456-426614174000");
    });

    it("valid JSON-RPC + malformed request_id fails ACS validation and is unaddressable (no fake deny)", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      req.params.request_id = "not-a-uuid";
      expect(() => validate(req)).toThrow(SchemaValidationError);
      expect(() => validate(req)).not.toThrow(AddressableSchemaError);
    });

    it("missing request_id must not invent one", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      delete req.params.request_id;
      expect(() => validate(req)).toThrow(SchemaValidationError);
      expect(() => validate(req)).not.toThrow(AddressableSchemaError);
    });

    it("non-UUID request_id must not be copied into a deny response", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      req.params.request_id = "just-some-string";
      expect(() => validate(req)).toThrow(SchemaValidationError);
      expect(() => validate(req)).not.toThrow(AddressableSchemaError);
    });

    it("numeric JSON-RPC id must not become ACS result.request_id (and neither must arbitrary string ids)", () => {
      const req = JSON.parse(JSON.stringify(validBaseRequest));
      req.id = 7;
      req.params.request_id = "not-uuid";
      // Even though JSON-RPC ID is available, we MUST NOT invent an ACS request_id
      expect(() => validate(req)).toThrow(SchemaValidationError);
      expect(() => validate(req)).not.toThrow(AddressableSchemaError);
    });
  });
});

describe("GuardedExecutor with Security Ordering", () => {
  let audit: AuditCollector;
  let executor: GuardedExecutor;
  let replayGuard: ReplayGuard;
  let guardian: Guardian;

  beforeEach(() => {
    resetCounters();
    audit = new AuditCollector();
    replayGuard = new ReplayGuard({ audit });
    guardian = new Guardian();
    executor = new GuardedExecutor(new SchemaValidator(), new SignatureService("test-secret", "key-1"),
      replayGuard,
      guardian,
      audit,
        new ExecutionCorrelationStore(),
        new (require("../src/approval-verifier").ApprovalGrantVerifier)(require("crypto").generateKeyPairSync("ed25519").publicKey, "key-1")
      );
  });

  it("JSON-RPC-invalid input never reaches ReplayGuard", async () => {
    const req = { ...validBaseRequest, jsonrpc: "1.0" };
    const checkSpy = jest.spyOn(replayGuard, "check");
    await expect(executor.process(req)).rejects.toThrow(JsonRpcProtocolError);
    expect(checkSpy).not.toHaveBeenCalled();
  });

  it("ACS-invalid input never reaches ReplayGuard or Guardian or Tools", async () => {
    const req = JSON.parse(JSON.stringify(validBaseRequest));
    req.params.timestamp = "invalid";

    const checkSpy = jest.spyOn(replayGuard, "check");
    const evalSpy = jest.spyOn(guardian, "evaluate");

    await expect(executor.process(req)).rejects.toThrow(AddressableSchemaError);
    
    expect(checkSpy).not.toHaveBeenCalled();
    expect(evalSpy).not.toHaveBeenCalled();
    expect(executionCounters.read_record).toBe(0);
  });

  it("invalid internal Guardian response does not reach ExecutionGate", async () => {
    // We mock Guardian to return a badly shaped response
    jest.spyOn(guardian, "evaluate").mockReturnValueOnce({
      jsonrpc: "2.0",
      id: "call-1",
      result: {
        type: "final",
        acs_version: "0.1.0",
        // missing request_id, decision, reasoning, etc.
      }
    } as any);

    const req = JSON.parse(JSON.stringify(validBaseRequest));
    await expect(executor.process(req)).rejects.toThrow(SchemaValidationError);
    expect(executionCounters.read_record).toBe(0);
  });
});

