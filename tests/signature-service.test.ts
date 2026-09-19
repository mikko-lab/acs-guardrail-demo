import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { SignatureService, SignatureInvalidError } from "../src/signature-service";
import { AcsToolCallRequest, AcsResponseEnvelope } from "../src/acs-types";
import { GuardedExecutor } from "../src/guarded-executor";
import { SchemaValidator } from "../src/schema-validator";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import { executionCounters, resetCounters } from "../src/tools";

describe("Signature Service - Authenticated Envelope Integrity", () => {
  const rootSecret = "test-root-secret";
  const keyId = "test-key-id";
  let service: SignatureService;

  beforeEach(() => {
    service = new SignatureService(rootSecret, keyId);
  });

  const makeBaseRequest = (sessionId: string): AcsToolCallRequest => ({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "call-1",
    params: {
      acs_version: "0.1.0",
      request_id: "5ebf4c9c-850d-40d9-b052-a5417abec810",
      timestamp: new Date().toISOString(),
      metadata: {
        agent_id: "agent-1",
        session_id: sessionId
      },
      payload: {
        tool: { name: "read_record" },
        arguments: { arg1: { value: "test" } }
      }
    }
  });

  const makeBaseResponse = (sessionId: string): AcsResponseEnvelope => ({
    jsonrpc: "2.0",
    id: "call-1",
    result: {
      type: "final",
      acs_version: "0.1.0",
      request_id: "5ebf4c9c-850d-40d9-b052-a5417abec810",
      decision: "allow"
    }
  });

  describe("Core Integrity Properties", () => {
    it("1. valid signed request passes", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      expect(() => service.verifyRequest(signed)).not.toThrow();
    });


    it("modifying top-level JSON-RPC id invalidates signature", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.id = "call-999";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("modifying method invalidates signature", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      (signed.method as any) = "steps/otherMethod";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("2. unsigned request fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      expect(() => service.verifyRequest(req)).toThrow(SignatureInvalidError);
    });

    it("3. wrong root key fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      const wrongService = new SignatureService("wrong-secret", keyId);
      expect(() => wrongService.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("4. wrong key_id fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.signature!.key_id = "wrong-key";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("5. modified session_id fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.metadata.session_id = "session-2";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("6. modified request_id fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.request_id = "modified";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("7. modified timestamp fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.timestamp = "2099-01-01T00:00:00Z";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("8. modified tool name fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.payload.tool.name = "malicious_tool";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("9. modified tool argument fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.payload.arguments.arg1.value = "malicious";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("10. signature from session A fails in session B", () => {
      const reqA = makeBaseRequest("session-A");
      const signedA = service.signRequest(reqA);
      
      const reqB = makeBaseRequest("session-B");
      reqB.params.signature = signedA.params.signature;
      expect(() => service.verifyRequest(reqB)).toThrow(SignatureInvalidError);
    });

    it("11. malformed base64 signature fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      signed.params.signature!.value = "not!base64";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });

    it("12. wrong algorithm fails", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      (signed.params.signature!.algorithm as any) = "HMAC-MD5";
      expect(() => service.verifyRequest(signed)).toThrow(SignatureInvalidError);
    });
  });

  describe("Response Integrity", () => {
    it("18. valid response is signed", () => {
      const res = makeBaseResponse("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signResponse(res, "123e4567-e89b-12d3-a456-426614174001");
      expect(signed.result.signature).toBeDefined();
    });

    it("19. signed response verifies", () => {
      const res = makeBaseResponse("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signResponse(res, "123e4567-e89b-12d3-a456-426614174001");
      expect(() => service.verifyResponse(signed, "123e4567-e89b-12d3-a456-426614174001")).not.toThrow();
    });


    it("modifying top-level response id invalidates signature", () => {
      const res = makeBaseResponse("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signResponse(res, "123e4567-e89b-12d3-a456-426614174001");
      signed.id = "modified-id";
      expect(() => service.verifyResponse(signed, "123e4567-e89b-12d3-a456-426614174001")).toThrow(SignatureInvalidError);
    });

    it("modifying reasoning invalidates signature", () => {
      const res = makeBaseResponse("123e4567-e89b-12d3-a456-426614174001");
      res.result.reasoning = "original reason";
      const signed = service.signResponse(res, "123e4567-e89b-12d3-a456-426614174001");
      signed.result.reasoning = "modified reason";
      expect(() => service.verifyResponse(signed, "123e4567-e89b-12d3-a456-426614174001")).toThrow(SignatureInvalidError);
    });

    it("20. modified signed response fails verification", () => {
      const res = makeBaseResponse("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signResponse(res, "123e4567-e89b-12d3-a456-426614174001");
      signed.result.decision = "deny";
      expect(() => service.verifyResponse(signed, "123e4567-e89b-12d3-a456-426614174001")).toThrow(SignatureInvalidError);
    });
  });

  describe("Canonicalization & MAC properties", () => {
    it("21. signature field itself is excluded from canonicalized input", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);
      
      // If we change another property of the signature block, it does not invalidate the MAC of the ENVELOPE.
      // Wait, we explicitly check keyId and algorithm first, so if we pass those, changing some arbitrary field in signature should not affect MAC.
      (signed.params.signature as any).extra_field = "ignored";
      expect(() => service.verifyRequest(signed)).not.toThrow();
    });


    it("original objects are not mutated by sign/verify operations", () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const originalJson = JSON.stringify(req);
      const signed = service.signRequest(req);
      service.verifyRequest(signed);
      expect(JSON.stringify(req)).toBe(originalJson);
    });

    it("22. same canonical envelope produces same MAC regardless of object key order", () => {
      const req1 = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed1 = service.signRequest(req1);

      // Recreate request with a different object key order
      const req2: any = {
        id: "call-1",
        method: "steps/toolCallRequest",
        jsonrpc: "2.0",
        params: {
          timestamp: req1.params.timestamp,
          acs_version: "0.1.0",
          payload: {
            arguments: { arg1: { value: "test" } },
            tool: { name: "read_record" }
          },
          request_id: "5ebf4c9c-850d-40d9-b052-a5417abec810",
          metadata: {
            session_id: "123e4567-e89b-12d3-a456-426614174001",
            agent_id: "agent-1"
          }
        }
      };
      
      const signed2 = service.signRequest(req2);
      expect(signed1.params.signature!.value).toEqual(signed2.params.signature!.value);
    });
  });

  describe("GuardedExecutor Architecture Ordering", () => {
    let audit: AuditCollector;
    let executor: GuardedExecutor;
    let replayGuard: ReplayGuard;
    let guardian: Guardian;

    beforeEach(() => {
      resetCounters();
      audit = new AuditCollector();
      replayGuard = new ReplayGuard({ audit });
      guardian = new Guardian();
      executor = new GuardedExecutor(
        new SchemaValidator(),
        service,
        replayGuard,
        guardian,
        new ExecutionGate(audit),
        audit,
        new ExecutionCorrelationStore()
      );
    });

    it("13, 14, 15, 16. invalid signature never reaches ReplayGuard, Guardian, ExecutionGate, or Tool", async () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      // Intentionally unsigned

      const checkSpy = jest.spyOn(replayGuard, "check");
      const evalSpy = jest.spyOn(guardian, "evaluate");

      await expect(executor.process(req)).rejects.toThrow(SignatureInvalidError);

      expect(checkSpy).not.toHaveBeenCalled();
      expect(evalSpy).not.toHaveBeenCalled();
      expect(executionCounters.read_record).toBe(0);
    });

    it("17. invalid signature does not consume replay state", async () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);

      // Mutate to make it invalid
      const badReq = JSON.parse(JSON.stringify(signed));
      badReq.params.payload.tool.name = "malicious";

      await expect(executor.process(badReq)).rejects.toThrow(SignatureInvalidError);

      // Now send the original good request
      const result = await executor.process(signed);
      expect(result.status).toBe("executed");
    });

    it("modified signed response cannot reach ExecutionGate or execute a tool", async () => {
      const req = makeBaseRequest("123e4567-e89b-12d3-a456-426614174001");
      const signed = service.signRequest(req);

      // We intercept the internal signResponse to mutate it before verifyResponse is called in GuardedExecutor
      const originalSignResponse = service.signResponse.bind(service);
      jest.spyOn(service, "signResponse").mockImplementation((res, sid) => {
        const signedRes = originalSignResponse(res, sid);
        signedRes.result.decision = "deny"; // malicious tampering after Guardian
        return signedRes;
      });

      await expect(executor.process(signed)).rejects.toThrow(SignatureInvalidError);
      expect(executionCounters.read_record).toBe(0); // tool not executed
    });

  });
});
