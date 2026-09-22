import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { ApprovalGrantVerifier, ApprovalGrantV2, ApprovalContext } from "../src/approval-verifier";

describe("ApprovalGrantVerifier V2 (WP-06A)", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyId = "appr-key-1";
  
  let verifier: ApprovalGrantVerifier;

  beforeEach(() => {
    verifier = new ApprovalGrantVerifier(publicKey, keyId);
  });

  const signV2 = (payload: any): ApprovalGrantV2 => {
    const clone = JSON.parse(JSON.stringify(payload));
    delete clone.signature;
    const dataBuffer = Buffer.from(canonicalize(clone));
    const sig = crypto.sign(null, dataBuffer, privateKey);
    return {
      ...clone,
      signature: {
        algorithm: "Ed25519",
        key_id: keyId,
        value: sig.toString("base64")
      }
    };
  };

  const createBaseV2 = () => ({
    version: 2,
    decision: "approve",
    session_id: "sess-1",
    request_id: "req-1",
    tool: "delete_record",
    approver: { type: "human", id: "human-1" },
    issued_at: new Date().toISOString(),
  });

  const createBaseV1 = () => ({
    version: 1,
    decision: "approve",
    session_id: "sess-1",
    request_id: "req-1",
    approver: { type: "human", id: "human-1" },
    issued_at: new Date().toISOString(),
  });

  const validContext: ApprovalContext = {
    expectedSessionId: "sess-1",
    expectedRequestId: "req-1",
    expectedTool: "delete_record",
    expectedApproverType: "human",
    expectedApproverId: "human-1"
  };

  it("APR2-001: valid signed V2 approval -> valid", () => {
    const grant = signV2(createBaseV2());
    const verified = verifier.verifyV2(grant, validContext);
    expect(verified.decision).toBe("approve");
    expect(verified.tool).toBe("delete_record");
  });

  it("APR2-002: wrong session -> fail", () => {
    const grant = signV2(createBaseV2());
    expect(() => verifier.verifyV2(grant, { ...validContext, expectedSessionId: "sess-2" })).toThrow(/Invariant Violation: session_id does not match/);
  });

  it("APR2-003: wrong request -> fail", () => {
    const grant = signV2(createBaseV2());
    expect(() => verifier.verifyV2(grant, { ...validContext, expectedRequestId: "req-2" })).toThrow(/Invariant Violation: request_id does not match/);
  });

  it("APR2-004: wrong expected tool -> fail", () => {
    const grant = signV2(createBaseV2());
    expect(() => verifier.verifyV2(grant, { ...validContext, expectedTool: "read_record" })).toThrow(/Invariant Violation: tool does not match expected tool/);
  });

  it("APR2-005: tool changed after signing -> signature fail", () => {
    const grant = signV2(createBaseV2());
    grant.tool = "read_record"; // mutated
    expect(() => verifier.verifyV2(grant, { ...validContext, expectedTool: "read_record" })).toThrow(/Invalid signature/);
  });

  it("APR2-006: invalid issued_at format is rejected; lifecycle freshness remains runtime policy", () => {
    // Current ApprovalGrantVerifier checks valid ISO timestamp format. Freshness is checked in GuardedExecutor.
    const base = createBaseV2();
    base.issued_at = "invalid";
    expect(() => verifier.verifyV2(signV2(base), validContext)).toThrow(/Validation Error: issued_at must be a valid ISO-8601 timestamp/);
  });

  it("APR2-007: V1 is not accepted as V2", () => {
    const grant = signV2(createBaseV1()); // Sign a V1 payload
    expect(() => verifier.verifyV2(grant, validContext)).toThrow(/Validation Error: version must be 2/);
  });

  it("APR2-008A: validly signed wrong approver identity -> fail", () => {
    const base = createBaseV2();
    base.approver.id = "another-human";
    const grant = signV2(base);

    expect(() => verifier.verifyV2(grant, validContext)).toThrow(
      /Invariant Violation: approver does not match expected approver/
    );
  });

  it("APR2-008: reject decision remains reject", () => {
    const base = createBaseV2();
    base.decision = "reject";
    const grant = signV2(base);
    const verified = verifier.verifyV2(grant, validContext);
    expect(verified.decision).toBe("reject");
  });

  it("V2 is not accepted by verify() (V1 verifier)", () => {
    const grant = signV2(createBaseV2());
    expect(() => verifier.verify(grant)).toThrow(/Validation Error: version must be 1/);
  });

  it("Canonicalization: same payload with different key order produces valid signature", () => {
    const grant = signV2(createBaseV2());
    // Re-order keys
    const reordered: any = {
      decision: grant.decision,
      version: grant.version,
      signature: grant.signature,
      tool: grant.tool,
      session_id: grant.session_id,
      approver: grant.approver,
      issued_at: grant.issued_at,
      request_id: grant.request_id,
    };
    
    // Should verify successfully because json-canonicalize handles the ordering
    expect(() => verifier.verifyV2(reordered, validContext)).not.toThrow();
  });

  describe("Negative Assertions", () => {
    it("Approval V2 for Tool A does not approve Tool B", () => {
      const base = createBaseV2();
      base.tool = "Tool-A";
      const grant = signV2(base);
      expect(() => verifier.verifyV2(grant, { ...validContext, expectedTool: "Tool-B" })).toThrow(/Invariant Violation: tool does not match expected tool/);
    });
  });
});
