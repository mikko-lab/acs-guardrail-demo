import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { CapabilityGrantV1, CapabilityGrantVerifier, CapabilityContext } from "../src/capability-grant";
import { MutableClock, fresh } from "./evals/eval-setup";

describe("CapabilityGrantVerifier (WP-06A)", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyId = "cap-key-1";
  
  let clock: MutableClock;
  let verifier: CapabilityGrantVerifier;

  beforeEach(() => {
    clock = new MutableClock(1000000);
    verifier = new CapabilityGrantVerifier(publicKey, keyId, clock);
  });

  const sign = (payload: any): CapabilityGrantV1 => {
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

  const createBase = () => ({
    version: 1,
    capability_id: "cap-1",
    agent_id: "agent-1",
    session_id: "sess-1",
    allowed_tools: ["read_record", "delete_record"],
    issued_at: fresh(clock.nowMs(), -1000), // 1 sec ago
    expires_at: fresh(clock.nowMs(), 60000), // 60 sec from now
  });

  const validContext: CapabilityContext = {
    expectedAgentId: "agent-1",
    expectedSessionId: "sess-1",
    requestedTool: "read_record"
  };

  it("AUTH-001: valid capability -> valid", () => {
    const grant = sign(createBase());
    expect(() => verifier.verify(grant, validContext)).not.toThrow();
  });

  it("AUTH-002: wrong agent -> fail", () => {
    const grant = sign(createBase());
    expect(() => verifier.verify(grant, { ...validContext, expectedAgentId: "agent-2" })).toThrow(/Invariant Violation: agent_id does not match/);
  });

  it("AUTH-003: wrong session -> fail", () => {
    const grant = sign(createBase());
    expect(() => verifier.verify(grant, { ...validContext, expectedSessionId: "sess-2" })).toThrow(/Invariant Violation: session_id does not match/);
  });

  it("AUTH-004: tool not in allowed_tools -> fail", () => {
    const grant = sign(createBase());
    expect(() => verifier.verify(grant, { ...validContext, requestedTool: "update_record" })).toThrow(/Invariant Violation: requested tool 'update_record' is not in allowed_tools/);
  });

  it("AUTH-005: expired capability -> fail", () => {
    const base = createBase();
    base.expires_at = fresh(clock.nowMs(), -100); // already expired
    const grant = sign(base);
    expect(() => verifier.verify(grant, validContext)).toThrow(/Validation Error: capability has expired/);
  });

  it("AUTH-006: not-yet-valid capability -> fail", () => {
    const base = createBase();
    base.issued_at = fresh(clock.nowMs(), 1000); // valid in 1 second
    const grant = sign(base);
    expect(() => verifier.verify(grant, validContext)).toThrow(/Validation Error: capability is not yet valid/);
  });

  it("AUTH-007: tampered allowed_tools -> signature fail", () => {
    const grant = sign(createBase());
    grant.allowed_tools = ["read_record", "delete_record", "update_record"]; // mutated after signing
    expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
  });

  it("AUTH-008: tampered agent_id -> signature fail", () => {
    const grant = sign(createBase());
    grant.agent_id = "agent-2"; // mutated after signing
    expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
  });

  it("AUTH-009: wildcard tool capability -> rejected / unsupported", () => {
    const base = createBase();
    base.allowed_tools = ["*"];
    expect(() => verifier.verify(sign(base), validContext)).toThrow(/no wildcards/);
  });

  it("AUTH-010: malformed temporal fields -> fail", () => {
    const base = createBase();
    base.issued_at = "not-a-date";
    // We expect schema validation to fail before signature verification
    expect(() => verifier.verify(sign(base), validContext)).toThrow(/Validation Error: issued_at must be a valid ISO-8601 timestamp/);
  });

  it("AUTH-011: same capability verifier call deterministic -> same result", () => {
    const grant = sign(createBase());
    const res1 = verifier.verify(grant, validContext);
    const res2 = verifier.verify(grant, validContext);
    expect(res1).toEqual(res2);
  });

  it("AUTH-012: Validly signed expired capability -> capability has expired", () => {
    const base = createBase();
    base.expires_at = fresh(clock.nowMs(), -500); // expired
    const grant = sign(base);
    expect(() => verifier.verify(grant, validContext)).toThrow(/capability has expired/);
  });

  it("AUTH-013: Tampered expires_at into the past -> Invalid signature (not expired error)", () => {
    const grant = sign(createBase());
    grant.expires_at = fresh(clock.nowMs(), -500); // mutate after signing to a past date
    expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
  });

  it("AUTH-014: Tampered issued_at into the future -> Invalid signature (not yet valid error)", () => {
    const grant = sign(createBase());
    grant.issued_at = fresh(clock.nowMs(), 50000); // mutate after signing to future date
    expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
  });

  it("AUTH-015: Tampered allowed_tools to wildcard -> Invalid signature (not wildcard error)", () => {
    const grant = sign(createBase());
    grant.allowed_tools = ["*"]; // mutate after signing
    expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
  });

  describe("Negative Assertions & Signed Fields", () => {
    it("capability for Agent A does not authorize Agent B", () => {
      const base = createBase();
      base.agent_id = "Agent-A";
      const grant = sign(base);
      expect(() => verifier.verify(grant, { ...validContext, expectedAgentId: "Agent-B" })).toThrow(/Invariant Violation/);
    });

    it("capability for Session A does not authorize Session B", () => {
      const base = createBase();
      base.session_id = "Session-A";
      const grant = sign(base);
      expect(() => verifier.verify(grant, { ...validContext, expectedSessionId: "Session-B" })).toThrow(/Invariant Violation/);
    });

    it("capability for Tool A does not authorize Tool B", () => {
      const base = createBase();
      base.allowed_tools = ["Tool-A"];
      const grant = sign(base);
      expect(() => verifier.verify(grant, { ...validContext, requestedTool: "Tool-B" })).toThrow(/Invariant Violation/);
    });

    it("tampering cannot produce a valid grant", () => {
      const grant = sign(createBase());
      grant.signature.value = Buffer.alloc(64, "A").toString("base64"); // Fake signature
      expect(() => verifier.verify(grant, validContext)).toThrow(/Invalid signature/);
    });

    it("malformed grant does not become valid through defaults", () => {
      const grant = sign(createBase());
      delete (grant as any).agent_id;
      expect(() => verifier.verify(grant, validContext)).toThrow(/Validation Error: agent_id must be a non-empty string/);
    });

    it("Capability signed fields cover all essential metadata", () => {
      // Prove that mutating any of the core fields invalidates the signature
      const original = sign(createBase());
      const fieldsToTamper: (keyof typeof original)[] = [
        "capability_id", "agent_id", "session_id", "allowed_tools", "issued_at", "expires_at"
      ];

      for (const field of fieldsToTamper) {
        const tampered = JSON.parse(JSON.stringify(original));
        if (Array.isArray(tampered[field])) {
          tampered[field] = [...tampered[field], "fake_tool"];
        } else if (field === "issued_at" || field === "expires_at") {
          // Mutate while keeping format valid
          tampered[field] = fresh(new Date(tampered[field]).getTime(), 1000);
        } else {
          tampered[field] = tampered[field] + "_tampered";
        }
        expect(() => verifier.verify(tampered, validContext)).toThrow(/Invalid signature/);
      }
    });

    it("Canonicalization: same payload with different key order produces valid signature", () => {
      const grant = sign(createBase());
      // Re-order keys
      const reordered: any = {
        expires_at: grant.expires_at,
        signature: grant.signature,
        allowed_tools: grant.allowed_tools,
        agent_id: grant.agent_id,
        capability_id: grant.capability_id,
        session_id: grant.session_id,
        version: grant.version,
        issued_at: grant.issued_at,
      };
      
      // Should verify successfully because json-canonicalize handles the ordering
      expect(() => verifier.verify(reordered, validContext)).not.toThrow();
    });
  });
});
