/**
 * Component tests of the approval-permit lifecycle (plan §7.5). They back only the check points that no production
 * path separates: the session, agent and tenant comparisons of the start bindings (M55, M56) and the source of the
 * execution authority (M71). They are component_check_point evidence, never production-path containment evidence.
 * The digest and fingerprint tests pin the canonical forms a human approval signs.
 */
import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import {
  argumentsDigest, authorityFingerprint, chainValidityAt, chainValidityEnd, compareStartBindings, draftLineage,
  matchesLineageSnapshot, ownedRequestSnapshot, requestDigest, startExecutionAuthority, StartBindings,
} from "../src/approval-lifecycle";
import { ApprovalGrantVerifier, ApprovalVerificationError } from "../src/approval-verifier";
import { capabilityFingerprint, type CapabilityGrant } from "../src/capability-grant";
import { TestSigner } from "./test-signer";
import { witness } from "./witness";

const grant = (id: string, extra: Partial<CapabilityGrant> = {}): CapabilityGrant => ({
  version: 2, capability_id: id, agent_id: "agent-test", session_id: "s1", tenant_id: "t1",
  allowed_tools: ["read_record", "update_record"], issued_at: "2026-01-01T00:00:00.000Z", expires_at: "2026-01-01T01:00:00.000Z",
  signature: { algorithm: "Ed25519", key_id: "cap-key-1", value: "AAAA" },
  ...extra,
} as CapabilityGrant);

describe("binding comparator (start, §5.1)", () => {
  const lineage: StartBindings = { session_id: "s1", agent_id: "g1", tenant_id: "t1", tool: "update_record", arguments_digest: argumentsDigest({ n: { value: 1 } }) };

  it("[LC-C-equal] equal bindings compare equal", () => {
    expect(compareStartBindings(lineage, { ...lineage })).toBeNull();
  });

  it.each([
    ["session", { session_id: "s2" }],
    ["agent", { agent_id: "g2" }],
    ["tenant", { tenant_id: "t2" }],
    ["tool", { tool: "read_record" }],
    ["arguments", { arguments_digest: argumentsDigest({ n: { value: 2 } }) }],
  ] as const)("[LC-C-%s] a differing %s field is reported as that field", (field, change) => {
    witness([`LC-C-comparator-${field}`, compareStartBindings(lineage, { ...lineage, ...change }), field]);
  });

  it("an absent tenant on one side is a difference (tenancy and non-tenancy authorities never compare equal)", () => {
    expect(compareStartBindings(lineage, { ...lineage, tenant_id: undefined })).toBe("tenant");
  });
});

describe("digest canonicalization", () => {
  it("key order does not change a digest", () => {
    expect(argumentsDigest({ a: { value: 1 }, b: { value: [1, 2] } })).toBe(argumentsDigest({ b: { value: [1, 2] }, a: { value: 1 } }));
    expect(requestDigest({ agent_id: "g", session_id: "s", tool: "t", arguments: { x: 1, y: 2 } }))
      .toBe(requestDigest({ tool: "t", arguments: { y: 2, x: 1 }, session_id: "s", agent_id: "g" } as never));
  });

  it("Unicode is hashed as its code points, without normalization (NFC and NFD differ; escapes do not matter)", () => {
    expect(argumentsDigest({ name: "é" })).toBe(argumentsDigest({ name: "é" }));
    expect(argumentsDigest({ name: "é" })).not.toBe(argumentsDigest({ name: "é" }));
    expect(argumentsDigest({ ["é"]: 1 })).toBe(argumentsDigest({ ["é"]: 1 }));
  });

  it("numbers use the RFC 8785 form (1 = 1.0, -0 = 0, exponent form for large values)", () => {
    expect(argumentsDigest({ n: 1 })).toBe(argumentsDigest({ n: 1.0 }));
    expect(argumentsDigest({ n: -0 })).toBe(argumentsDigest({ n: 0 }));
    expect(argumentsDigest({ n: 1e21 })).toBe(crypto.createHash("sha256").update('{"n":1e+21}').digest("hex"));
    expect(argumentsDigest({ n: 1 })).not.toBe(argumentsDigest({ n: "1" }));
  });

  it("request_digest covers exactly agent_id, session_id, tool and arguments", () => {
    const base = { agent_id: "g", session_id: "s", tool: "t", arguments: { n: 1 } };
    const expected = crypto.createHash("sha256").update(canonicalize(base)).digest("hex");
    expect(requestDigest(base)).toBe(expected);
    for (const change of [{ agent_id: "g2" }, { session_id: "s2" }, { tool: "t2" }, { arguments: { n: 2 } }]) {
      expect(requestDigest({ ...base, ...change })).not.toBe(expected);
    }
  });
});

describe("authority fingerprint", () => {
  it("is the SHA-256 of the canonical list of member fingerprints, leaf first, order-sensitive", () => {
    const leaf = grant("L"); const i = grant("I"); const r = grant("R");
    const expected = crypto.createHash("sha256").update(canonicalize([capabilityFingerprint(leaf), capabilityFingerprint(i), capabilityFingerprint(r)])).digest("hex");
    expect(authorityFingerprint(leaf, [i, r])).toBe(expected);
    expect(authorityFingerprint(leaf, [r, i])).not.toBe(expected);
    expect(authorityFingerprint(leaf, [i])).not.toBe(expected);
  });

  it("ignores signatures (content fingerprints) and changes with any content field", () => {
    const leaf = grant("L");
    expect(authorityFingerprint({ ...leaf, signature: { ...leaf.signature, value: "BBBB" } }, [])).toBe(authorityFingerprint(leaf, []));
    expect(authorityFingerprint(grant("L", { expires_at: "2026-01-01T02:00:00.000Z" }), [])).not.toBe(authorityFingerprint(leaf, []));
  });
});

describe("execution binding source (M71)", () => {
  it("[LC-C-execution-authority] the execution authority of a start is the lineage's snapshot A, even for a provider answer B", () => {
    const draft = draftLineage({ agentId: "agent-test", sessionId: "s1", requestId: "r1", tool: "update_record", arguments: { n: { value: 1 } }, leaf: grant("A-L"), ancestors: [grant("A-I")] });
    const authority = startExecutionAuthority(draft, { leaf: grant("B-L", { tenant_id: "t9" }), ancestors: [grant("B-I")] });
    witness(["LC-C-execution-authority", [authority.capabilityId, authority.ancestorIds, authority.tenantId, authority.sessionId], ["A-L", ["A-I"], "t1", "s1"]]);
    expect(Object.isFrozen(authority)).toBe(true);
  });
});

describe("lineage draft: bindings are frozen copies", () => {
  it("later mutation of the inputs changes nothing; the bindings are deep-frozen", () => {
    const args = { n: { value: 1 } };
    const leaf = grant("L");
    const draft = draftLineage({ agentId: "g", sessionId: "s1", requestId: "r", tool: "update_record", arguments: args, leaf, ancestors: [] });
    args.n.value = 2;
    (leaf as { capability_id: string }).capability_id = "X";
    expect(draft.bindings.arguments_digest).toBe(argumentsDigest({ n: { value: 1 } }));
    expect(draft.bindings.leaf.capability_id).toBe("L");
    expect(Object.isFrozen(draft.bindings)).toBe(true);
    expect(Object.isFrozen(draft.bindings.leaf)).toBe(true);
    expect(Object.isFrozen(draft.bindings.leaf.allowed_tools)).toBe(true);
  });
});

describe("runtime-owned request snapshot (permit-mode process())", () => {
  it("is an independent, deep-frozen copy; later changes to the input do not reach it and writes to it fail", () => {
    const input = { params: { payload: { tool: { name: "update_record" }, arguments: { n: { value: 1 } } } } };
    const owned = ownedRequestSnapshot(input) as typeof input;
    input.params.payload.tool.name = "read_record";
    expect(owned.params.payload.tool.name).toBe("update_record");
    expect(() => { owned.params.payload.tool.name = "read_record"; }).toThrow(TypeError);
    expect(() => { (owned.params.payload.arguments as Record<string, unknown>).n = { value: 2 }; }).toThrow(TypeError);
    expect(Object.isFrozen(owned.params.payload.arguments.n)).toBe(true);
  });

  it("reads getters once and rejects input that is not a JSON value", () => {
    let reads = 0;
    const input = { get tool() { reads++; return reads === 1 ? "update_record" : "read_record"; } };
    const owned = ownedRequestSnapshot(input) as { tool: string };
    expect([owned.tool, owned.tool, reads]).toEqual(["update_record", "update_record", 1]);
    expect(() => ownedRequestSnapshot({ n: BigInt(1) })).toThrow(/JSON value/);
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    expect(() => ownedRequestSnapshot(cyclic)).toThrow(/JSON value/);
  });
});

describe("strict snapshot comparison (fail closed)", () => {
  const L = grant("L"); const I = grant("I");
  const env = { kind: "capability_chain", leaf: L, ancestors: [I] };

  it("equal chain matches; changed member, other leaf, other length do not", () => {
    expect(matchesLineageSnapshot(env, L, [I])).toBe(true);
    expect(matchesLineageSnapshot({ ...env, leaf: grant("L", { expires_at: "2026-01-01T00:30:00.000Z" }) }, L, [I])).toBe(false);
    expect(matchesLineageSnapshot({ ...env, ancestors: [] }, L, [I])).toBe(false);
    expect(matchesLineageSnapshot(grant("L2"), grant("L"), [])).toBe(false);
    expect(matchesLineageSnapshot(L, L, [])).toBe(true);
  });

  it("a thenable, a Proxy, an array, null or a member without a computable fingerprint does not match", () => {
    expect(matchesLineageSnapshot(Promise.resolve(env), L, [I])).toBe(false);
    expect(matchesLineageSnapshot({ ...env, then: () => undefined }, L, [I])).toBe(false);
    expect(matchesLineageSnapshot(new Proxy(env, {}), L, [I])).toBe(false);
    expect(matchesLineageSnapshot({ ...env, leaf: new Proxy(L, {}) }, L, [I])).toBe(false);
    expect(matchesLineageSnapshot([L], L, [])).toBe(false);
    expect(matchesLineageSnapshot(null, L, [])).toBe(false);
    const cyclic: Record<string, unknown> = { ...L }; cyclic.self = cyclic;
    expect(matchesLineageSnapshot(cyclic, L, [])).toBe(false);
  });
});

describe("chain validity at a final fence", () => {
  const members = [grant("L", { expires_at: "2026-01-01T00:30:00.000Z" }), grant("I")];
  it("uses the verifier's window [issued_at, expires_at) on every member, leaf first", () => {
    const at = (iso: string) => chainValidityAt(members, Date.parse(iso));
    expect(at("2025-12-31T23:59:59.999Z")).toBe("capability_not_yet_valid");
    expect(at("2026-01-01T00:00:00.000Z")).toBeUndefined();
    expect(at("2026-01-01T00:29:59.999Z")).toBeUndefined();
    expect(at("2026-01-01T00:30:00.000Z")).toBe("capability_expired");
    expect(chainValidityEnd(members)).toBe(Date.parse("2026-01-01T00:30:00.000Z"));
  });

  it("an unparsable time is invalid (fail closed)", () => {
    expect(chainValidityAt([grant("L", { expires_at: "not-a-date" })], Date.parse("2026-01-01T00:10:00.000Z"))).toBe("capability_expired");
  });
});

describe("ApprovalGrantV3 verification", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const signer = new TestSigner(privateKey, "approver-1");
  const verifier = new ApprovalGrantVerifier(publicKey, "approver-1");
  const digest = "a".repeat(64);
  const fp = "b".repeat(64);
  const body = {
    version: 3 as const, decision: "approve" as const, lineage_id: "lineage-1", session_id: "s1", request_id: "r1", tool: "update_record",
    request_digest: digest, authority_fingerprint: fp, approver: { type: "human" as const, id: "op" }, issued_at: "2026-01-01T00:00:00.000Z",
  };
  const ctx = {
    expectedLineageId: "lineage-1", expectedSessionId: "s1", expectedRequestId: "r1", expectedTool: "update_record",
    expectedRequestDigest: digest, expectedAuthorityFingerprint: fp, expectedApproverType: "human" as const, expectedApproverId: "op",
  };
  const code = (fn: () => unknown) => { try { fn(); return "ok"; } catch (e) { return e instanceof ApprovalVerificationError ? e.code : String(e); } };

  it("accepts a correctly signed grant and returns a copy", () => {
    const g = signer.sign(body);
    const verified = verifier.verifyV3(g, ctx);
    expect(verified).toEqual(g);
    expect(verified).not.toBe(g);
  });

  it.each([
    ["lineage_id", { lineage_id: "lineage-2" }, "LINEAGE_MISMATCH"],
    ["request_digest", { request_digest: "c".repeat(64) }, "REQUEST_DIGEST_MISMATCH"],
    ["authority_fingerprint", { authority_fingerprint: "d".repeat(64) }, "AUTHORITY_FINGERPRINT_MISMATCH"],
    ["session_id", { session_id: "s2" }, "SESSION_MISMATCH"],
    ["request_id", { request_id: "r2" }, "REQUEST_MISMATCH"],
    ["tool", { tool: "read_record" }, "TOOL_BINDING_MISMATCH"],
    ["approver", { approver: { type: "human", id: "other" } }, "WRONG_APPROVER_IDENTITY"],
  ])("a signed grant with another %s is rejected", (_f, change, expected) => {
    expect(code(() => verifier.verifyV3(signer.sign({ ...body, ...change } as typeof body), ctx))).toBe(expected);
  });

  it("missing or malformed digests, a V2 grant and a tampered field are rejected", () => {
    const { request_digest: _d, ...noDigest } = body;
    expect(code(() => verifier.verifyV3(signer.sign(noDigest as typeof body), ctx))).toBe("MALFORMED_GRANT");
    expect(code(() => verifier.verifyV3(signer.sign({ ...body, authority_fingerprint: "B".repeat(64) }), ctx))).toBe("MALFORMED_GRANT");
    expect(code(() => verifier.verifyV3(signer.sign({ ...body, lineage_id: "" }), ctx))).toBe("MALFORMED_GRANT");
    const { lineage_id: _l, request_digest: _r, authority_fingerprint: _a, ...v2body } = body;
    expect(code(() => verifier.verifyV3(signer.sign({ ...v2body, version: 2 } as never), ctx))).toBe("MALFORMED_GRANT");
    expect(code(() => verifier.verifyV3({ ...signer.sign(body), request_digest: "e".repeat(64) }, { ...ctx, expectedRequestDigest: "e".repeat(64) }))).toBe("INVALID_SIGNATURE");
  });

  it("verifyV2 still rejects a V3 grant (versions are not interchangeable)", () => {
    expect(code(() => verifier.verifyV2(signer.sign(body), { expectedSessionId: "s1", expectedRequestId: "r1", expectedTool: "update_record", expectedApproverType: "human", expectedApproverId: "op" }))).toBe("V1_REJECTED");
  });
});
