/**
 * Ancestor chains and descendant revocation (tenancy mode, package 1b). Effects are observed through the runtime's own
 * state and the tool doubles' own logs: tool calls, managed-state writes, returned content and the cancellation
 * signal seen inside the tool. Audit events are used only as check-point evidence (stage, boundary, rejection
 * reason), never as effect evidence.
 *
 * Tests whose name starts with a mutant id ("[M21]") are named witnesses in mutants/ancestor/manifest.json; C1.01 is
 * the valid-chain control that must keep passing under every ancestor mutant. Their decisive assertions are
 * `witness(...)` checks with fixed labels; every other expectation is ordinary.
 *
 * Every chain-verification witness uses a fresh executor, no revocation record and chain members never seen before,
 * so the verification under test is the only check that can reject the chain (unless the test says otherwise).
 */
import { tools } from "../src/tools";
import { AuditCollector } from "../src/audit";
import { AuthorityRevokedError } from "../src/guarded-executor";
import { CommitRejectedError, ExecutionContext } from "../src/managed-execution";
import { AuthorityRevocationRegistry } from "../src/authority-revocation";
import { MAX_CHAIN_LENGTH } from "../src/capability-grant";
import { OCSF_METADATA_ALLOWLIST } from "../src/ocsf/mapper";
import type { AuditEvent, AuditEventType } from "../src/acs-types";
import { fresh } from "./evals/eval-setup";
import { setupTenancy, tenantRequest, sessionUuid, TenancyCtx } from "./tenant-setup";
import { chain, ChainEnvelope, Grant, member, parentRef, serveChain, serveChains, signMember } from "./chain-setup";
import { observeError, witness } from "./witness";

type Deferred<T = void> = { promise: Promise<T>; resolve: (v: T) => void };
function deferred<T = void>(): Deferred<T> {
  let resolve!: (v: T) => void;
  return { promise: new Promise<T>(res => { resolve = res; }), resolve };
}
const original = { ...tools };
afterEach(() => { for (const k of Object.keys(tools)) delete tools[k]; Object.assign(tools, original); jest.restoreAllMocks(); });

interface Harness { calls: number; started: Deferred; ctx: ExecutionContext; signalled: boolean }
function scriptedTool(name: string, steps: (ctx: ExecutionContext, h: Harness) => Promise<unknown> = async () => ({ status: "ok" })) {
  const h: Harness = { calls: 0, started: deferred(), ctx: undefined as unknown as ExecutionContext, signalled: false };
  tools[name] = async (_args, ctx) => {
    h.calls++; h.ctx = ctx!; h.started.resolve();
    return steps(ctx!, h);
  };
  return h;
}
const tryCommit = (ctx: ExecutionContext, key: string, value: unknown): string => {
  try { ctx.commit(key, value); return "ok"; } catch (e) { return e instanceof CommitRejectedError ? e.reason : `error:${String(e)}`; }
};
type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };
/** Settles a call without throwing; every caught error is logged for the mutant gate (tests/witness.ts). */
const outcome = <T>(p: Promise<T>): Promise<Outcome<T>> => p.then(value => ({ ok: true as const, value }), error => { observeError(error); return { ok: false as const, error }; });
const stageOf = (o: Outcome<unknown>) => (!o.ok && o.error instanceof AuthorityRevokedError ? o.error.stage : undefined);
const reasonOf = (o: Outcome<unknown>) => (!o.ok && o.error instanceof AuthorityRevokedError ? o.error.reason : undefined);
const messageOf = (o: Outcome<unknown>) => (!o.ok && o.error instanceof Error ? o.error.message : "");
const positionOf = (o: Outcome<unknown>) => { const m = /chain position (\d+)/.exec(messageOf(o)); return m ? Number(m[1]) : undefined; };
const linkKindOf = (o: Outcome<unknown>) =>
  /names parent capability id/.test(messageOf(o)) ? "capability_id" : /parent fingerprint/.test(messageOf(o)) ? "fingerprint" : undefined;
const events = (ctx: TenancyCtx, type: AuditEventType, requestId?: string) =>
  ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === type && (requestId === undefined || e.request_id === requestId));
const rejectedReason = (ctx: TenancyCtx, requestId: string) => events(ctx, "capability_rejected", requestId).map(e => e.metadata!.reason)[0];
/** Runs `action` once, after the first audit record of `type`, with the metadata object the sink received. */
const onAudit = (ctx: TenancyCtx, type: AuditEventType, action: (meta?: Record<string, unknown>) => void) => {
  const recordOriginal = AuditCollector.prototype.record;
  let fired = false;
  jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
    recordOriginal.call(this, id, t, meta);
    if (t === type && !fired) { fired = true; action(meta); }
  });
};
const approvalFor = (ctx: TenancyCtx, req: ReturnType<typeof tenantRequest>) => ctx.testSigner.sign({
  version: 2, tool: req.params.payload.tool.name, decision: "approve", session_id: req.params.metadata.session_id,
  request_id: req.params.request_id, approver: { type: "human", id: "demo-operator" }, issued_at: fresh(ctx.clock.nowMs()),
});
const request = (ctx: TenancyCtx, name: string, session: string, tool = "read_record") => tenantRequest({ requestId: name, sessionId: session, tool }, ctx.clock);
const NONCE = "ancestor-output-nonce-4c1e";
const delivered = (value: unknown) => JSON.stringify(value).includes(NONCE);
const resultOf = (o: Outcome<{ status: string; result?: unknown }>) =>
  (o.ok && o.value.status === "executed" ? o.value.result : undefined) as { exit_status?: string; outputs?: { value?: { code?: string } }[] } | undefined;

/** A fresh executor serving the chain L -> I -> R (ids prefixed with `p`) for session `s`. */
function threeChain(p: string, s: string) {
  const ctx = setupTenancy();
  const env = chain(ctx, s, [{ id: `${p}-L` }, { id: `${p}-I` }, { id: `${p}-R` }]);
  serveChains(ctx, { [s]: env });
  return { ctx, env, L: `${p}-L`, I: `${p}-I`, R: `${p}-R` };
}

describe("C1 chain verification", () => {
  it("[chain-valid] C1.01 control: a leaf with a verified issuer-signed chain executes; the execution is bound to the chain", async () => {
    const { ctx, I, R } = threeChain("c101", "s-c101");
    const h = scriptedTool("read_record");
    const req = request(ctx, "c101", "s-c101");
    const o = await outcome(ctx.executor.process(req));
    await ctx.executor.whenTerminal("exec-1");
    witness(["A-chain-valid", [o.ok, h.calls, ctx.executor.getExecution("exec-1")?.ancestor_capability_ids], [true, 1, [I, R]]]);
    expect(ctx.executor.terminals()[0].ancestor_capability_ids).toEqual([I, R]);
    expect(events(ctx, "capability_verified", req.params.request_id)[0].metadata).toMatchObject({ capability_id: "c101-L", ancestor_capability_ids: [I, R], tenant_id: "t1" });
  });

  it("[M38] C1.02 a leaf whose parent the provider does not supply is rejected; it is never treated as a root", async () => {
    const ctx = setupTenancy();
    const env = chain(ctx, "s-c102", [{ id: "c102-L" }, { id: "c102-I" }]);
    serveChains(ctx, { "s-c102": { ...env, ancestors: [] } });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c102", "s-c102");
    await outcome(ctx.executor.process(req));
    witness(["A-M38-check", rejectedReason(ctx, req.params.request_id), "capability_malformed_chain"], ["A-M38-effect", h.calls, 0]);
  });

  it("C1.03 a parent reference without the chain, a chain past a root, and a parent seen earlier: all rejected (no chain from memory)", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const env = chain(ctx, "s-c103-a", [{ id: "c103-L" }, { id: "c103-P" }]);
    serveChains(ctx, { "s-c103-a": env });
    await ctx.executor.process(request(ctx, "c103-a", "s-c103-a"));
    expect(h.calls).toBe(1);
    // The parent c103-P is bound now; a child naming it without supplying it is still rejected.
    const child = member(ctx, { id: "c103-K" }, 0, sessionUuid("s-c103-b"), env.ancestors[0]);
    serveChain(ctx, "s-c103-b", child);
    const plain = request(ctx, "c103-b", "s-c103-b");
    await expect(ctx.executor.process(plain)).rejects.toThrow(/missing parent c103-P/);
    expect(rejectedReason(ctx, plain.params.request_id)).toBe("capability_malformed_chain");
    // A root followed by another member.
    const root = member(ctx, { id: "c103-X" }, 0, sessionUuid("s-c103-c"));
    serveChain(ctx, "s-c103-c", { kind: "capability_chain", leaf: root, ancestors: [env.ancestors[0]] });
    const past = request(ctx, "c103-c", "s-c103-c");
    await expect(ctx.executor.process(past)).rejects.toThrow(/continues past a root/);
    expect(rejectedReason(ctx, past.params.request_id)).toBe("capability_malformed_chain");
    expect(h.calls).toBe(1);
  });

  it("[M39] C1.04 a chain longer than the limit is rejected, not truncated", async () => {
    const ctx = setupTenancy();
    expect(MAX_CHAIN_LENGTH).toBe(8);
    serveChains(ctx, { "s-c104": chain(ctx, "s-c104", Array.from({ length: 9 }, (_, i) => ({ id: `c104-${i}` }))) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c104", "s-c104");
    await outcome(ctx.executor.process(req));
    witness(["A-M39-check", rejectedReason(ctx, req.params.request_id), "capability_chain_too_deep"], ["A-M39-effect", h.calls, 0]);
  });

  it("C1.05 a chain of exactly the limit (8 grants, leaf included) is accepted", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c105": chain(ctx, "s-c105", Array.from({ length: 8 }, (_, i) => ({ id: `c105-${i}` }))) });
    const h = scriptedTool("read_record");
    expect((await ctx.executor.process(request(ctx, "c105", "s-c105"))).status).toBe("executed");
    expect(h.calls).toBe(1);
    expect(ctx.executor.getExecution("exec-1")!.ancestor_capability_ids).toHaveLength(7);
  });

  it("[M40] C1.06 a repeated capability_id in the chain is rejected as such", async () => {
    const ctx = setupTenancy();
    // L -> P -> P' where P' carries P's id with other content: links and signatures are valid.
    serveChains(ctx, { "s-c106": chain(ctx, "s-c106", [{ id: "c106-L" }, { id: "c106-P" }, { id: "c106-P" }]) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c106", "s-c106");
    await outcome(ctx.executor.process(req));
    witness(["A-M40", rejectedReason(ctx, req.params.request_id), "capability_chain_repeated_id"]);
    expect(h.calls).toBe(0);
  });

  it("C1.07 a cycle (the leaf's id again as an ancestor) is rejected", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c107": chain(ctx, "s-c107", [{ id: "c107-L" }, { id: "c107-X" }, { id: "c107-L" }]) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c107", "s-c107");
    await expect(ctx.executor.process(req)).rejects.toThrow(/occurs more than once/);
    expect(rejectedReason(ctx, req.params.request_id)).toBe("capability_chain_repeated_id");
    expect(h.calls).toBe(0);
  });

  it("[M41] C1.08 a chain member of another tenant is rejected", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c108": chain(ctx, "s-c108", [{ id: "c108-L" }, { id: "c108-R", tenant: "t2" }]) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c108", "s-c108");
    await outcome(ctx.executor.process(req));
    witness(["A-M41-check", rejectedReason(ctx, req.params.request_id), "capability_tenant_chain_mismatch"], ["A-M41-effect", h.calls, 0]);
  });

  it("[M43] C1.09 attenuation: a child may not allow a tool its parent does not, or be valid beyond its parent", async () => {
    const tool = setupTenancy();
    serveChains(tool, { "s-c109-a": chain(tool, "s-c109-a", [{ id: "c109a-L", tools: ["read_record"] }, { id: "c109a-R", tools: ["update_record"] }]) });
    const window = setupTenancy();
    serveChains(window, { "s-c109-b": chain(window, "s-c109-b", [{ id: "c109b-L", expires: 400000 }, { id: "c109b-R" }]) });
    const h = scriptedTool("read_record");
    const reqA = request(tool, "c109-a", "s-c109-a");
    const reqB = request(window, "c109-b", "s-c109-b");
    await outcome(tool.executor.process(reqA));
    await outcome(window.executor.process(reqB));
    witness(
      ["A-M43-check", [rejectedReason(tool, reqA.params.request_id), rejectedReason(window, reqB.params.request_id)], ["capability_chain_attenuation", "capability_chain_attenuation"]],
      ["A-M43-effect", h.calls, 0],
    );
  });

  it("[M44] C1.10 a root with an invalid signature is rejected at chain position 2; nothing runs", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c110": chain(ctx, "s-c110", [{ id: "c110-L" }, { id: "c110-I" }, { id: "c110-R", untrusted: true }]) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c110", "s-c110");
    const o = await outcome(ctx.executor.process(req));
    witness(
      ["A-M44-check", [rejectedReason(ctx, req.params.request_id), positionOf(o)], ["capability_authentication_failed", 2]],
      ["A-M44-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]],
    );
  });

  it("[M45] C1.11 an intermediate member with an invalid signature is rejected at chain position 1; nothing runs", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c111": chain(ctx, "s-c111", [{ id: "c111-L" }, { id: "c111-I", untrusted: true }, { id: "c111-R" }]) });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c111", "s-c111");
    const o = await outcome(ctx.executor.process(req));
    witness(
      ["A-M45-check", [rejectedReason(ctx, req.params.request_id), positionOf(o)], ["capability_authentication_failed", 1]],
      ["A-M45-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]],
    );
  });

  it("[M46] C1.12 a replaced parent (same capability_id, other content) is rejected by the fingerprint link", async () => {
    const ctx = setupTenancy();
    const env = chain(ctx, "s-c112", [{ id: "c112-L" }, { id: "c112-I" }, { id: "c112-R" }]);
    const replaced = member(ctx, { id: "c112-I", issued: -2500 }, 1, sessionUuid("s-c112"), env.ancestors[1]);
    serveChains(ctx, { "s-c112": { ...env, ancestors: [replaced, env.ancestors[1]] } });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c112", "s-c112");
    const o = await outcome(ctx.executor.process(req));
    witness(
      ["A-M46-check", [rejectedReason(ctx, req.params.request_id), linkKindOf(o)], ["capability_chain_link_mismatch", "fingerprint"]],
      ["A-M46-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]],
    );
  });

  it("[M47] C1.13 a substituted parent (another validly signed grant) is rejected by the capability_id link", async () => {
    const ctx = setupTenancy();
    const env = chain(ctx, "s-c113", [{ id: "c113-L" }, { id: "c113-I" }, { id: "c113-R" }]);
    const substitute = member(ctx, { id: "c113-J" }, 1, sessionUuid("s-c113"), env.ancestors[1]);
    serveChains(ctx, { "s-c113": { ...env, ancestors: [substitute, env.ancestors[1]] } });
    const h = scriptedTool("read_record");
    const req = request(ctx, "c113", "s-c113");
    const o = await outcome(ctx.executor.process(req));
    witness(["A-M47", [rejectedReason(ctx, req.params.request_id), linkKindOf(o)], ["capability_chain_link_mismatch", "capability_id"]]);
    expect(h.calls).toBe(0);
  });

  it("[M48] C1.14 approval: a chain that differs from the pending request's snapshot is rejected as a snapshot mismatch", async () => {
    const ctx = setupTenancy();
    const env = chain(ctx, "s-c114", [{ id: "c114-L" }, { id: "c114-I" }, { id: "c114-R" }]);
    serveChains(ctx, { "s-c114": env });
    const h = scriptedTool("update_record");
    const req = request(ctx, "c114", "s-c114", "update_record");
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    const replaced = member(ctx, { id: "c114-I", issued: -2500 }, 1, sessionUuid("s-c114"), env.ancestors[1]);
    serveChain(ctx, "s-c114", { ...env, ancestors: [replaced, env.ancestors[1]] });
    await outcome(ctx.executor.resolveApproval(approvalFor(ctx, req)));
    witness(["A-M48", rejectedReason(ctx, req.params.request_id), "chain_snapshot_mismatch"]);
    expect(h.calls).toBe(0);
  });

  it("C1.15 a rejected chain stops before the Guardian decision, a pending approval, a permit, an execution and the tool call", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, { "s-c115": chain(ctx, "s-c115", [{ id: "c115-L" }, { id: "c115-R", untrusted: true }]) });
    const h = scriptedTool("update_record");
    const req = request(ctx, "c115", "s-c115", "update_record");
    await expect(ctx.executor.process(req)).rejects.toThrow(/chain position 1/);
    for (const type of ["guardian_decision", "approval_requested", "tool_execution_started", "capability_verified"] as const) {
      expect(events(ctx, type, req.params.request_id)).toEqual([]);
    }
    await expect(ctx.executor.resolveApproval(approvalFor(ctx, req))).rejects.toThrow(/No pending action/);
    expect(ctx.executor.getExecution("exec-1")).toBeUndefined();
    expect(h.calls).toBe(0);
  });

  it("C1.16 malformed chains and parent references are rejected fail closed", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const env = chain(ctx, "s-c116", [{ id: "c116-L" }, { id: "c116-R" }]);
    const leafWithBadRef = member(ctx, { id: "c116-M", parent: { capability_id: "c116-R", fingerprint: "not-hex" } }, 0, sessionUuid("s-c116-d"));
    const cases: [string, unknown, string][] = [
      ["s-c116-a", { ...env, extra: true }, "capability_malformed_chain"],
      ["s-c116-b", { kind: "capability_chain", leaf: env.leaf, ancestors: "c116-R" }, "capability_malformed_chain"],
      ["s-c116-c", { kind: "capability_chain", leaf: member(ctx, { id: "c116-N" }, 0, sessionUuid("s-c116-c")), ancestors: [null] }, "capability_malformed"],
      ["s-c116-d", leafWithBadRef, "capability_malformed"],
    ];
    for (const [session, answer] of cases) serveChain(ctx, session, answer as Grant);
    for (const [session, , reason] of cases) {
      const req = request(ctx, `c116-${session}`, session);
      await expect(ctx.executor.process(req)).rejects.toThrow(/Capability rejected/);
      expect(rejectedReason(ctx, req.params.request_id)).toBe(reason);
    }
    expect(h.calls).toBe(0);
  });
});

describe("C2 chain binding", () => {
  it("[M42b] C2.01 an ancestor id bound through a used chain cannot be presented later with other content", async () => {
    const ctx = setupTenancy();
    const first = chain(ctx, "s-c201-a", [{ id: "c201-L1" }, { id: "c201-P" }, { id: "c201-R" }]);
    const rebound = member(ctx, { id: "c201-P", issued: -2500 }, 1, sessionUuid("s-c201-b"), first.ancestors[1]);
    const second: ChainEnvelope = { kind: "capability_chain", leaf: member(ctx, { id: "c201-L2" }, 0, sessionUuid("s-c201-b"), rebound), ancestors: [rebound, first.ancestors[1]] };
    serveChains(ctx, { "s-c201-a": first, "s-c201-b": second });
    const h = scriptedTool("read_record");
    await ctx.executor.process(request(ctx, "c201-a", "s-c201-a"));
    expect(h.calls).toBe(1);
    const req = request(ctx, "c201-b", "s-c201-b");
    await outcome(ctx.executor.process(req));
    witness(["A-M42b-check", rejectedReason(ctx, req.params.request_id), "capability_id_conflict"], ["A-M42b-effect", h.calls, 1]);
  });

  it("C2.02 a conflicting chain leaves no partial bindings: its new members stay unbound", async () => {
    const ctx = setupTenancy();
    const used = chain(ctx, "s-c202-a", [{ id: "c202-L" }, { id: "c202-R" }]);
    // The leaf conflicts with the bound c202-L; its ancestors c202-N and c202-Q are new.
    const conflicting = chain(ctx, "s-c202-b", [{ id: "c202-L", issued: -1200 }, { id: "c202-N" }, { id: "c202-Q" }]);
    // Other content for c202-N and c202-Q: accepted only if the rejected chain bound nothing.
    const later = chain(ctx, "s-c202-c", [{ id: "c202-M" }, { id: "c202-N", issued: -2700 }, { id: "c202-Q", issued: -3700 }]);
    serveChains(ctx, { "s-c202-a": used, "s-c202-b": conflicting, "s-c202-c": later });
    const h = scriptedTool("read_record");
    await ctx.executor.process(request(ctx, "c202-a", "s-c202-a"));
    const bad = request(ctx, "c202-b", "s-c202-b");
    await expect(ctx.executor.process(bad)).rejects.toThrow(/already bound to a different grant/);
    expect(rejectedReason(ctx, bad.params.request_id)).toBe("capability_id_conflict");
    expect((await ctx.executor.process(request(ctx, "c202-c", "s-c202-c"))).status).toBe("executed");
    expect(h.calls).toBe(2);
  });

  it("C2.03 a chain whose ancestor session is bound to another tenant is rejected before anything is bound", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    ctx.provider.answerFor = undefined;
    ctx.provider.tenants.set(sessionUuid("anc-c203-R"), "t2");
    await ctx.executor.process(request(ctx, "c203-a", "anc-c203-R"));
    expect(h.calls).toBe(1);
    serveChains(ctx, { "s-c203": chain(ctx, "s-c203", [{ id: "c203-L" }, { id: "c203-R" }]) });
    const req = request(ctx, "c203-b", "s-c203");
    await expect(ctx.executor.process(req)).rejects.toThrow(/different tenant/);
    expect(rejectedReason(ctx, req.params.request_id)).toBe("session_tenant_conflict");
    expect(h.calls).toBe(1);
  });

  it("[M42a] C2.04 the execution's chain is the start-time binding: no capability or chain is resolved again after start", async () => {
    const { ctx, I, R } = threeChain("c204", "s-c204");
    const gate = deferred(); let commit = "";
    const h = scriptedTool("read_record", async c => { await gate.promise; commit = tryCommit(c, "k", 1); return { data: NONCE }; });
    const run = ctx.executor.process(request(ctx, "c204", "s-c204"));
    await h.started.promise;
    const afterStart = ctx.provider.resolveCalled;
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    gate.resolve();
    const out = await run;
    expect(commit).toBe("ancestor_revoked");
    expect(delivered(out)).toBe(false);
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.ancestor_capability_ids).toEqual([I, R]);
    witness(["A-M42a", ctx.provider.resolveCalled - afterStart, 0]);
  });

  it("C2.05 a chain change after start does not change the running execution's bound chain", async () => {
    const { ctx, I, R } = threeChain("c205", "s-c205");
    const gate = deferred(); let commit = "";
    const h = scriptedTool("read_record", async c => { await gate.promise; commit = tryCommit(c, "k", 1); return { data: NONCE }; });
    const run = ctx.executor.process(request(ctx, "c205", "s-c205"));
    await h.started.promise;
    // The provider now answers with an unrelated root grant; the running execution keeps its start-time chain.
    serveChain(ctx, "s-c205", member(ctx, { id: "c205-other" }, 0, sessionUuid("s-c205")));
    ctx.executor.revoke({ scope: "capability", capability_id: R });
    gate.resolve();
    const out = await run;
    expect(commit).toBe("ancestor_revoked");
    expect(delivered(out)).toBe(false);
    expect((await ctx.executor.whenTerminal(h.ctx.execution_id)).ancestor_capability_ids).toEqual([I, R]);
  });
});

describe("C3 ancestor revocation at the runtime check points", () => {
  it("[M27b] C3.01 request check after verification: an ancestor revoked before its first use denies the descendant at stage request", async () => {
    const { ctx, I } = threeChain("c301", "s-c301");
    scriptedTool("read_record");
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    const o = await outcome(ctx.executor.process(request(ctx, "c301", "s-c301")));
    expect(reasonOf(o)).toBe("ancestor_revoked");
    witness(["A-M27b", stageOf(o), "request"]);
  });

  it("[M20] C3.02 a descendant of a revoked ancestor is denied at request and start; the tool is never called", async () => {
    const { ctx, R } = threeChain("c302", "s-c302");
    const h = scriptedTool("read_record");
    ctx.executor.revoke({ scope: "capability", capability_id: R });
    const o = await outcome(ctx.executor.process(request(ctx, "c302", "s-c302")));
    witness(["A-M20-decision", reasonOf(o), "ancestor_revoked"], ["A-M20-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]]);
  });

  it("[M27g] C3.03 early start check: an ancestor revoked after the request checks is denied before the gate starts the tool", async () => {
    const { ctx, I } = threeChain("c303", "s-c303");
    const h = scriptedTool("read_record");
    const req = request(ctx, "c303", "s-c303");
    onAudit(ctx, "guardian_decision", () => ctx.executor.revoke({ scope: "capability", capability_id: I }));
    const o = await outcome(ctx.executor.process(req));
    expect([stageOf(o), reasonOf(o)]).toEqual(["start", "ancestor_revoked"]);
    expect(h.calls).toBe(0);
    witness(["A-M27g", events(ctx, "tool_execution_started", req.params.request_id).length, 0]);
  });

  it("[M27d] C3.04 start guard: an ancestor revoked at tool_execution_started is denied immediately before the tool call", async () => {
    const { ctx, I } = threeChain("c304", "s-c304");
    const h = scriptedTool("read_record");
    onAudit(ctx, "tool_execution_started", () => ctx.executor.revoke({ scope: "capability", capability_id: I }));
    const o = await outcome(ctx.executor.process(request(ctx, "c304", "s-c304")));
    witness(["A-M27d-check", stageOf(o), "start"], ["A-M27d-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]]);
  });

  it("[M34a] C3.05 approval: a pending descendant of a revoked ancestor is denied at the approval re-verification", async () => {
    const { ctx, I } = threeChain("c305", "s-c305");
    scriptedTool("update_record");
    const req = request(ctx, "c305", "s-c305", "update_record");
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    const o = await outcome(ctx.executor.resolveApproval(approvalFor(ctx, req)));
    expect(reasonOf(o)).toBe("ancestor_revoked");
    witness(["A-M34a", stageOf(o), "approval"]);
  });

  it("[M34] C3.06 approval: a pending descendant of a revoked ancestor never calls the tool; the receipt lists it", async () => {
    const { ctx, R } = threeChain("c306", "s-c306");
    const h = scriptedTool("update_record");
    const req = request(ctx, "c306", "s-c306", "update_record");
    await ctx.executor.process(req);
    const receipt = ctx.executor.revoke({ scope: "capability", capability_id: R });
    expect(receipt).toMatchObject({ revocation_id: `capability:${R}`, pending_approvals: [req.params.request_id], in_flight_executions: [] });
    const o = await outcome(ctx.executor.resolveApproval(approvalFor(ctx, req)));
    witness(["A-M34-decision", reasonOf(o), "ancestor_revoked"], ["A-M34-effect", h.calls, 0]);
  });

  it("[M21] C3.07 commit fence: a running descendant of a revoked ancestor cannot commit; the managed state is unchanged", async () => {
    const { ctx, I } = threeChain("c307", "s-c307");
    const gate = deferred(); let commit = "";
    const h = scriptedTool("read_record", async c => { await gate.promise; commit = tryCommit(c, "balance", 100); return { status: "ok" }; });
    const run = ctx.executor.process(request(ctx, "c307", "s-c307"));
    await h.started.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    gate.resolve(); await outcome(run);
    witness(["A-M21-check", commit, "ancestor_revoked"], ["A-M21-effect", [ctx.executor.managedState.has("balance"), ctx.executor.managedState.version], [false, 0]]);
  });

  it("C3.08 a commit before the ancestor revocation stays a historical effect; the later commit and the delivery are denied", async () => {
    const { ctx, R } = threeChain("c308", "s-c308");
    const gate = deferred(); const commits: string[] = [];
    const h = scriptedTool("read_record", async c => { commits.push(tryCommit(c, "order", 7)); await gate.promise; commits.push(tryCommit(c, "order2", 8)); return { data: NONCE }; });
    const run = ctx.executor.process(request(ctx, "c308", "s-c308"));
    await h.started.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: R });
    gate.resolve();
    const out = await run;
    expect(commits).toEqual(["ok", "ancestor_revoked"]);
    expect(ctx.executor.managedState.get("order")).toBe(7);
    expect(ctx.executor.managedState.has("order2")).toBe(false);
    expect(delivered(out)).toBe(false);
  });

  it("[M35] C3.09 delivery: the output of a descendant whose ancestor was revoked while it ran is withheld", async () => {
    const { ctx, I } = threeChain("c309", "s-c309");
    const gate = deferred();
    const h = scriptedTool("read_record", async () => { await gate.promise; return { data: NONCE }; });
    const run = outcome(ctx.executor.process(request(ctx, "c309", "s-c309")));
    await h.started.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    gate.resolve();
    const o = await run;
    const result = resultOf(o);
    witness(
      ["A-M35-decision", [result?.exit_status, result?.outputs?.[0]?.value?.code], ["blocked", "ancestor_revoked"]],
      ["A-M35-effect", delivered(o), false],
    );
  });

  it("[M35a] C3.10 delivery: an ancestor revocation while the tool runs is enforced at the early delivery check", async () => {
    const { ctx, I } = threeChain("c310", "s-c310");
    const gate = deferred();
    const h = scriptedTool("read_record", async () => { await gate.promise; return { data: NONCE }; });
    const run = ctx.executor.process(request(ctx, "c310", "s-c310"));
    await h.started.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    gate.resolve();
    expect(delivered(await run)).toBe(false);
    const boundaries = events(ctx, "authority_revocation_enforced").filter(e => e.metadata!.stage === "delivery").map(e => e.metadata!.boundary);
    witness(["A-M35a", boundaries, ["result_processing"]]);
  });

  it("[M35b] C3.11 hand-over: an ancestor revoked after the early delivery check is withheld at the public API return", async () => {
    const { ctx, R } = threeChain("c311", "s-c311");
    scriptedTool("read_record", async () => ({ data: NONCE }));
    onAudit(ctx, "tool_result_delivered", () => ctx.executor.revoke({ scope: "capability", capability_id: R }));
    const o = await outcome(ctx.executor.process(request(ctx, "c311", "s-c311")));
    const result = resultOf(o);
    witness(
      ["A-M35b-check", [result?.exit_status, result?.outputs?.[0]?.value?.code], ["blocked", "ancestor_revoked"]],
      ["A-M35b-effect", delivered(o), false],
    );
  });

  it("[M36] C3.12 cancellation: an ancestor revocation sends the cancellation signal to its running descendant; the signal is not termination", async () => {
    const { ctx, I } = threeChain("c312", "s-c312");
    const gate = deferred(); let requestedInTool: boolean | undefined;
    const h = scriptedTool("read_record", async (c, h) => { c.cancellation.onCancel(() => { h.signalled = true; }); await gate.promise; requestedInTool = c.cancellation.requested; return { status: "ok" }; });
    const req = request(ctx, "c312", "s-c312");
    const run = ctx.executor.process(req);
    await h.started.promise;
    const receipt = ctx.executor.revoke({ scope: "capability", capability_id: I });
    const snapshot = ctx.executor.getExecution(h.ctx.execution_id)!;
    const acknowledged = h.ctx.acknowledgeCancellation();
    const afterAck = ctx.executor.getExecution(h.ctx.execution_id)!;
    gate.resolve(); await outcome(run);
    witness(["A-M36-effect", [h.signalled, requestedInTool, snapshot.cancellation_requested], [true, true, true]]);
    expect(receipt.in_flight_executions).toEqual([req.params.request_id]);
    expect(acknowledged).toBe(true);
    expect(afterAck.state).toBe("running");
    expect(afterAck.terminal).toBeUndefined();
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(terminal.ancestor_capability_ids).toEqual(["c312-I", "c312-R"]);
  });
});

describe("C4 scope: siblings, branches, sessions and tenants", () => {
  /** R -> A -> {C1 (session s1), C2 (session s2)}; A is also usable directly in its own session. */
  function tree(p: string) {
    const ctx = setupTenancy();
    const branch1 = chain(ctx, `${p}-s1`, [{ id: `${p}-C1` }, { id: `${p}-A`, session: `${p}-sA` }, { id: `${p}-R`, session: `${p}-sR` }]);
    const [A, R] = branch1.ancestors;
    const branch2: ChainEnvelope = { kind: "capability_chain", leaf: member(ctx, { id: `${p}-C2` }, 0, sessionUuid(`${p}-s2`), A), ancestors: [A, R] };
    const parent: ChainEnvelope = { kind: "capability_chain", leaf: A, ancestors: [R] };
    serveChains(ctx, { [`${p}-s1`]: branch1, [`${p}-s2`]: branch2, [`${p}-sA`]: parent, [`${p}-sR`]: R });
    return { ctx, A: `${p}-A`, R: `${p}-R`, C1: `${p}-C1`, C2: `${p}-C2` };
  }

  it("[M37] C4.01 a revocation does not propagate to the parent or to a sibling", async () => {
    const { ctx, C1 } = tree("c401");
    const h = scriptedTool("read_record");
    await ctx.executor.process(request(ctx, "c401-a", "c401-s1"));
    expect(h.calls).toBe(1);
    ctx.executor.revoke({ scope: "capability", capability_id: C1 });
    const own = await outcome(ctx.executor.process(request(ctx, "c401-b", "c401-s1")));
    const sibling = await outcome(ctx.executor.process(request(ctx, "c401-c", "c401-s2")));
    const parent = await outcome(ctx.executor.process(request(ctx, "c401-d", "c401-sA")));
    witness(["A-M37-decision", [sibling.ok, parent.ok], [true, true]], ["A-M37-effect", h.calls - 1, 2]);
    expect(reasonOf(own)).toBe("capability_revoked");
  });

  it("C4.02 a common ancestor's revocation covers both branches, not the ancestor's own parent or an unrelated chain", async () => {
    const { ctx, A } = tree("c402");
    const h = scriptedTool("read_record");
    serveChain(ctx, "c402-s3", chain(ctx, "c402-s3", [{ id: "c402-U" }, { id: "c402-UR" }]));
    ctx.executor.revoke({ scope: "capability", capability_id: A });
    for (const [name, session, reason] of [["c402-a", "c402-s1", "ancestor_revoked"], ["c402-b", "c402-s2", "ancestor_revoked"], ["c402-c", "c402-sA", "capability_revoked"]]) {
      const o = await outcome(ctx.executor.process(request(ctx, name, session)));
      expect([stageOf(o), reasonOf(o)]).toEqual(["request", reason]);
    }
    expect((await ctx.executor.process(request(ctx, "c402-d", "c402-sR"))).status).toBe("executed");
    expect((await ctx.executor.process(request(ctx, "c402-e", "c402-s3"))).status).toBe("executed");
    expect(h.calls).toBe(2);
  });

  it("C4.03 descendants in different sessions: an ancestor revocation fences and signals both; a session revocation only its own", async () => {
    const { ctx, A } = tree("c403");
    const gates: Record<string, Deferred> = { [sessionUuid("c403-s1")]: deferred(), [sessionUuid("c403-s2")]: deferred() };
    const started: Record<string, Deferred> = { [sessionUuid("c403-s1")]: deferred(), [sessionUuid("c403-s2")]: deferred() };
    const signalled: Record<string, boolean> = {}; const commits: Record<string, string> = {};
    tools["read_record"] = async (_args, c) => {
      const session = ctx.executor.getExecution(c!.execution_id)!.session_id;
      c!.cancellation.onCancel(() => { signalled[session] = true; });
      started[session].resolve();
      await gates[session].promise;
      commits[session] = tryCommit(c!, `k-${session}`, 1);
      return { data: NONCE };
    };
    const req1 = request(ctx, "c403-a", "c403-s1"), req2 = request(ctx, "c403-b", "c403-s2");
    const run1 = ctx.executor.process(req1), run2 = ctx.executor.process(req2);
    await Promise.all(Object.values(started).map(d => d.promise));
    const bySession = ctx.executor.revoke({ scope: "session", session_id: sessionUuid("c403-s1") });
    expect(bySession.in_flight_executions).toEqual([req1.params.request_id]);
    expect(signalled).toEqual({ [sessionUuid("c403-s1")]: true });
    const byAncestor = ctx.executor.revoke({ scope: "capability", capability_id: A });
    expect(byAncestor.in_flight_executions).toEqual([req1.params.request_id, req2.params.request_id].sort());
    expect(signalled).toEqual({ [sessionUuid("c403-s1")]: true, [sessionUuid("c403-s2")]: true });
    for (const g of Object.values(gates)) g.resolve();
    const [out1, out2] = await Promise.all([run1, run2]);
    expect(commits).toEqual({ [sessionUuid("c403-s1")]: "session_revoked", [sessionUuid("c403-s2")]: "ancestor_revoked" });
    expect(delivered(out1) || delivered(out2)).toBe(false);
    expect(ctx.executor.managedState.version).toBe(0);
  });

  it("C4.04 tenant semantics are kept: a tenant revocation covers the tenant's chains only; another tenant's chain runs", async () => {
    const ctx = setupTenancy();
    serveChains(ctx, {
      "s-c404-1": chain(ctx, "s-c404-1", [{ id: "c404-L1" }, { id: "c404-R1" }]),
      "s-c404-2": chain(ctx, "s-c404-2", [{ id: "c404-L2", tenant: "t2" }, { id: "c404-R2", tenant: "t2" }]),
    });
    const h = scriptedTool("read_record");
    ctx.executor.revoke({ scope: "capability", capability_id: "c404-R1" });
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o1 = await outcome(ctx.executor.process(request(ctx, "c404-a", "s-c404-1")));
    expect([stageOf(o1), reasonOf(o1)]).toEqual(["request", "tenant_revoked"]);
    expect((await ctx.executor.process(request(ctx, "c404-b", "s-c404-2"))).status).toBe("executed");
    expect(h.calls).toBe(1);
    expect(ctx.executor.getExecution("exec-1")).toMatchObject({ tenant_id: "t2", ancestor_capability_ids: ["c404-R2"] });
  });

  it("C4.05 registry precedence: tenant, then session, then ancestors (parent first), then the capability itself", () => {
    const registry = new AuthorityRevocationRegistry();
    const authority = { session_id: "s", capability_id: "L", tenant_id: "t1", ancestor_capability_ids: ["I", "R"] };
    expect(registry.check(authority)).toBeUndefined();
    registry.revoke({ scope: "capability", capability_id: "L" }, 0);
    expect(registry.check(authority)!.reason).toBe("capability_revoked");
    registry.revoke({ scope: "capability", capability_id: "R" }, 0);
    expect(registry.check(authority)!.record.revocation_id).toBe("capability:R");
    registry.revoke({ scope: "capability", capability_id: "I" }, 0);
    expect(registry.check(authority)).toMatchObject({ reason: "ancestor_revoked", record: { revocation_id: "capability:I" } });
    registry.revoke({ scope: "session", session_id: "s" }, 0);
    expect(registry.check(authority)!.reason).toBe("session_revoked");
    registry.revoke({ scope: "tenant", tenant_id: "t1" }, 0);
    expect(registry.check(authority)!.reason).toBe("tenant_revoked");
    expect(registry.check({ session_id: "other", capability_id: "X", ancestor_capability_ids: ["Y"] })).toBeUndefined();
  });
});

describe("C5 approval snapshots, legacy mode and export", () => {
  it("C5.01 approval: a chained pending request executes when the provider returns the same chain; the execution keeps the snapshot", async () => {
    const { ctx, I, R } = threeChain("c501", "s-c501");
    const h = scriptedTool("update_record");
    const req = request(ctx, "c501", "s-c501", "update_record");
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    await ctx.executor.resolveApproval(approvalFor(ctx, req));
    expect(h.calls).toBe(1);
    expect(ctx.executor.getExecution("exec-1")).toMatchObject({ capability_id: "c501-L", ancestor_capability_ids: [I, R] });
  });

  it("C5.02 approval: a pending request without ancestors is rejected if the provider now returns a chain", async () => {
    const ctx = setupTenancy();
    const env = chain(ctx, "s-c502", [{ id: "c502-L" }, { id: "c502-R" }]);
    const h = scriptedTool("update_record");
    const req = request(ctx, "c502", "s-c502", "update_record");
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    serveChains(ctx, { "s-c502": env });
    await expect(ctx.executor.resolveApproval(approvalFor(ctx, req))).rejects.toThrow(/differs from the chain verified at the request/);
    expect(rejectedReason(ctx, req.params.request_id)).toBe("chain_snapshot_mismatch");
    expect(h.calls).toBe(0);
  });

  it("C5.03 legacy mode: chain envelopes and parent references are rejected", async () => {
    const ctx = setupTenancy({ tenancy: false });
    const h = scriptedTool("read_record");
    const v1 = (id: string, extra: Record<string, unknown> = {}) => signMember(ctx, {
      version: 1, capability_id: id, agent_id: "agent-test", session_id: sessionUuid("s-c503"), allowed_tools: ["read_record"],
      issued_at: fresh(ctx.clock.nowMs(), -1000), expires_at: fresh(ctx.clock.nowMs(), 300000), ...extra,
    });
    serveChains(ctx, { "s-c503": { kind: "capability_chain", leaf: v1("c503-L"), ancestors: [] } });
    const env = request(ctx, "c503-a", "s-c503");
    await expect(ctx.executor.process(env)).rejects.toThrow(/require tenancy mode/);
    expect(rejectedReason(ctx, env.params.request_id)).toBe("capability_malformed_chain");
    serveChains(ctx, { "s-c503": v1("c503-M", { parent: parentRef(v1("c503-P")) }) });
    const ref = request(ctx, "c503-b", "s-c503");
    await expect(ctx.executor.process(ref)).rejects.toThrow(/parent is only valid/);
    expect(rejectedReason(ctx, ref.params.request_id)).toBe("capability_malformed");
    expect(h.calls).toBe(0);
  });

  it("C5.04 OCSF export carries only a verified chain: ancestor_capability_ids is allowlisted for grant- and execution-bound events", () => {
    for (const type of ["capability_verified", "authority_revocation_enforced", "tool_commit_blocked", "execution_cancellation_requested", "execution_terminal"] as const) {
      expect(OCSF_METADATA_ALLOWLIST[type]).toContain("ancestor_capability_ids");
    }
    expect(OCSF_METADATA_ALLOWLIST.capability_rejected).not.toContain("ancestor_capability_ids");
    expect(OCSF_METADATA_ALLOWLIST.authority_revoked).not.toContain("ancestor_capability_ids");
  });

  it("C5.05 enforcement evidence names the bound chain; the revocation of an ancestor is reported with reason ancestor_revoked", async () => {
    const { ctx, I, R } = threeChain("c505", "s-c505");
    scriptedTool("read_record");
    ctx.executor.revoke({ scope: "capability", capability_id: R });
    const req = request(ctx, "c505", "s-c505");
    await outcome(ctx.executor.process(req));
    expect(events(ctx, "authority_revocation_enforced", req.params.request_id)[0].metadata).toMatchObject({
      stage: "request", reason: "ancestor_revoked", revocation_id: `capability:${R}`, capability_id: "c505-L", ancestor_capability_ids: [I, R],
    });
  });
});

describe("C6 audit metadata never aliases the bound ancestor chain", () => {
  const ids = (meta?: Record<string, unknown>) => meta!.ancestor_capability_ids as string[];

  it("[M42c] C6.01 an audit sink that empties its ancestor list and revokes the ancestor before start: no tool call, no commit, no raw output", async () => {
    const { ctx, I } = threeChain("c601", "s-c601");
    const h = scriptedTool("read_record", async c => { tryCommit(c, "k", 17); return { data: NONCE }; });
    onAudit(ctx, "capability_verified", meta => {
      ids(meta).length = 0;
      ctx.executor.revoke({ scope: "capability", capability_id: I });
    });
    const o = await outcome(ctx.executor.process(request(ctx, "c601", "s-c601")));
    witness(
      ["A-M42c-check", [stageOf(o), reasonOf(o)], ["start", "ancestor_revoked"]],
      ["A-M42c-effect", [h.calls, ctx.executor.managedState.has("k"), delivered(o)], [0, false, false]],
    );
  });

  it("C6.02 an audit sink that changes its ancestor list without a revocation: the execution succeeds bound to the original chain", async () => {
    const { ctx, I, R } = threeChain("c602", "s-c602");
    const h = scriptedTool("read_record", async c => { tryCommit(c, "k", 1); return { data: NONCE }; });
    onAudit(ctx, "capability_verified", meta => { ids(meta).length = 0; ids(meta).push("c602-forged"); });
    const out = await ctx.executor.process(request(ctx, "c602", "s-c602"));
    expect(delivered(out)).toBe(true);
    expect(h.calls).toBe(1);
    expect(ctx.executor.managedState.get("k")).toBe(1);
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.ancestor_capability_ids).toEqual([I, R]);
    expect((await ctx.executor.whenTerminal(h.ctx.execution_id)).ancestor_capability_ids).toEqual([I, R]);
    // A revocation of the forged id covers nothing; the original ancestor still covers a new use.
    expect(ctx.executor.revoke({ scope: "capability", capability_id: "c602-forged" }).in_flight_executions).toEqual([]);
    ctx.executor.revoke({ scope: "capability", capability_id: I });
    const again = await outcome(ctx.executor.process(request(ctx, "c602-b", "s-c602")));
    expect([stageOf(again), reasonOf(again)]).toEqual(["request", "ancestor_revoked"]);
  });

  it("C6.03 a retained metadata list changed after start: commit, delivery and cancellation still use the original chain", async () => {
    const { ctx, I, R } = threeChain("c603", "s-c603");
    const retained: string[][] = [];
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      recordOriginal.call(this, id, t, meta);
      if (Array.isArray(meta?.ancestor_capability_ids)) retained.push(meta!.ancestor_capability_ids as string[]);
    });
    const gate = deferred(); let commit = ""; let signalled = false;
    const h = scriptedTool("read_record", async c => { c.cancellation.onCancel(() => { signalled = true; }); await gate.promise; commit = tryCommit(c, "k", 1); return { data: NONCE }; });
    const run = ctx.executor.process(request(ctx, "c603", "s-c603"));
    await h.started.promise;
    expect(retained.length).toBeGreaterThan(0);
    for (const list of retained) list.length = 0;
    const receipt = ctx.executor.revoke({ scope: "capability", capability_id: I });
    gate.resolve();
    const out = await run;
    expect(signalled).toBe(true);
    expect(receipt.in_flight_executions).toHaveLength(1);
    expect(commit).toBe("ancestor_revoked");
    expect(ctx.executor.managedState.has("k")).toBe(false);
    expect(delivered(out)).toBe(false);
    expect(out.status === "executed" ? (out.result.outputs?.[0]?.value as { code?: string }).code : undefined).toBe("ancestor_revoked");
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.ancestor_capability_ids).toEqual([I, R]);
  });
});
