/**
 * Tenant scope (tenancy mode, package 1a). Effects are observed through the runtime's own state and the tool doubles'
 * own logs: tool calls, managed-state writes, returned content and the cancellation signal seen inside the tool.
 * Audit events are used only as check-point evidence (stage, boundary, rejection reason), never as effect evidence.
 *
 * Tests whose name starts with a mutant id ("[M15]") are named witnesses in mutants/tenant/manifest.json. Their
 * decisive assertions are `witness(...)` checks with fixed labels; every other expectation is ordinary.
 */
import crypto from "crypto";
import { tools } from "../src/tools";
import { AuditCollector } from "../src/audit";
import { AuthorityRevokedError } from "../src/guarded-executor";
import { CommitRejectedError, ExecutionContext } from "../src/managed-execution";
import { AuthorityRevocationRegistry, capabilityFingerprint, parseRevocationTarget, RevocationTargetError } from "../src/authority-revocation";
import { CapabilityGrant } from "../src/capability-grant";
import { OCSF_METADATA_ALLOWLIST } from "../src/ocsf/mapper";
import type { AuditEvent, AuditEventType } from "../src/acs-types";
import { fresh } from "./evals/eval-setup";
import { setupTenancy, tenantRequest, sessionUuid, TenancyCtx } from "./tenant-setup";
import { witness } from "./witness";

type Deferred<T = void> = { promise: Promise<T>; resolve: (v: T) => void };
function deferred<T = void>(): Deferred<T> {
  let resolve!: (v: T) => void;
  return { promise: new Promise<T>(res => { resolve = res; }), resolve };
}
const original = { ...tools };
afterEach(() => { for (const k of Object.keys(tools)) delete tools[k]; Object.assign(tools, original); jest.restoreAllMocks(); });

interface Harness { calls: number; started: Deferred; ctx: ExecutionContext; log: string[]; signalled: boolean }
function scriptedTool(name: string, steps: (ctx: ExecutionContext, h: Harness) => Promise<unknown> = async () => ({ status: "ok" })) {
  const h: Harness = { calls: 0, started: deferred(), ctx: undefined as unknown as ExecutionContext, log: [], signalled: false };
  tools[name] = async (_args, ctx) => {
    h.calls++; h.ctx = ctx!; h.log.push("start"); h.started.resolve();
    return steps(ctx!, h);
  };
  return h;
}
const tryCommit = (h: Harness, key: string, value: unknown): string => {
  try { h.ctx.commit(key, value); return "ok"; } catch (e) { return e instanceof CommitRejectedError ? e.reason : `error:${String(e)}`; }
};
type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };
const outcome = <T>(p: Promise<T>): Promise<Outcome<T>> => p.then(value => ({ ok: true as const, value }), error => ({ ok: false as const, error }));
const stageOf = (o: Outcome<unknown>) => (!o.ok && o.error instanceof AuthorityRevokedError ? o.error.stage : undefined);
const reasonOf = (o: Outcome<unknown>) => (!o.ok && o.error instanceof AuthorityRevokedError ? o.error.reason : undefined);
const events = (ctx: TenancyCtx, type: AuditEventType, requestId?: string) =>
  ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === type && (requestId === undefined || e.request_id === requestId));
const rejectedReason = (ctx: TenancyCtx, requestId: string) => events(ctx, "capability_rejected", requestId).map(e => e.metadata!.reason)[0];
const sid = sessionUuid;
const onAudit = (ctx: TenancyCtx, type: AuditEventType, action: () => void) => {
  const recordOriginal = AuditCollector.prototype.record;
  let fired = false;
  jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
    recordOriginal.call(this, id, t, meta);
    if (t === type && !fired) { fired = true; action(); }
  });
};
const approvalFor = (ctx: TenancyCtx, req: ReturnType<typeof tenantRequest>) => ctx.testSigner.sign({
  version: 2, tool: req.params.payload.tool.name, decision: "approve", session_id: req.params.metadata.session_id,
  request_id: req.params.request_id, approver: { type: "human", id: "demo-operator" }, issued_at: fresh(ctx.clock.nowMs()),
});
const NONCE = "tenant-output-nonce-7f3a";
const delivered = (value: unknown) => JSON.stringify(value).includes(NONCE);

describe("T1 tenant grant and request binding", () => {
  it("T1.01 control: a tenant-bound grant executes; the execution, its terminal and capability_verified carry the grant's tenant", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const req = tenantRequest({ requestId: "t101", sessionId: "s-t101" }, ctx.clock);
    const out = await ctx.executor.process(req);
    expect(out.status).toBe("executed");
    expect(h.calls).toBe(1);
    await ctx.executor.whenTerminal("exec-1");
    expect(ctx.executor.getExecution("exec-1")).toMatchObject({ tenant_id: "t1", state: "terminal" });
    expect(ctx.executor.terminals()[0].tenant_id).toBe("t1");
    expect(events(ctx, "capability_verified", req.params.request_id)[0].metadata!.tenant_id).toBe("t1");
  });

  it("[M30] T1.02 the tenant comes from the signed grant: a request without tenant_id under a revoked tenant's grant is denied", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t102", sessionId: "s-t102" }, ctx.clock)));
    witness(["A-M30-decision", reasonOf(o), "tenant_revoked"], ["A-M30-effect", h.calls, 0]);
  });

  it("[M30b] T1.03 a request whose own tenant_id differs from the grant's tenant is rejected before any tool call", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const req = tenantRequest({ requestId: "t103", sessionId: "s-t103", tenantId: "t2" }, ctx.clock);
    await outcome(ctx.executor.process(req));
    witness(["A-M30b-check", rejectedReason(ctx, req.params.request_id), "tenant_mismatch"], ["A-M30b-effect", h.calls, 0]);
  });

  it("T1.04 control: a request whose tenant_id equals the grant's tenant executes", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const out = await ctx.executor.process(tenantRequest({ requestId: "t104", sessionId: "s-t104", tenantId: "t1" }, ctx.clock));
    expect(out.status).toBe("executed");
    expect(h.calls).toBe(1);
  });

  it("[M31] T1.05 a tenantless (version 1) grant is rejected in tenancy mode; there is no default tenant", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    ctx.provider.grantFor = () => ({ version: 1 });
    const req = tenantRequest({ requestId: "t105", sessionId: "s-t105" }, ctx.clock);
    await outcome(ctx.executor.process(req));
    witness(["A-M31-check", rejectedReason(ctx, req.params.request_id), "capability_missing_tenant"], ["A-M31-effect", h.calls, 0]);
  });

  it("T1.06 a version 2 grant without tenant_id, or with an invalid one, is rejected", async () => {
    for (const [name, spec, reason] of [
      ["missing", { version: 2 as const }, "capability_missing_tenant"],
      ["empty", { version: 2 as const, tenant_id: "" }, "capability_malformed"],
      ["too long", { version: 2 as const, tenant_id: "x".repeat(257) }, "capability_malformed"],
    ] as const) {
      const ctx = setupTenancy();
      const h = scriptedTool("read_record");
      ctx.provider.grantFor = () => spec;
      const req = tenantRequest({ requestId: `t106-${name}`, sessionId: `s-t106-${name}` }, ctx.clock);
      await expect(ctx.executor.process(req)).rejects.toThrow(/Capability rejected/);
      expect(rejectedReason(ctx, req.params.request_id)).toBe(reason);
      expect(h.calls).toBe(0);
    }
  });

  it("[M32] T1.07 a runtime session belongs to one tenant: a grant of another tenant for the same session is rejected", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    await ctx.executor.process(tenantRequest({ requestId: "t107-a", sessionId: "s-t107" }, ctx.clock));
    expect(h.calls).toBe(1);
    ctx.provider.tenants.set(sid("s-t107"), "t2");
    const reqB = tenantRequest({ requestId: "t107-b", sessionId: "s-t107" }, ctx.clock);
    await outcome(ctx.executor.process(reqB));
    witness(["A-M32-check", rejectedReason(ctx, reqB.params.request_id), "session_tenant_conflict"], ["A-M32-effect", h.calls - 1, 0]);
  });

  it("T1.08 regression (kept safeguards, not M33 evidence): one capability_id presented under another tenant cannot escape a tenant revocation", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const X = crypto.randomUUID();
    ctx.provider.grantFor = c => ({ version: 2, capability_id: X, tenant_id: c.session_id === sid("s-t108-new") ? "t2" : "t1" });
    await ctx.executor.process(tenantRequest({ requestId: "t108-a", sessionId: "s-t108" }, ctx.clock));
    expect(h.calls).toBe(1);
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    // New session: the fingerprint's session_id (and tenant_id) differ from the bound grant -> capability_id_conflict.
    const reqNew = tenantRequest({ requestId: "t108-b", sessionId: "s-t108-new" }, ctx.clock);
    await expect(ctx.executor.process(reqNew)).rejects.toThrow(/already bound to a different grant/);
    expect(rejectedReason(ctx, reqNew.params.request_id)).toBe("capability_id_conflict");
    // Same session: the session is bound to the revoked tenant, so the early request check denies before resolution.
    ctx.provider.grantFor = () => ({ version: 2, capability_id: X, tenant_id: "t2" });
    const reqSame = tenantRequest({ requestId: "t108-c", sessionId: "s-t108" }, ctx.clock);
    const o = await outcome(ctx.executor.process(reqSame));
    expect([stageOf(o), reasonOf(o)]).toEqual(["request", "tenant_revoked"]);
    // Without a revocation, the same session under another tenant is a session_tenant_conflict.
    const ctx2 = setupTenancy();
    scriptedTool("read_record");
    await ctx2.executor.process(tenantRequest({ requestId: "t108-d", sessionId: "s-t108" }, ctx2.clock));
    ctx2.provider.tenants.set(sid("s-t108"), "t2");
    const reqD = tenantRequest({ requestId: "t108-e", sessionId: "s-t108" }, ctx2.clock);
    await expect(ctx2.executor.process(reqD)).rejects.toThrow(/different tenant/);
    expect(h.calls).toBe(1);
  });

  it("[M33] T1.09 component: the capability binding registry treats grants differing only in tenant_id as different content", () => {
    const ctx = setupTenancy();
    const context = { agent_id: "agent-test", session_id: sid("s-t109"), request_id: "r", tool: "read_record" };
    const X = crypto.randomUUID();
    const g1 = ctx.provider.grant(context, { version: 2, capability_id: X, tenant_id: "t1" }) as unknown as CapabilityGrant;
    const g2 = { ...(g1 as object), tenant_id: "t2" } as unknown as CapabilityGrant;
    const registry = new AuthorityRevocationRegistry();
    const fingerprintsDiffer = capabilityFingerprint(g1) !== capabilityFingerprint(g2);
    const first = registry.bindCapability(g1);
    const second = registry.bindCapability(g2);
    witness(["A-M33", [fingerprintsDiffer, first, second], [true, true, false]]);
  });
});

describe("T2 tenant revocation at the runtime check points", () => {
  it("[M27a] T2.01 early request check: a session already bound to a revoked tenant is denied before any capability resolution", async () => {
    const ctx = setupTenancy();
    scriptedTool("read_record");
    await ctx.executor.process(tenantRequest({ requestId: "t201-a", sessionId: "s-t201" }, ctx.clock));
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const before = ctx.provider.resolveCalled;
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t201-b", sessionId: "s-t201" }, ctx.clock)));
    expect(reasonOf(o)).toBe("tenant_revoked");
    witness(["A-M27a", ctx.provider.resolveCalled - before, 0]);
  });

  it("[M27e] T2.02 request check after verification: a first use under a revoked tenant is denied at stage request", async () => {
    const ctx = setupTenancy();
    scriptedTool("read_record");
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t202", sessionId: "s-t202" }, ctx.clock)));
    witness(["A-M27e", stageOf(o), "request"]);
  });

  it("[M22] T2.03 a start under a revoked tenant is denied and the tool is never called", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t203", sessionId: "s-t203" }, ctx.clock)));
    witness(["A-M22-decision", reasonOf(o), "tenant_revoked"], ["A-M22-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]]);
  });

  it("[M27f] T2.04 early start check: a tenant revoked after the request checks is denied before the gate starts the tool", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    const req = tenantRequest({ requestId: "t204", sessionId: "s-t204" }, ctx.clock);
    onAudit(ctx, "guardian_decision", () => ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" }));
    const o = await outcome(ctx.executor.process(req));
    expect(stageOf(o)).toBe("start");
    expect(h.calls).toBe(0);
    witness(["A-M27f", events(ctx, "tool_execution_started", req.params.request_id).length, 0]);
  });

  it("[M27c] T2.05 start guard: a tenant revoked at tool_execution_started is denied immediately before the tool call", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    onAudit(ctx, "tool_execution_started", () => ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" }));
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t205", sessionId: "s-t205" }, ctx.clock)));
    witness(["A-M27c-check", stageOf(o), "start"], ["A-M27c-effect", [h.calls, ctx.executor.getExecution("exec-1") === undefined], [0, true]]);
  });

  it("[M26a] T2.06 approval: a pending approval under a revoked tenant is denied at the approval re-verification", async () => {
    const ctx = setupTenancy();
    scriptedTool("update_record");
    const req = tenantRequest({ requestId: "t206", sessionId: "s-t206", tool: "update_record" }, ctx.clock);
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o = await outcome(ctx.executor.resolveApproval(approvalFor(ctx, req)));
    witness(["A-M26a", stageOf(o), "approval"]);
  });

  it("[M26] T2.07 approval: a pending approval under a revoked tenant never calls the tool", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("update_record");
    const req = tenantRequest({ requestId: "t207", sessionId: "s-t207", tool: "update_record" }, ctx.clock);
    await ctx.executor.process(req);
    const receipt = ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    expect(receipt.pending_approvals).toEqual([req.params.request_id]);
    const o = await outcome(ctx.executor.resolveApproval(approvalFor(ctx, req)));
    witness(["A-M26-decision", reasonOf(o), "tenant_revoked"], ["A-M26-effect", h.calls, 0]);
  });

  it("[M15] T2.08 commit fence: a running execution of a revoked tenant cannot commit; the managed state is unchanged", async () => {
    const ctx = setupTenancy();
    const gate = deferred(); let commit = "";
    const h = scriptedTool("read_record", async (_c, h) => { await gate.promise; commit = tryCommit(h, "balance", 100); return { status: "ok" }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t208", sessionId: "s-t208" }, ctx.clock));
    await h.started.promise;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve(); await outcome(run);
    witness(["A-M15-check", commit, "tenant_revoked"], ["A-M15-effect", [ctx.executor.managedState.has("balance"), ctx.executor.managedState.version], [false, 0]]);
  });

  it("T2.09 a commit before the tenant revocation stays a historical effect; the later delivery is withheld", async () => {
    const ctx = setupTenancy();
    const gate = deferred(); const commits: string[] = [];
    const h = scriptedTool("read_record", async (_c, h) => { commits.push(tryCommit(h, "order", 7)); await gate.promise; commits.push(tryCommit(h, "order2", 8)); return { data: NONCE }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t209", sessionId: "s-t209" }, ctx.clock));
    await h.started.promise;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve();
    const out = await run;
    expect(commits).toEqual(["ok", "tenant_revoked"]);
    expect(ctx.executor.managedState.get("order")).toBe(7);
    expect(ctx.executor.managedState.has("order2")).toBe(false);
    expect(delivered(out)).toBe(false);
  });

  it("[M28] T2.10 delivery: the output of an execution whose tenant was revoked while it ran is withheld", async () => {
    const ctx = setupTenancy();
    const gate = deferred();
    const h = scriptedTool("read_record", async () => { await gate.promise; return { data: NONCE }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t210", sessionId: "s-t210" }, ctx.clock));
    await h.started.promise;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve();
    const out = await run;
    const result = out.status === "executed" ? out.result : undefined;
    witness(
      ["A-M28-decision", [result?.exit_status, (result?.outputs?.[0]?.value as { code?: string } | undefined)?.code], ["blocked", "tenant_revoked"]],
      ["A-M28-effect", delivered(out), false],
    );
  });

  it("[M28a] T2.11 delivery: a revocation while the tool runs is enforced at the early delivery check in result processing", async () => {
    const ctx = setupTenancy();
    const gate = deferred();
    const h = scriptedTool("read_record", async () => { await gate.promise; return { data: NONCE }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t211", sessionId: "s-t211" }, ctx.clock));
    await h.started.promise;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve();
    const out = await run;
    expect(delivered(out)).toBe(false);
    const boundaries = events(ctx, "authority_revocation_enforced").filter(e => e.metadata!.stage === "delivery").map(e => e.metadata!.boundary);
    witness(["A-M28a", boundaries, ["result_processing"]]);
  });

  it("[M28b] T2.12 hand-over: a tenant revoked after the early delivery check is withheld at the public API return", async () => {
    const ctx = setupTenancy();
    scriptedTool("read_record", async () => ({ data: NONCE }));
    onAudit(ctx, "tool_result_delivered", () => ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" }));
    const out = await ctx.executor.process(tenantRequest({ requestId: "t212", sessionId: "s-t212" }, ctx.clock));
    const result = out.status === "executed" ? out.result : undefined;
    witness(
      ["A-M28b-check", [result?.exit_status, (result?.outputs?.[0]?.value as { code?: string } | undefined)?.code], ["blocked", "tenant_revoked"]],
      ["A-M28b-effect", delivered(out), false],
    );
  });

  it("[M29] T2.13 cancellation: a tenant revocation sends the cancellation signal to the tenant's running execution", async () => {
    const ctx = setupTenancy();
    const gate = deferred(); let requestedInTool: boolean | undefined;
    const h = scriptedTool("read_record", async (c, h) => { c.cancellation.onCancel(() => { h.signalled = true; }); await gate.promise; requestedInTool = c.cancellation.requested; return { status: "ok" }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t213", sessionId: "s-t213" }, ctx.clock));
    await h.started.promise;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const snapshot = ctx.executor.getExecution(h.ctx.execution_id)!;
    // The acknowledgement is not termination: the execution is still running after it.
    const acknowledged = h.ctx.acknowledgeCancellation();
    const afterAck = ctx.executor.getExecution(h.ctx.execution_id)!;
    gate.resolve(); await outcome(run);
    witness(["A-M29-effect", [h.signalled, requestedInTool, snapshot.cancellation_requested], [true, true, true]]);
    expect(acknowledged).toBe(true);
    expect(afterAck.state).toBe("running");
    expect(afterAck.terminal).toBeUndefined();
  });

  it("[M33b] T2.14 the execution's tenant is the start-time binding: no capability is resolved again after start", async () => {
    const ctx = setupTenancy();
    const gate = deferred(); let commit = "";
    const h = scriptedTool("read_record", async (_c, h) => { await gate.promise; commit = tryCommit(h, "k", 1); return { data: NONCE }; });
    const run = ctx.executor.process(tenantRequest({ requestId: "t214", sessionId: "s-t214" }, ctx.clock));
    await h.started.promise;
    const afterStart = ctx.provider.resolveCalled;
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve();
    const out = await run;
    expect(commit).toBe("tenant_revoked");
    expect(delivered(out)).toBe(false);
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.tenant_id).toBe("t1");
    witness(["A-M33b", ctx.provider.resolveCalled - afterStart, 0]);
  });
});

describe("T3 tenant isolation, receipts and legacy mode", () => {
  it("[M16] T3.01 a tenant revocation does not reach another tenant", async () => {
    const ctx = setupTenancy();
    const h = scriptedTool("read_record");
    ctx.provider.tenants.set(sid("s-t301"), "t2");
    ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    const o = await outcome(ctx.executor.process(tenantRequest({ requestId: "t301", sessionId: "s-t301" }, ctx.clock)));
    witness(["A-M16-decision", o.ok, true], ["A-M16-effect", h.calls, 1]);
  });

  it("T3.02 in flight: the revoked tenant's execution is fenced and cancelled; another tenant's execution commits and delivers", async () => {
    const ctx = setupTenancy();
    const gate = deferred();
    const results: Record<string, string> = {};
    const signalled: Record<string, boolean> = {};
    tools["read_record"] = async (_args, c) => {
      const tenant = ctx.executor.getExecution(c!.execution_id)!.tenant_id!;
      c!.cancellation.onCancel(() => { signalled[tenant] = true; });
      await gate.promise;
      try { c!.commit(`k-${tenant}`, tenant); results[tenant] = "ok"; } catch (e) { results[tenant] = (e as CommitRejectedError).reason; }
      return { data: `${NONCE}-${tenant}` };
    };
    ctx.provider.tenants.set(sid("s-t302-b"), "t2");
    const runA = ctx.executor.process(tenantRequest({ requestId: "t302-a", sessionId: "s-t302-a" }, ctx.clock));
    const runB = ctx.executor.process(tenantRequest({ requestId: "t302-b", sessionId: "s-t302-b" }, ctx.clock));
    for (let i = 0; i < 20; i++) await Promise.resolve();
    const receipt = ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    gate.resolve();
    const [outA, outB] = await Promise.all([runA, runB]);
    expect(results).toEqual({ t1: "tenant_revoked", t2: "ok" });
    expect(signalled).toEqual({ t1: true });
    expect(JSON.stringify(outA)).not.toContain(`${NONCE}-t1`);
    expect(JSON.stringify(outB)).toContain(`${NONCE}-t2`);
    expect(ctx.executor.managedState.keys()).toEqual(["k-t2"]);
    expect(receipt.in_flight_executions).toEqual([tenantRequest({ requestId: "t302-a", sessionId: "s-t302-a" }, ctx.clock).params.request_id]);
  });

  it("T3.03 receipt: target, idempotence and the tenant's pending approvals only", async () => {
    const ctx = setupTenancy();
    scriptedTool("update_record");
    ctx.provider.tenants.set(sid("s-t303-b"), "t2");
    const reqA = tenantRequest({ requestId: "t303-a", sessionId: "s-t303-a", tool: "update_record" }, ctx.clock);
    const reqB = tenantRequest({ requestId: "t303-b", sessionId: "s-t303-b", tool: "update_record" }, ctx.clock);
    await ctx.executor.process(reqA); await ctx.executor.process(reqB);
    const first = ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    expect(first).toMatchObject({ revocation_id: "tenant:t1", target: { scope: "tenant", tenant_id: "t1" }, status: "revoked", pending_approvals: [reqA.params.request_id] });
    const again = ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" });
    expect(again).toMatchObject({ status: "already_revoked", effective_sequence: first.effective_sequence });
    expect(events(ctx, "authority_revoked")[0].metadata).toMatchObject({ scope: "tenant", tenant_id: "t1" });
  });

  it("T3.04 legacy mode: no tenant scope, tenant-bound grants rejected, a request's tenant_id is ignored", async () => {
    const ctx = setupTenancy({ tenancy: false });
    const h = scriptedTool("read_record");
    expect(() => ctx.executor.revoke({ scope: "tenant", tenant_id: "t1" })).toThrow(RevocationTargetError);
    expect(events(ctx, "authority_revoked")).toEqual([]);
    ctx.provider.grantFor = () => ({ version: 2, tenant_id: "t1" });
    const v2 = tenantRequest({ requestId: "t304-a", sessionId: "s-t304-a" }, ctx.clock);
    await expect(ctx.executor.process(v2)).rejects.toThrow(/Capability rejected/);
    expect(rejectedReason(ctx, v2.params.request_id)).toBe("capability_malformed");
    ctx.provider.grantFor = () => ({ version: 1, tenant_id: "t1" });
    const v1t = tenantRequest({ requestId: "t304-b", sessionId: "s-t304-b" }, ctx.clock);
    await expect(ctx.executor.process(v1t)).rejects.toThrow(/tenant_id is only valid/);
    ctx.provider.grantFor = () => ({ version: 1 });
    const out = await ctx.executor.process(tenantRequest({ requestId: "t304-c", sessionId: "s-t304-c", tenantId: "anything" }, ctx.clock));
    expect(out.status).toBe("executed");
    expect(h.calls).toBe(1);
    expect(ctx.executor.getExecution("exec-1")!.tenant_id).toBeUndefined();
  });

  it("T3.05 tenant targets are validated fail closed", () => {
    expect(parseRevocationTarget({ scope: "tenant", tenant_id: "t1" })).toEqual({ scope: "tenant", tenant_id: "t1" });
    for (const bad of [{ scope: "tenant" }, { scope: "tenant", tenant_id: "" }, { scope: "tenant", tenant_id: "t1", session_id: "s" }, { scope: "tenant", tenant_id: "x".repeat(257) }]) {
      expect(() => parseRevocationTarget(bad)).toThrow(RevocationTargetError);
    }
  });

  it("T3.06 OCSF export carries only the verified tenant: tenant_id is allowlisted for grant- and execution-bound events, not for rejections", () => {
    for (const type of ["capability_verified", "authority_revoked", "authority_revocation_enforced", "tool_commit_blocked", "execution_terminal"] as const) {
      expect(OCSF_METADATA_ALLOWLIST[type]).toContain("tenant_id");
    }
    expect(OCSF_METADATA_ALLOWLIST.capability_rejected).not.toContain("tenant_id");
  });
});
