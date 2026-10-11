/**
 * Approval-permit lifecycle (permit mode, G3/G4; docs/approval-permit-lifecycle.md). Tests L1–L16 of the lifecycle
 * plan (agent-control-evals docs/revocation/approval-permit-lifecycle-plan.md §7.4) and the transition table T1–T22.
 *
 * Evidence rules:
 *   - lifecycle effects are read from the runtime's lineage snapshots (state, *_seq) and from the receipts;
 *   - "no tool call" is asserted through the tool doubles' own counters, never through the audit;
 *   - audit records are used only as check-point evidence (stage, reason), never as effect evidence.
 *
 * Determinism: every test uses the injected clock, deterministic callbacks (audit sink, provider, Guardian test
 * double, tool body) for interleavings, and Promise.all only for genuinely concurrent calls. No test waits for time.
 * Decisive assertions use witness(...) labels ("LC-..."), so a later lifecycle mutant gate can name them.
 */
import { AuthorityRevokedError } from "../src/guarded-executor";
import { argumentsDigest, LifecycleDeniedError, LifecycleModeError, type LineageSnapshot } from "../src/approval-lifecycle";
import { Guardian } from "../src/guardian";
import { tools } from "../src/tools";
import type { AcsToolCallRequest } from "../src/acs-types";
import { setupTenancy, tenantRequest } from "./tenant-setup";
import { chain, ChainEnvelope, Grant, serveChain, serveChains, signMember } from "./chain-setup";
import {
  approvalV3, asTenancy, fresh, LifecycleCtx, onAudit, onNextResolve, restoreTools, sessionUuid, setupLifecycle,
  toolDouble, toolRequest,
} from "./lifecycle-setup";
import { observeError, witness } from "./witness";

afterEach(() => { restoreTools(); jest.restoreAllMocks(); });

type Outcome<T> = { ok: true; value: T } | { ok: false; error: unknown };
const settle = <T>(p: Promise<T>): Promise<Outcome<T>> => p.then(value => ({ ok: true as const, value }), error => { observeError(error); return { ok: false as const, error }; });
const attempt = <T>(fn: () => T): Outcome<T> => { try { return { ok: true, value: fn() }; } catch (error) { observeError(error); return { ok: false, error }; } };

/** "ok", "revoked:<stage>/<check>", or the lifecycle reason ("lineage_binding_mismatch:tool"), or "error:<message>". */
const verdict = (o: Outcome<unknown>): string => {
  if (o.ok) return "ok";
  const e = o.error;
  if (e instanceof AuthorityRevokedError) return `revoked:${e.stage}${e.check ? `/${e.check}` : ""}`;
  if (e instanceof LifecycleDeniedError) return e.qualifiedReason;
  return `error:${e instanceof Error ? e.message : String(e)}`;
};
const revokedReason = (o: Outcome<unknown>) => (!o.ok && o.error instanceof AuthorityRevokedError ? o.error.reason : undefined);

const SCOPES = ["capability", "ancestor", "session", "tenant"] as const;
type Scope = typeof SCOPES[number];

interface Fixture { ctx: LifecycleCtx; env: ChainEnvelope; session: string; L: string; I: string; R: string }

/**
 * A permit-mode executor serving the chain L -> I -> R (tenant t1) for session `s`. `leafExpires` sets the leaf's
 * validity end (ms from now); a longer one than the default extends the parents too, so the chain stays nested.
 */
function fixture(p: string, options: Parameters<typeof setupLifecycle>[0] = {}, leafExpires?: number, tools?: string[]): Fixture {
  const ctx = setupLifecycle(options);
  const s = `s-${p}`;
  const parentExpires = (i: number) => (leafExpires !== undefined && leafExpires > 300000 ? { expires: leafExpires + 1000 * i } : {});
  const env = chain(asTenancy(ctx), s, [
    { id: `${p}-L`, ...(leafExpires !== undefined ? { expires: leafExpires } : {}), ...(tools ? { tools } : {}) },
    { id: `${p}-I`, ...parentExpires(1), ...(tools ? { tools } : {}) },
    { id: `${p}-R`, ...parentExpires(2), ...(tools ? { tools } : {}) },
  ]);
  serveChains(asTenancy(ctx), { [s]: env });
  return { ctx, env, session: s, L: `${p}-L`, I: `${p}-I`, R: `${p}-R` };
}

const targetFor = (f: Fixture, scope: Scope) =>
  scope === "capability" ? { scope: "capability", capability_id: f.L }
    : scope === "ancestor" ? { scope: "capability", capability_id: f.I }
    : scope === "session" ? { scope: "session", session_id: sessionUuid(f.session) }
    : { scope: "tenant", tenant_id: "t1" };

let requestCounter = 0;
const req = (f: Fixture, o: Partial<Parameters<typeof toolRequest>[1]> = {}): AcsToolCallRequest =>
  toolRequest(f.ctx, { id: `r-${++requestCounter}`, session: f.session, ...o });

/** process() of an ASK request (update_record, { n: 1 }); returns the lineage id. */
async function pending(f: Fixture, o: Partial<Parameters<typeof toolRequest>[1]> = {}): Promise<string> {
  const result = await f.ctx.executor.process(req(f, o));
  if (result.status !== "pending") throw new Error(`expected pending, got ${result.status}`);
  return result.lineage_id;
}
const snap = (f: Fixture, id: string): LineageSnapshot => f.ctx.executor.getLineage(id)!;
const approve = (f: Fixture, id: string, overrides: Record<string, unknown> = {}) => f.ctx.executor.approve(approvalV3(f.ctx, snap(f, id), overrides));
async function approved(f: Fixture, o: Partial<Parameters<typeof toolRequest>[1]> = {}): Promise<string> {
  const id = await pending(f, o);
  approve(f, id);
  return id;
}
async function issued(f: Fixture, o: Partial<Parameters<typeof toolRequest>[1]> = {}): Promise<string> {
  const id = await approved(f, o);
  f.ctx.executor.issuePermit({ lineage_id: id });
  return id;
}
const start = (f: Fixture, id: string, o: Partial<Parameters<typeof toolRequest>[1]> = {}) =>
  f.ctx.executor.start({ lineage_id: id, request: req(f, o) });

describe("T1/T2 creation: process() in permit mode creates a lineage and starts nothing", () => {
  it("T1 Guardian ASK: lineage pending with frozen bindings and created_seq; no tool call; approval_requested names it", async () => {
    const f = fixture("t1");
    const tool = toolDouble("update_record");
    const r = req(f);
    const result = await f.ctx.executor.process(r);
    expect(result).toEqual({ status: "pending", lineage_id: "lineage-1", audit_recorded: true });
    const s = snap(f, "lineage-1");
    expect(s.state).toBe("pending");
    expect(s.bindings).toMatchObject({
      agent_id: "agent-test", session_id: sessionUuid(f.session), tenant_id: "t1", tool: "update_record",
      capability_id: f.L, ancestor_capability_ids: [f.I, f.R], request_id: r.params.request_id,
      arguments_digest: argumentsDigest({ n: { value: 1 } }),
    });
    expect(s.approval).toMatchObject({ state: "pending", approver: { type: "human", id: "demo-operator" }, created_seq: 1 });
    expect(s.permit).toEqual({ state: "none" });
    expect(s.covered_by).toBeNull();
    expect(tool.calls).toBe(0);
    expect(f.ctx.audit.getEvents().filter(e => e.event_type === "approval_requested").map(e => e.metadata)).toEqual([{ session_id: sessionUuid(f.session), lineage_id: "lineage-1" }]);
  });

  it("T2 Guardian ALLOW: lineage approved by policy (created_seq, approved_seq), nothing started; issue and start run it once", async () => {
    const f = fixture("t2");
    const read = toolDouble("read_record");
    const result = await f.ctx.executor.process(req(f, { tool: "read_record" }));
    expect(result).toEqual({ status: "approved", lineage_id: "lineage-1", audit_recorded: true });
    expect(read.calls).toBe(0);
    const s = snap(f, "lineage-1");
    expect(s.state).toBe("approved");
    expect(s.approval).toMatchObject({ state: "approved", approver: { type: "policy", id: "guardian" }, created_seq: 1, approved_seq: 2 });
    f.ctx.executor.issuePermit({ lineage_id: "lineage-1" });
    const started = await start(f, "lineage-1", { tool: "read_record" });
    expect(started.status).toBe("executed");
    expect(read.calls).toBe(1);
  });

  it("T3 Guardian DENY and any failed check create no lineage", async () => {
    const f = fixture("t3", {}, undefined, ["read_record", "update_record", "delete_record"]);
    await expect(f.ctx.executor.process(req(f, { tool: "delete_record" }))).rejects.toThrow(/deny/);
    serveChain(asTenancy(f.ctx), f.session, chain(asTenancy(f.ctx), f.session, [{ id: "t3-x", untrusted: true }]));
    await expect(f.ctx.executor.process(req(f))).rejects.toThrow(/Capability rejected/);
    expect(f.ctx.executor.lineages()).toEqual([]);
    expect(f.ctx.executor.authoritySequence()).toBe(0);
  });
});

describe("L3 valid lifecycle and the shared authority sequence", () => {
  it("[LC-L3] approve, issue, start: receipts in order with increasing *_seq; one tool call; permit consumed by the started execution", async () => {
    const f = fixture("l3");
    const tool = toolDouble("update_record");
    const id = await pending(f);
    const a = approve(f, id);
    const p = f.ctx.executor.issuePermit({ lineage_id: id });
    const r = req(f);
    const o = await settle(f.ctx.executor.start({ lineage_id: id, request: r }));
    const s = snap(f, id);
    witness(
      ["LC-L3-decision", verdict(o), "ok"],
      ["LC-L3-tool-calls", tool.calls, 1],
      ["LC-L3-state", s.state, "consumed"],
      ["LC-L3-seq", [s.approval.created_seq, a.approved_seq, p.issued_seq, s.permit.consumed_seq], [1, 2, 3, 4]],
    );
    expect(a).toEqual({ lineage_id: id, decision: "approved", approved_seq: 2, approver: { type: "human", id: "demo-operator" }, audit_recorded: true });
    expect(p).toMatchObject({ lineage_id: id, permit_id: "permit-1", issued_seq: 3, audit_recorded: true });
    expect(s.permit).toMatchObject({ state: "consumed", permit_id: "permit-1", start_request_id: r.params.request_id, execution_id: "exec-1" });
    const terminal = await f.ctx.executor.whenTerminal("exec-1");
    // The execution is bound to the lineage's authority (its chain snapshot), and to R′ by the gate permit.
    expect(terminal).toMatchObject({ outcome: "completed", request_id: r.params.request_id, capability_id: f.L, tenant_id: "t1", ancestor_capability_ids: [f.I, f.R] });
    expect(o.ok && o.value).toMatchObject({ status: "executed", lineage_id: id, result: { exit_status: "success" } });
  });

  it("D13 revocations and transitions share one monotonic sequence", async () => {
    const f = fixture("d13");
    toolDouble("update_record");
    const first = await pending(f);
    const second = await pending(f);
    const a = approve(f, first);
    const receipt = f.ctx.executor.revoke({ scope: "capability", capability_id: "unrelated-capability" });
    const p = f.ctx.executor.issuePermit({ lineage_id: first });
    expect([snap(f, first).approval.created_seq, snap(f, second).approval.created_seq, a.approved_seq, receipt.effective_sequence, p.issued_seq]).toEqual([1, 2, 3, 4, 5]);
    expect(f.ctx.executor.authoritySequence()).toBe(5);
  });
});

describe("L1 revocation while pending (every scope)", () => {
  it.each(SCOPES)("[LC-L1] %s: approve DENY revoked (approval); stays pending; issue and start DENY; no tool call; receipt pending_lineages", async scope => {
    const f = fixture(`l1-${scope}`);
    const tool = toolDouble("update_record");
    const id = await pending(f);
    const receipt = f.ctx.executor.revoke(targetFor(f, scope));
    const a = attempt(() => approve(f, id));
    const i = attempt(() => f.ctx.executor.issuePermit({ lineage_id: id }));
    const s = await settle(start(f, id));
    witness(
      ["LC-L1-approve", verdict(a), "revoked:approval/early"],
      ["LC-L1-state", snap(f, id).state, "pending"],
      ["LC-L1-issue", verdict(i), "not_approved"],
      ["LC-L1-start-denied", s.ok, false],
      ["LC-L1-tool-calls", tool.calls, 0],
    );
    expect(receipt).toMatchObject({ pending_lineages: [id], approved_lineages: [], unused_permits: [] });
    expect(receipt.enforced_at).toEqual(["request", "approval", "issue", "start", "delivery"]);
    expect(snap(f, id).covered_by).toEqual({ revocation_id: receipt.revocation_id, reason: revokedReason(a) });
  });

  it("[LC-L1-provider] revoke inside the provider callback of approve: F(approve) denies; approval stays pending", async () => {
    const f = fixture("l1p");
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    onNextResolve(f.ctx, () => f.ctx.executor.revoke({ scope: "capability", capability_id: f.L }));
    const a = attempt(() => f.ctx.executor.approve(grant));
    witness(["LC-L1p-approve", verdict(a), "revoked:approval/final"], ["LC-L1p-state", snap(f, id).approval.state, "pending"]);
    expect(snap(f, id).approval.approved_seq).toBeUndefined();
  });
});

describe("L2 / L2b revocation of an issued, unused permit (every scope)", () => {
  it.each(SCOPES)("[LC-L2] %s: revoke after issue: start DENY revoked; permit stays issued; no consumed_seq; no tool call; receipt unused_permits", async scope => {
    const f = fixture(`l2-${scope}`);
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const receipt = f.ctx.executor.revoke(targetFor(f, scope));
    const o = await settle(start(f, id));
    // The start order of the plan (§5.4) puts the request-stage checks of R′ (session and bound tenant before the
    // provider, capability/ancestors/tenant after verification) before the early start check, so a revocation made
    // before the call is denied at stage "request" (see the M57 row of plan §8.2; L2 cannot witness M57).
    witness(
      ["LC-L2-start", verdict(o), "revoked:request"],
      ["LC-L2-permit", snap(f, id).permit.state, "issued"],
      ["LC-L2-consumed-seq", snap(f, id).permit.consumed_seq, undefined],
      ["LC-L2-tool-calls", tool.calls, 0],
    );
    expect(receipt).toMatchObject({ pending_lineages: [], approved_lineages: [], unused_permits: [id] });
  });

  it.each(SCOPES)("[LC-L2b] %s: revoke inside the capability_verified sink of start: DENY at the early start check; permit issued; no tool call", async scope => {
    const f = fixture(`l2b-${scope}`);
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const r = req(f);
    onAudit(f.ctx, "capability_verified", () => f.ctx.executor.revoke(targetFor(f, scope)), r.params.request_id);
    const o = await settle(f.ctx.executor.start({ lineage_id: id, request: r }));
    witness(
      ["LC-L2b-start", verdict(o), "revoked:start/early"],
      ["LC-L2b-permit", snap(f, id).permit.state, "issued"],
      ["LC-L2b-tool-calls", tool.calls, 0],
    );
  });

  it("an approved (not issued) lineage is listed in approved_lineages and can no longer be issued", async () => {
    const f = fixture("l2a");
    const id = await approved(f);
    const receipt = f.ctx.executor.revoke({ scope: "session", session_id: sessionUuid(f.session) });
    expect(receipt).toMatchObject({ pending_lineages: [], approved_lineages: [id], unused_permits: [] });
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({ lineage_id: id })))).toBe("revoked:issue/early");
    expect(snap(f, id).permit.state).toBe("none");
  });
});

describe("L4 single use", () => {
  it("[LC-L4a] sequential reuse: a second start on a consumed lineage is DENY permit_consumed", async () => {
    const f = fixture("l4a");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    await start(f, id);
    const second = await settle(start(f, id));
    witness(["LC-L4a-second", verdict(second), "permit_consumed"], ["LC-L4a-tool-calls", tool.calls, 1]);
  });

  it("[LC-L4b] concurrent: two start() under Promise.all: exactly one ALLOW, one permit_consumed", async () => {
    const f = fixture("l4b");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const results = await Promise.all([settle(start(f, id)), settle(start(f, id))]);
    witness(["LC-L4b-verdicts", results.map(verdict).sort(), ["ok", "permit_consumed"]], ["LC-L4b-tool-calls", tool.calls, 1]);
  });

  it("[LC-L4c] re-entrant start from the first start's tool_execution_started sink: inner ALLOW, outer permit_consumed", async () => {
    const f = fixture("l4c");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    let inner: Promise<Outcome<unknown>> | undefined;
    onAudit(f.ctx, "tool_execution_started", () => { inner = settle(start(f, id)); });
    const outer = await settle(start(f, id));
    witness(
      ["LC-L4c-inner", verdict(await inner!), "ok"],
      ["LC-L4c-outer", verdict(outer), "permit_consumed"],
      ["LC-L4c-tool-calls", tool.calls, 1],
    );
    expect(snap(f, id).permit.consumed_seq).toBeDefined();
  });

  it("[LC-L4d] re-entrant start from the provider callback, and from the tool body: one tool call", async () => {
    const f = fixture("l4d");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    let inner: Promise<Outcome<unknown>> | undefined;
    onNextResolve(f.ctx, () => { inner = settle(start(f, id)); });
    const outer = await settle(start(f, id));
    witness(["LC-L4d-provider", [verdict(await inner!), verdict(outer)], ["ok", "permit_consumed"]], ["LC-L4d-provider-calls", tool.calls, 1]);

    const g = fixture("l4d-tool");
    let fromTool: Promise<Outcome<unknown>> | undefined;
    const t2 = toolDouble("update_record", () => { fromTool = settle(start(g, gid)); return { status: "ok" }; });
    const gid = await issued(g);
    const first = await settle(start(g, gid));
    witness(["LC-L4d-tool", [verdict(first), verdict(await fromTool!)], ["ok", "permit_consumed"]], ["LC-L4d-tool-calls", t2.calls, 1]);
    expect(tool.calls).toBe(1);
  });
});

describe("L5 binding comparisons of the fresh start request R′", () => {
  it("[LC-L5-tool] R′ names another tool the chain allows: lineage_binding_mismatch:tool; the correct start follows", async () => {
    const f = fixture("l5t");
    const t1 = toolDouble("update_record");
    const t2 = toolDouble("read_record");
    const id = await issued(f);
    const wrong = await settle(start(f, id, { tool: "read_record" }));
    witness(["LC-L5-tool", verdict(wrong), "lineage_binding_mismatch:tool"], ["LC-L5-tool-state", snap(f, id).state, "issued"], ["LC-L5-tool-T2-calls", t2.calls, 0]);
    const right = await settle(start(f, id));
    witness(["LC-L5-tool-follow", verdict(right), "ok"], ["LC-L5-tool-T1-calls", t1.calls, 1]);
  });

  it("[LC-L5-arguments] R′ with { n: 2 } instead of { n: 1 }: lineage_binding_mismatch:arguments; the correct start follows", async () => {
    const f = fixture("l5a");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const wrong = await settle(start(f, id, { args: { n: 2 } }));
    witness(["LC-L5-arguments", verdict(wrong), "lineage_binding_mismatch:arguments"], ["LC-L5-arguments-state", snap(f, id).state, "issued"], ["LC-L5-arguments-calls", tool.calls, 0]);
    const right = await settle(start(f, id));
    witness(["LC-L5-arguments-follow", verdict(right), "ok"], ["LC-L5-arguments-args", tool.args, [{ n: 1 }]]);
  });

  it("[LC-L5-session] R′ in another session: (a) its own grant -> chain_snapshot_mismatch, (b) A's grant -> capability_session_mismatch", async () => {
    const f = fixture("l5s");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    serveChain(asTenancy(f.ctx), "s-l5s-2", chain(asTenancy(f.ctx), "s-l5s-2", [{ id: "l5s-2-L" }, { id: f.I }, { id: f.R }].slice(0, 1)));
    const a = await settle(start(f, id, { session: "s-l5s-2" }));
    serveChain(asTenancy(f.ctx), "s-l5s-2", f.env);
    const b = await settle(start(f, id, { session: "s-l5s-2" }));
    witness(["LC-L5-session", [verdict(a), verdict(b)], ["chain_snapshot_mismatch", "capability_session_mismatch"]], ["LC-L5-session-calls", tool.calls, 0]);
    expect(snap(f, id).state).toBe("issued");
  });

  it("[LC-L5-agent] R′ for another agent: (a) its own grant -> chain_snapshot_mismatch, (b) A's grant -> capability_agent_mismatch", async () => {
    const f = fixture("l5g");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const g2Leaf = signMember(asTenancy(f.ctx), { ...stripSignature(f.env.leaf), capability_id: "l5g-g2-L", agent_id: "agent-g2", parent: undefined });
    const answers = new Map<string, unknown>([["agent-g2", g2Leaf]]);
    const base = f.ctx.provider.answerFor!;
    f.ctx.provider.answerFor = context => answers.get(context.agent_id) ?? base(context);
    const a = await settle(start(f, id, { agent: "agent-g2" }));
    answers.delete("agent-g2");
    const b = await settle(start(f, id, { agent: "agent-g2" }));
    witness(["LC-L5-agent", [verdict(a), verdict(b)], ["chain_snapshot_mismatch", "capability_agent_mismatch"]], ["LC-L5-agent-calls", tool.calls, 0]);
  });

  it("[LC-L5-tenant] R′ claims tenant t2 over A's chain: tenant_mismatch (the claim check)", async () => {
    const f = fixture("l5n");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const o = await settle(start(f, id, { tenantId: "t2" }));
    witness(["LC-L5-tenant", verdict(o), "tenant_mismatch"], ["LC-L5-tenant-calls", tool.calls, 0]);
  });

  it("R′ re-using the original request_id is a replay; the permit stays issued", async () => {
    const f = fixture("l5r");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    const s = snap(f, id);
    const original = toolRequest(f.ctx, { id: "replay", session: f.session });
    expect(original.params.request_id).not.toBe(s.bindings.request_id);
    const replayed = { ...original, params: { ...original.params, request_id: s.bindings.request_id } };
    await expect(f.ctx.executor.start({ lineage_id: id, request: replayed })).rejects.toThrow();
    expect(snap(f, id).state).toBe("issued");
    expect(tool.calls).toBe(0);
  });
});

function stripSignature(grant: Grant): Grant {
  const { signature: _s, ...body } = grant;
  return body;
}

describe("L6 the provider's chain changes (snapshot comparison at approve, issue and start)", () => {
  /** (i) same ids, changed content; (ii) another valid authority B with fresh ids; (iii) a dropped ancestor. */
  function variant(f: Fixture, kind: "i" | "ii" | "iii"): ChainEnvelope {
    const t = asTenancy(f.ctx);
    if (kind === "i") return { ...f.env, leaf: signMember(t, { ...stripSignature(f.env.leaf), expires_at: fresh(f.ctx.clock.nowMs(), 250000) }) };
    if (kind === "ii") return chain(t, f.session, [{ id: `${f.L}-B` }, { id: `${f.I}-B` }, { id: `${f.R}-B` }]);
    return { ...f.env, ancestors: [f.env.ancestors[1]] };
  }
  const KINDS = ["i", "ii", "iii"] as const;

  it.each(KINDS)("[LC-L6-approve] (%s) DENY chain_snapshot_mismatch at approve; pending; no tool call", async kind => {
    const f = fixture(`l6a-${kind}`);
    const tool = toolDouble("update_record");
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    serveChain(asTenancy(f.ctx), f.session, variant(f, kind));
    const o = attempt(() => f.ctx.executor.approve(grant));
    witness(["LC-L6-approve", verdict(o), "chain_snapshot_mismatch"], ["LC-L6-approve-state", snap(f, id).state, "pending"], ["LC-L6-approve-calls", tool.calls, 0]);
  });

  it.each(KINDS)("[LC-L6-issue] (%s) DENY chain_snapshot_mismatch at issue; approved, permit none", async kind => {
    const f = fixture(`l6i-${kind}`);
    const id = await approved(f);
    serveChain(asTenancy(f.ctx), f.session, variant(f, kind));
    const o = attempt(() => f.ctx.executor.issuePermit({ lineage_id: id }));
    witness(["LC-L6-issue", verdict(o), "chain_snapshot_mismatch"], ["LC-L6-issue-state", snap(f, id).state, "approved"]);
  });

  it.each(KINDS)("[LC-L6-start] (%s) DENY chain_snapshot_mismatch at start; permit issued; no tool call", async kind => {
    const f = fixture(`l6s-${kind}`);
    const tool = toolDouble("update_record");
    const id = await issued(f);
    serveChain(asTenancy(f.ctx), f.session, variant(f, kind));
    const o = await settle(start(f, id));
    witness(
      ["LC-L6-start", verdict(o), "chain_snapshot_mismatch"],
      ["LC-L6-start-state", snap(f, id).state, "issued"],
      ["LC-L6-start-calls", tool.calls, 0],
      // The authority a started execution would be bound to (none in the control): always the lineage's chain A.
      ["LC-L6-start-execution-capability", f.ctx.executor.getExecution("exec-1")?.capability_id, undefined],
    );
  });

  it("a single grant without ancestors is compared too: a re-issued grant for the same context is another authority", async () => {
    const ctx = setupLifecycle();
    const f: Fixture = { ctx, env: undefined as unknown as ChainEnvelope, session: "s-l6-single", L: "", I: "", R: "" };
    const leaf = chain(asTenancy(ctx), f.session, [{ id: "single-A" }]).leaf;
    serveChain(asTenancy(ctx), f.session, leaf);
    const id = await approved(f);
    serveChain(asTenancy(ctx), f.session, chain(asTenancy(ctx), f.session, [{ id: "single-A2" }]).leaf);
    expect(verdict(attempt(() => ctx.executor.issuePermit({ lineage_id: id })))).toBe("chain_snapshot_mismatch");
  });
});

describe("L7 revocation inside the last callback before an effective point", () => {
  it("[LC-L7a] revoke inside the provider callback of issuePermit: DENY revoked (issue, final); permit none", async () => {
    const f = fixture("l7a");
    const id = await approved(f);
    onNextResolve(f.ctx, () => f.ctx.executor.revoke({ scope: "capability", capability_id: f.L }));
    const o = attempt(() => f.ctx.executor.issuePermit({ lineage_id: id }));
    witness(["LC-L7a-issue", verdict(o), "revoked:issue/final"], ["LC-L7a-permit", snap(f, id).permit.state, "none"]);
  });

  it("[LC-L7b] revoke inside the tool_execution_started sink: DENY revoked (start, final); permit issued; no tool call", async () => {
    const f = fixture("l7b");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    onAudit(f.ctx, "tool_execution_started", () => f.ctx.executor.revoke({ scope: "capability", capability_id: f.L }));
    const o = await settle(start(f, id));
    witness(["LC-L7b-start", verdict(o), "revoked:start/final"], ["LC-L7b-permit", snap(f, id).permit.state, "issued"], ["LC-L7b-tool-calls", tool.calls, 0]);
  });

  it("[LC-L7c] revoke inside the permit_issued sink (after the transition): the permit stays issued; the next start DENY", async () => {
    const f = fixture("l7c");
    const tool = toolDouble("update_record");
    const id = await approved(f);
    let receipt: ReturnType<typeof f.ctx.executor.revoke> | undefined;
    onAudit(f.ctx, "permit_issued", () => { receipt = f.ctx.executor.revoke({ scope: "capability", capability_id: f.L }); });
    const p = f.ctx.executor.issuePermit({ lineage_id: id });
    const o = await settle(start(f, id));
    witness(["LC-L7c-permit", snap(f, id).permit.state, "issued"], ["LC-L7c-start-denied", o.ok, false], ["LC-L7c-tool-calls", tool.calls, 0]);
    expect(p.issued_seq).toBeLessThan(receipt!.effective_sequence);
    expect(receipt!.unused_permits).toEqual([id]);
  });
});

describe("L8 approval never restores authority", () => {
  it("[LC-L8] revoke, then a valid V3 approval: DENY; a new process() for the same authority is DENY at request", async () => {
    const f = fixture("l8");
    const id = await pending(f);
    f.ctx.executor.revoke({ scope: "capability", capability_id: f.L });
    const a = attempt(() => approve(f, id));
    const again = await settle(f.ctx.executor.process(req(f)));
    witness(["LC-L8", [verdict(a), verdict(again)], ["revoked:approval/early", "revoked:request"]], ["LC-L8-state", snap(f, id).state, "pending"]);
    expect(f.ctx.executor.lineages()).toHaveLength(1);
  });
});

describe("L9 expiry", () => {
  it("[LC-L9-approval] approve after approval_expires_at: DENY approval_expired; state recorded; no tool call", async () => {
    const f = fixture("l9a", {}, 3_600_000);
    const tool = toolDouble("update_record");
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    f.ctx.clock.currentMs = Date.parse(snap(f, id).approval.expires_at);
    const o = attempt(() => f.ctx.executor.approve(grant));
    witness(["LC-L9-approval", verdict(o), "approval_expired"], ["LC-L9-approval-state", snap(f, id).state, "approval_expired"], ["LC-L9-approval-calls", tool.calls, 0]);
    expect(verdict(attempt(() => f.ctx.executor.approve(grant)))).toBe("not_pending");
  });

  it("[LC-L9-issue] issue after approval_expires_at: DENY approval_expired; recorded", async () => {
    const f = fixture("l9i", {}, 3_600_000);
    const id = await approved(f);
    f.ctx.clock.currentMs = Date.parse(snap(f, id).approval.expires_at) + 1;
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({ lineage_id: id })))).toBe("approval_expired");
    expect(snap(f, id).state).toBe("approval_expired");
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({ lineage_id: id })))).toBe("not_approved");
  });

  it("[LC-L9-permit] start after permit_expires_at (inside every chain window): DENY permit_expired; recorded; no tool call", async () => {
    const f = fixture("l9p", { permitTtlMs: 10_000 }, 3_600_000);
    const tool = toolDouble("update_record");
    const id = await issued(f);
    expect(Date.parse(snap(f, id).permit.expires_at!)).toBe(f.ctx.clock.nowMs() + 10_000);
    f.ctx.clock.currentMs += 10_000;
    const o = await settle(start(f, id));
    witness(["LC-L9-permit", verdict(o), "permit_expired"], ["LC-L9-permit-state", snap(f, id).state, "permit_expired"], ["LC-L9-permit-calls", tool.calls, 0]);
    expect(verdict(await settle(start(f, id)))).toBe("permit_expired");
  });

  it("D16 the permit lifetime is capped by the end of the chain's validity window", async () => {
    const f = fixture("d16", { permitTtlMs: 600_000 });
    const id = await issued(f);
    expect(snap(f, id).permit.expires_at).toBe(f.env.leaf.expires_at);
  });
});

describe("L10 reject", () => {
  it("[LC-L10] reject, then approve, issue, start: not_pending, not_approved, permit_not_issued", async () => {
    const f = fixture("l10");
    const tool = toolDouble("update_record");
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    const rejection = f.ctx.executor.reject(approvalV3(f.ctx, snap(f, id), { decision: "reject" }));
    expect(rejection).toEqual({ lineage_id: id, decision: "rejected", approver: { type: "human", id: "demo-operator" }, audit_recorded: true });
    const a = attempt(() => f.ctx.executor.approve(grant));
    const i = attempt(() => f.ctx.executor.issuePermit({ lineage_id: id }));
    const s = await settle(start(f, id));
    witness(["LC-L10", [verdict(a), verdict(i), verdict(s)], ["not_pending", "not_approved", "permit_not_issued"]], ["LC-L10-state", snap(f, id).state, "rejected"], ["LC-L10-calls", tool.calls, 0]);
  });

  it("a reject of a revoked lineage is allowed (a reject only removes authority)", async () => {
    const f = fixture("l10r");
    const id = await pending(f);
    f.ctx.executor.revoke({ scope: "session", session_id: sessionUuid(f.session) });
    f.ctx.executor.reject(approvalV3(f.ctx, snap(f, id), { decision: "reject" }));
    expect(snap(f, id).state).toBe("rejected");
  });
});

describe("L11 a failed start after the effective point", () => {
  it("[LC-L11] the tool throws: permit consumed; execution terminal failed; a second start DENY permit_consumed", async () => {
    const f = fixture("l11");
    const tool = toolDouble("update_record", () => { throw new Error("tool failure"); });
    const id = await issued(f);
    const first = await settle(start(f, id));
    const terminal = await f.ctx.executor.whenTerminal("exec-1");
    const second = await settle(start(f, id));
    witness(
      ["LC-L11-first", first.ok && first.value.result.exit_status, "failure"],
      ["LC-L11-permit", snap(f, id).permit.state, "consumed"],
      ["LC-L11-terminal", terminal.outcome, "failed"],
      ["LC-L11-second", verdict(second), "permit_consumed"],
      ["LC-L11-tool-calls", tool.calls, 1],
    );
  });

  it("[LC-L11-before] B10: an audit sink throwing before the effective point is a denial; the permit stays issued and usable", async () => {
    const f = fixture("l11b");
    const tool = toolDouble("update_record");
    const id = await issued(f);
    onAudit(f.ctx, "tool_execution_started", () => { throw new Error("sink down"); });
    const first = await settle(start(f, id));
    jest.restoreAllMocks();
    const second = await settle(start(f, id));
    witness(["LC-L11b", [verdict(first), verdict(second)], ["error:sink down", "ok"]], ["LC-L11b-tool-calls", tool.calls, 1]);
  });
});

describe("L11-unobservable: the existing terminal-evidence contract holds for a lineage start", () => {
  it("a tool whose returned Promise cannot be observed: the start fails without a terminal; the permit stays consumed", async () => {
    const f = fixture("l11u");
    const id = await issued(f);
    let hiddenCtx: { execution_id: string } | undefined;
    const hidden = new Promise<unknown>(() => undefined);
    Object.defineProperty(hidden, "constructor", { get: () => { throw new Error("constructor getter must not run"); } });
    tools.update_record = (_args, ctx) => { hiddenCtx = ctx; return hidden; };
    const o = await settle(start(f, id));
    expect(o.ok && o.value.result.exit_status).toBe("failure");
    expect(f.ctx.executor.getExecution(hiddenCtx!.execution_id)!.state).toBe("unobservable");
    expect(f.ctx.executor.terminals()).toEqual([]);
    expect(snap(f, id).permit).toMatchObject({ state: "consumed", execution_id: hiddenCtx!.execution_id });
    expect(verdict(await settle(start(f, id)))).toBe("permit_consumed");
  });
});

describe("L12 modes", () => {
  it("[LC-L12] permit mode rejects resolveApproval(); legacy mode rejects every lifecycle method", async () => {
    const f = fixture("l12");
    await expect(f.ctx.executor.resolveApproval({})).rejects.toBeInstanceOf(LifecycleModeError);
    const legacy = setupTenancy();
    expect(legacy.executor.lifecycleMode).toBe("legacy");
    expect(() => legacy.executor.approve({})).toThrow(LifecycleModeError);
    expect(() => legacy.executor.reject({})).toThrow(LifecycleModeError);
    expect(() => legacy.executor.issuePermit({ lineage_id: "x" })).toThrow(LifecycleModeError);
    expect(() => legacy.executor.getLineage("x")).toThrow(LifecycleModeError);
    expect(() => legacy.executor.lineages()).toThrow(LifecycleModeError);
    await expect(legacy.executor.start({ lineage_id: "x" })).rejects.toBeInstanceOf(LifecycleModeError);
    // Legacy behaviour is unchanged: ASK gives { status: "pending" } and the receipt has no lifecycle lists.
    const pendingResult = await legacy.executor.process(tenantRequest({ requestId: "l12-legacy", sessionId: "s-l12-legacy", tool: "update_record" }, legacy.clock));
    expect(pendingResult).toEqual({ status: "pending" });
    const receipt = legacy.executor.revoke({ scope: "session", session_id: sessionUuid("s-l12-legacy") });
    expect(Object.keys(receipt)).not.toContain("pending_lineages");
    expect(receipt.enforced_at).toEqual(["request", "approval", "start", "delivery"]);
  });

  it("permit mode requires an ApprovalGrantV3: a V2 grant is approval_verification_failed and changes nothing", async () => {
    const f = fixture("l12v2");
    const id = await pending(f);
    const s = snap(f, id);
    const v2 = f.ctx.testSigner.sign({ version: 2, decision: "approve", session_id: s.bindings.session_id, request_id: s.bindings.request_id, tool: s.bindings.tool, approver: { type: "human", id: "demo-operator" }, issued_at: fresh(f.ctx.clock.nowMs()) });
    expect(verdict(attempt(() => f.ctx.executor.approve({ ...v2, lineage_id: id })))).toBe("approval_verification_failed");
    expect(snap(f, id).state).toBe("pending");
  });
});

describe("approval grant verification (T7, B3)", () => {
  it.each([
    ["request_digest", { request_digest: "0".repeat(64) }, "request_digest_mismatch"],
    ["authority_fingerprint", { authority_fingerprint: "0".repeat(64) }, "authority_fingerprint_mismatch"],
    ["request_id", { request_id: "other" }, "request_mismatch"],
    ["tool", { tool: "read_record" }, "tool_binding_mismatch"],
    ["approver", { approver: { type: "human", id: "someone-else" } }, "wrong_approver_identity"],
    ["decision", { decision: "reject" }, "decision_mismatch"],
  ])("a grant with a wrong %s is DENY approval_verification_failed (%s) with no state change", async (_field, overrides, sub) => {
    const f = fixture(`gv-${_field}`);
    const id = await pending(f);
    const o = attempt(() => approve(f, id, overrides));
    expect(verdict(o)).toBe("approval_verification_failed");
    expect(!o.ok && (o.error as LifecycleDeniedError).detail?.sub_reason).toBe(sub);
    expect(snap(f, id).state).toBe("pending");
  });

  it("a grant for one lineage cannot be replayed on another", async () => {
    const f = fixture("gv-replay");
    const one = await pending(f);
    const two = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, one));
    expect(verdict(attempt(() => f.ctx.executor.approve({ ...grant, lineage_id: two })))).toBe("approval_verification_failed");
    expect(snap(f, two).state).toBe("pending");
  });

  it("[LC-B3] a re-entrant approve from the provider callback of an outer approve: inner approves, outer not_pending, one approved_seq", async () => {
    const f = fixture("b3");
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    let inner: Outcome<unknown> | undefined;
    onNextResolve(f.ctx, () => { inner = attempt(() => f.ctx.executor.approve(grant)); });
    const outer = attempt(() => f.ctx.executor.approve(grant));
    witness(["LC-B3", [verdict(inner!), verdict(outer)], ["ok", "not_pending"]], ["LC-B3-seq", snap(f, id).approval.approved_seq, 2]);
  });

  it("T22 unknown lineage_id and malformed calls are typed denials", async () => {
    const f = fixture("t22");
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({ lineage_id: "lineage-404" })))).toBe("unknown_lineage");
    expect(verdict(await settle(f.ctx.executor.start({ lineage_id: "lineage-404", request: {} })))).toBe("unknown_lineage");
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({})))).toBe("malformed_lifecycle_call");
    expect(verdict(attempt(() => f.ctx.executor.approve({ version: 3 })))).toBe("malformed_lifecycle_call");
  });
});

describe("L13 audit claims never replace a transition", () => {
  it("[LC-L13] fake permit_issued / tool_execution_started events change no lineage state and call no tool", async () => {
    const f = fixture("l13");
    const tool = toolDouble("update_record");
    const id = await approved(f);
    f.ctx.audit.record(snap(f, id).bindings.request_id, "permit_issued", { lineage_id: id, permit_id: "permit-forged", issued_seq: 99 });
    f.ctx.audit.record(snap(f, id).bindings.request_id, "tool_execution_started");
    witness(["LC-L13-state", snap(f, id).state, "approved"], ["LC-L13-permit", snap(f, id).permit, { state: "none" }], ["LC-L13-calls", tool.calls, 0]);
    expect(verdict(await settle(start(f, id)))).toBe("permit_not_issued");
  });

  it("[LC-L13-throw] an audit sink that throws after a transition leaves it in place; the receipt reports the missing evidence", async () => {
    const f = fixture("l13t");
    const id = await pending(f);
    onAudit(f.ctx, "approval_granted", () => { throw new Error("sink down"); });
    const receipt = approve(f, id);
    expect(receipt.audit_recorded).toBe(false);
    expect(snap(f, id).state).toBe("approved");
  });
});

describe("L14 aliasing and input mutation", () => {
  it("[LC-L14] a Guardian that mutates the request, a sink that mutates its metadata and a caller that mutates snapshots change nothing", async () => {
    const f = fixture("l14");
    const tool = toolDouble("update_record");
    const evaluate = Guardian.prototype.evaluate;
    let guardianWrite = "not attempted";
    jest.spyOn(f.ctx.guardian, "evaluate").mockImplementation(function (this: Guardian, request) {
      const decision = evaluate.call(this, request);
      // The Guardian is handed the runtime-owned frozen snapshot: the write is rejected and changes nothing.
      try { (request.params.payload.arguments as Record<string, unknown>).n = { value: 666 }; guardianWrite = "applied"; } catch (e) { guardianWrite = e instanceof TypeError ? "rejected" : "error"; }
      return decision;
    });
    onAudit(f.ctx, "capability_verified", meta => { if (meta) (meta as Record<string, unknown>).capability_id = "forged"; });
    const id = await pending(f);
    const s = snap(f, id);
    expect(() => { (s.bindings as { tool: string }).tool = "read_record"; }).toThrow(TypeError);
    expect(() => { (s.permit as { state: string }).state = "issued"; }).toThrow(TypeError);
    jest.restoreAllMocks();
    approve(f, id);
    f.ctx.executor.issuePermit({ lineage_id: id });
    // R′ through a getter that answers differently on a second read: read once at entry.
    const good = req(f);
    const evil = req(f, { args: { n: 2 } });
    let reads = 0;
    const input = { lineage_id: id, get request() { reads++; return reads === 1 ? good : evil; } };
    const started = f.ctx.executor.start(input);
    (good.params.payload.arguments as Record<string, unknown>).n = { value: 3 };
    const o = await settle(started);
    witness(
      ["LC-L14-digest", snap(f, id).bindings.arguments_digest, argumentsDigest({ n: { value: 1 } })],
      ["LC-L14-capability", snap(f, id).bindings.capability_id, f.L],
      ["LC-L14-start", verdict(o), "ok"],
      ["LC-L14-tool-args", tool.args, [{ n: 1 }]],
      ["LC-L14-reads", reads, 1],
      ["LC-L14-guardian-write", guardianWrite, "rejected"],
    );
  });
});

describe("L17 the request process() evaluates is runtime-owned (no approval bypass by mutation)", () => {
  /**
   * The caller keeps a reference to the signed update_record request and rewrites its tool to read_record from a
   * callback before the Guardian decides. Without a runtime-owned snapshot the Guardian sees read_record (ALLOW) while
   * the lineage binds update_record, so the update would get a policy approval and run without a human. The fixed path
   * keeps the original ASK (pending lineage) or rejects the mutation attempt; it never creates an approved update
   * lineage, and issue + start never call the update tool.
   */
  const SITES = ["control", "capability_verified", "provider", "guardian"] as const;
  const EXPECTED: Record<typeof SITES[number], [string, string, number]> = {
    control: ["ok", "pending", 0],
    capability_verified: ["ok", "pending", 0],
    provider: ["ok", "pending", 0],
    // The Guardian receives the frozen snapshot: its write attempt throws, process() is denied, no lineage.
    guardian: ["error", "none", 0],
  };

  it.each(SITES)("[LC-L17] %s: no policy-approved update lineage and no update call", async site => {
    const f = fixture(`l17-${site}`);
    const update = toolDouble("update_record");
    const read = toolDouble("read_record");
    const r = req(f);
    const rewrite = (target: AcsToolCallRequest) => { (target.params.payload.tool as { name: string }).name = "read_record"; };
    if (site === "capability_verified") onAudit(f.ctx, "capability_verified", () => rewrite(r));
    if (site === "provider") onNextResolve(f.ctx, () => rewrite(r));
    if (site === "guardian") {
      const evaluate = Guardian.prototype.evaluate;
      jest.spyOn(f.ctx.guardian, "evaluate").mockImplementation(function (this: Guardian, request) { rewrite(request); return evaluate.call(this, request); });
    }
    const created = await settle(f.ctx.executor.process(r));
    jest.restoreAllMocks();
    const lineage = f.ctx.executor.lineages()[0];
    if (lineage?.state === "approved") {
      attempt(() => f.ctx.executor.issuePermit({ lineage_id: lineage.lineage_id }));
      await settle(start(f, lineage.lineage_id));
    }
    witness([`LC-L17-${site}`, [created.ok ? "ok" : "error", lineage?.state ?? "none", update.calls], EXPECTED[site]]);
    if (site === "guardian") expect(!created.ok && created.error).toBeInstanceOf(TypeError);
    expect(read.calls).toBe(0);
    if (lineage) expect(lineage.bindings.tool).toBe("update_record");
  });
});

describe("L15 the creation fence after the last callbacks of process()", () => {
  const SITES = ["capability_verified", "guardian", "guardian_decision"] as const;
  const cases = SITES.flatMap(site => SCOPES.map(scope => [site, scope] as const));

  it.each(cases)("[LC-L15] revoke inside %s, %s scope: process DENY revoked (request, final); no lineage; no approval_requested", async (site, scope) => {
    const f = fixture(`l15-${site}-${scope}`);
    const tool = toolDouble("update_record");
    const revoke = () => f.ctx.executor.revoke(targetFor(f, scope));
    if (site === "guardian") {
      const evaluate = Guardian.prototype.evaluate;
      jest.spyOn(f.ctx.guardian, "evaluate").mockImplementation(function (this: Guardian, request) { revoke(); return evaluate.call(this, request); });
    } else {
      onAudit(f.ctx, site, revoke);
    }
    const o = await settle(f.ctx.executor.process(req(f)));
    witness(
      ["LC-L15-process", verdict(o), "revoked:request/final"],
      ["LC-L15-lineages", f.ctx.executor.lineages().length, 0],
      ["LC-L15-tool-calls", tool.calls, 0],
    );
    expect(f.ctx.audit.getEvents().filter(e => e.event_type === "approval_requested")).toEqual([]);
    expect(verdict(attempt(() => f.ctx.executor.issuePermit({ lineage_id: "lineage-1" })))).toBe("unknown_lineage");
  });
});

describe("L16 chain validity after the last callback", () => {
  const LEAF_TTL = 50_000;

  it("[LC-L16-create] the leaf expires inside the guardian_decision sink: DENY capability_expired at F(create); no lineage", async () => {
    const f = fixture("l16c", {}, LEAF_TTL);
    onAudit(f.ctx, "guardian_decision", () => { f.ctx.clock.currentMs = Date.parse(f.env.leaf.expires_at as string) + 1; });
    const o = await settle(f.ctx.executor.process(req(f)));
    witness(["LC-L16-create", verdict(o), "capability_expired"], ["LC-L16-create-lineages", f.ctx.executor.lineages().length, 0]);
  });

  it("[LC-L16-approve] the leaf expires inside the provider callback of approve: DENY capability_expired; pending", async () => {
    const f = fixture("l16a", {}, LEAF_TTL);
    const id = await pending(f);
    const grant = approvalV3(f.ctx, snap(f, id));
    onNextResolve(f.ctx, () => { f.ctx.clock.currentMs = Date.parse(f.env.leaf.expires_at as string) + 1; });
    const o = attempt(() => f.ctx.executor.approve(grant));
    witness(["LC-L16-approve", verdict(o), "capability_expired"], ["LC-L16-approve-state", snap(f, id).state, "pending"]);
  });

  it("[LC-L16-issue] the leaf expires inside the provider callback of issuePermit: DENY capability_expired; permit none", async () => {
    const f = fixture("l16i", {}, LEAF_TTL);
    const id = await approved(f);
    onNextResolve(f.ctx, () => { f.ctx.clock.currentMs = Date.parse(f.env.leaf.expires_at as string) + 1; });
    const o = attempt(() => f.ctx.executor.issuePermit({ lineage_id: id }));
    witness(["LC-L16-issue", verdict(o), "capability_expired"], ["LC-L16-issue-permit", snap(f, id).permit.state, "none"]);
  });

  it("[LC-L16-start] the leaf expires inside the tool_execution_started sink: DENY capability_expired at F(start); permit issued; no tool call", async () => {
    const f = fixture("l16s", {}, LEAF_TTL);
    const tool = toolDouble("update_record");
    const id = await issued(f);
    expect(snap(f, id).permit.expires_at).toBe(f.env.leaf.expires_at);
    onAudit(f.ctx, "tool_execution_started", () => { f.ctx.clock.currentMs = Date.parse(f.env.leaf.expires_at as string) + 1; });
    const o = await settle(start(f, id));
    witness(["LC-L16-start", verdict(o), "capability_expired"], ["LC-L16-start-permit", snap(f, id).permit.state, "issued"], ["LC-L16-start-calls", tool.calls, 0]);
  });
});

describe("execution containment after a lineage start (existing contracts)", () => {
  it("a revocation while the tool runs: cancellation requested, delivery withheld, permit stays consumed", async () => {
    const f = fixture("cont");
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const tool = toolDouble("update_record", async () => { await gate; return { secret: "lineage-output" }; });
    const id = await issued(f);
    const running = settle(start(f, id));
    await Promise.resolve();
    const receipt = f.ctx.executor.revoke({ scope: "capability", capability_id: f.I });
    expect(receipt.in_flight_executions).toHaveLength(1);
    expect(receipt.unused_permits).toEqual([]);
    expect(tool.ctx[0].cancellation.requested).toBe(true);
    release();
    const o = await running;
    expect(o.ok && JSON.stringify(o.value.result)).not.toContain("lineage-output");
    expect(o.ok && o.value.result.exit_status).toBe("blocked");
    expect(snap(f, id).state).toBe("consumed");
  });
});
