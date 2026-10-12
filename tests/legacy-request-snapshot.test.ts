/**
 * Legacy mode: the request that was verified is the request that runs (docs/legacy-request-snapshot.md).
 *
 * A caller signs a request and keeps a reference to the object it passed to process(). A callback that runs after the
 * signature, replay and capability checks — the capability provider, the capability_verified audit sink, or the
 * Guardian, which is handed the request itself — then rewrites the tool, an argument, the session or the request id.
 * The tool, its arguments, the session and the request id must stay those that were verified, up to the start
 * effective point (the tool call), on both legacy paths:
 *   - process() with a Guardian ALLOW (read_record): the tool runs directly;
 *   - process() with a Guardian ASK (update_record), then resolveApproval(): the pending action holds the verified
 *     request, the human approves exactly that request, and exactly that request runs.
 *
 * Rewriting the caller's object has no effect on the executor. The Guardian is handed the runtime's frozen copy, so its
 * write attempt throws and process() is rejected before anything runs or is pending.
 * Tool calls are observed through the tool doubles' own counters and arguments, never through the audit.
 */
import { tools } from "../src/tools";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import type { AcsToolCallRequest, AuditEventType } from "../src/acs-types";
import { fresh, testSignatureService, toUuid } from "./evals/eval-setup";
import { setupTenancy, TenancyCtx } from "./tenant-setup";

const original = { ...tools };
afterEach(() => { Object.assign(tools, original); jest.restoreAllMocks(); });

type Field = "tool" | "arguments" | "session" | "request_id";
type Site = "provider" | "capability_verified" | "guardian";
const FIELDS: Field[] = ["tool", "arguments", "session", "request_id"];
const CALLER_SITES: Site[] = ["provider", "capability_verified"];

/** A signed legacy request with one argument, { id: "r-1" }. */
function signedRequest(ctx: TenancyCtx, name: string, tool: string): AcsToolCallRequest {
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: `rpc-${name}`,
    params: {
      acs_version: "0.1.0",
      request_id: toUuid(`req-${name}`),
      timestamp: fresh(ctx.clock.nowMs()),
      metadata: { agent_id: "agent-test", session_id: toUuid(`s-${name}`) },
      payload: { tool: { name: tool }, arguments: { id: { value: "r-1" } } },
    },
  };
  return testSignatureService.signRequest(req) as AcsToolCallRequest;
}

/** Tool doubles that count their own calls and record their arguments. */
function toolDoubles() {
  const seen = { read_record: [] as unknown[], update_record: [] as unknown[] };
  tools.read_record = async (args: Record<string, unknown>) => { seen.read_record.push({ ...args }); return { ok: "read" }; };
  tools.update_record = async (args: Record<string, unknown>) => { seen.update_record.push({ ...args }); return { ok: "update" }; };
  return seen;
}

/** Rewrites one field of a request object after its checks; the other tool is the one the policy treats differently. */
function rewrite(target: AcsToolCallRequest, field: Field): void {
  const p = target.params;
  if (field === "tool") (p.payload.tool as { name: string }).name = p.payload.tool.name === "read_record" ? "update_record" : "read_record";
  if (field === "arguments") (p.payload.arguments.id as { value: unknown }).value = "r-2";
  if (field === "session") (p.metadata as { session_id: string }).session_id = toUuid("s-rewritten");
  if (field === "request_id") (p as { request_id: string }).request_id = toUuid("req-rewritten");
}

/** Installs the rewrite at a callback site. provider and capability_verified rewrite the caller's object. */
function rewriteAt(ctx: TenancyCtx, site: Site, field: Field, callerObject: AcsToolCallRequest): void {
  if (site === "provider") {
    const resolve = ctx.provider.resolve.bind(ctx.provider);
    jest.spyOn(ctx.provider, "resolve").mockImplementation(c => { const answer = resolve(c); rewrite(callerObject, field); return answer; });
  }
  if (site === "capability_verified") {
    const record = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, m?: Record<string, unknown>) {
      record.call(this, id, t, m);
      if (t === "capability_verified") rewrite(callerObject, field);
    });
  }
  if (site === "guardian") {
    const evaluate = Guardian.prototype.evaluate;
    jest.spyOn(Guardian.prototype, "evaluate").mockImplementation(function (this: Guardian, req) { rewrite(req, field); return evaluate.call(this, req); });
  }
}

const events = (ctx: TenancyCtx, type: string) => ctx.audit.getEvents().filter(e => e.event_type === type);
const approvalFor = (ctx: TenancyCtx, signed: { tool: string; session_id: string; request_id: string }) => ctx.testSigner.sign({
  version: 2, tool: signed.tool, decision: "approve", session_id: signed.session_id, request_id: signed.request_id,
  approver: { type: "human", id: "demo-operator" }, issued_at: fresh(ctx.clock.nowMs()),
});
const signedValues = (r: AcsToolCallRequest) => ({ tool: r.params.payload.tool.name, session_id: r.params.metadata.session_id, request_id: r.params.request_id });

describe("LS1 process(), Guardian ALLOW: the verified request runs", () => {
  describe.each(CALLER_SITES)("a rewrite of the caller's object in the %s callback", site => {
    it.each(FIELDS)("%s: read_record runs once with the signed arguments, session and request id", async field => {
      const ctx = setupTenancy();
      const seen = toolDoubles();
      const r = signedRequest(ctx, `ls1-${site}-${field}`, "read_record");
      const signed = signedValues(r);
      rewriteAt(ctx, site, field, r);
      const out = await ctx.executor.process(r);
      expect(out.status).toBe("executed");
      expect(seen).toEqual({ read_record: [{ id: "r-1" }], update_record: [] });
      expect(ctx.executor.getExecution("exec-1")).toMatchObject({ request_id: signed.request_id, session_id: signed.session_id });
      expect(events(ctx, "tool_execution_started").map(e => e.request_id)).toEqual([signed.request_id]);
      expect(events(ctx, "approval_requested")).toHaveLength(0);
    });
  });

  it.each(FIELDS)("a Guardian that rewrites the request it is handed (%s): process() is rejected, nothing runs", async field => {
    const ctx = setupTenancy();
    const seen = toolDoubles();
    const r = signedRequest(ctx, `ls1-guardian-${field}`, "read_record");
    rewriteAt(ctx, "guardian", field, r);
    await expect(ctx.executor.process(r)).rejects.toThrow(TypeError);
    expect(seen).toEqual({ read_record: [], update_record: [] });
    expect(events(ctx, "tool_execution_started")).toHaveLength(0);
    expect(events(ctx, "approval_requested")).toHaveLength(0);
  });
});

describe("LS2 process() with Guardian ASK, then resolveApproval(): the verified request is pending, approved and run", () => {
  describe.each(CALLER_SITES)("a rewrite of the caller's object in the %s callback", site => {
    it.each(FIELDS)("%s: the signed update_record is pending; approving it runs it once with the signed arguments", async field => {
      const ctx = setupTenancy();
      const seen = toolDoubles();
      const r = signedRequest(ctx, `ls2-${site}-${field}`, "update_record");
      const signed = signedValues(r);
      rewriteAt(ctx, site, field, r);
      const out = await ctx.executor.process(r);
      expect(out.status).toBe("pending");
      expect(seen).toEqual({ read_record: [], update_record: [] });
      expect(events(ctx, "approval_requested").map(e => [e.request_id, e.metadata?.session_id])).toEqual([[signed.request_id, signed.session_id]]);
      jest.restoreAllMocks();
      await ctx.executor.resolveApproval(approvalFor(ctx, signed));
      expect(seen).toEqual({ read_record: [], update_record: [{ id: "r-1" }] });
      expect(ctx.executor.getExecution("exec-1")).toMatchObject({ request_id: signed.request_id, session_id: signed.session_id });
      expect(events(ctx, "tool_execution_started").map(e => e.request_id)).toEqual([signed.request_id]);
    });
  });

  it.each(FIELDS)("a Guardian that rewrites the request it is handed (%s): process() is rejected, nothing is pending", async field => {
    const ctx = setupTenancy();
    const seen = toolDoubles();
    const r = signedRequest(ctx, `ls2-guardian-${field}`, "update_record");
    const signed = signedValues(r);
    rewriteAt(ctx, "guardian", field, r);
    await expect(ctx.executor.process(r)).rejects.toThrow(TypeError);
    jest.restoreAllMocks();
    expect(events(ctx, "approval_requested")).toHaveLength(0);
    await expect(ctx.executor.resolveApproval(approvalFor(ctx, signed))).rejects.toThrow(/No pending action/);
    expect(seen).toEqual({ read_record: [], update_record: [] });
  });

  it.each(FIELDS)("control: a rewrite of the caller's object after process() returned pending (%s) changes nothing", async field => {
    const ctx = setupTenancy();
    const seen = toolDoubles();
    const r = signedRequest(ctx, `ls2-after-${field}`, "update_record");
    const signed = signedValues(r);
    expect((await ctx.executor.process(r)).status).toBe("pending");
    rewrite(r, field);
    await ctx.executor.resolveApproval(approvalFor(ctx, signed));
    expect(seen).toEqual({ read_record: [], update_record: [{ id: "r-1" }] });
    expect(ctx.executor.getExecution("exec-1")).toMatchObject({ request_id: signed.request_id, session_id: signed.session_id });
  });
});
