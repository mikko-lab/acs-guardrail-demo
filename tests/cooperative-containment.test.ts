/**
 * A2 cooperative containment corpus. Tool doubles are harness-owned and driven by latches and explicit events:
 * they never decide or block anything. Commits are observed through the runtime-managed state itself
 * (executor.managedState), tool behaviour through the doubles' own logs; audit events are decision evidence only.
 */
import { setup, makeRequest, fresh } from "./evals/eval-setup";
import { tools } from "../src/tools";
import { AuditCollector } from "../src/audit";
import { AuthorityRevokedError } from "../src/guarded-executor";
import { CancellationError, CommitRejectedError, ExecutionContext, ManagedExecution, ManagedStateStore } from "../src/managed-execution";
import type { AuditEvent, AuditEventType } from "../src/acs-types";
import { spawnSync } from "child_process";
import path from "path";

type Ctx = ReturnType<typeof setup>;
type Deferred<T = void> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void };
function deferred<T = void>(): Deferred<T> {
  let resolve!: (v: T) => void, reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

const original = { ...tools };
afterEach(() => { for (const k of Object.keys(tools)) delete tools[k]; Object.assign(tools, original); });

const sessionOf = (req: ReturnType<typeof makeRequest>) => req.params.metadata.session_id;
const eventsOf = (ctx: Ctx, type: AuditEventType) => ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === type);
const capabilityOf = (ctx: Ctx, requestId: string) =>
  ctx.audit.getEvents().find((e: AuditEvent) => e.event_type === "capability_verified" && e.request_id === requestId)!.metadata!.capability_id as string;
const approve = (ctx: Ctx, req: ReturnType<typeof makeRequest>) => ctx.testSigner.sign({
  version: 2, tool: req.params.payload.tool.name, decision: "approve", session_id: req.params.metadata.session_id,
  request_id: req.params.request_id, approver: { type: "human", id: "demo-operator" }, issued_at: fresh(ctx.clock.nowMs()),
});

/**
 * A scripted cooperative tool double. `steps` runs inside the tool with its context; the harness drives it
 * through the returned latches. Everything it observes is pushed to `log`.
 */
function scriptedTool(name: string, steps: (ctx: ExecutionContext, h: Harness) => Promise<unknown>) {
  const h: Harness = { log: [], started: deferred(), ctx: undefined as unknown as ExecutionContext, calls: 0 };
  tools[name] = async (_args, ctx) => {
    h.calls++; h.ctx = ctx!; h.log.push("start"); h.started.resolve();
    return steps(ctx!, h);
  };
  return h;
}
interface Harness { log: string[]; started: Deferred; ctx: ExecutionContext; calls: number }
const tryCommit = (h: Harness, key: string, value: unknown) => {
  try { h.ctx.commit(key, value); h.log.push(`commit:${key}:ok`); return true; }
  catch (e) { h.log.push(`commit:${key}:${e instanceof CommitRejectedError ? e.reason : String(e)}`); return false; }
};

describe("A2 commit fence", () => {
  it("C01 revoke before start: no tool call, no execution, no terminal", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async c => { c.commit("k", 1); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c01", requestId: "c01-a" }, ctx.clock);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    await expect(ctx.executor.process(req)).rejects.toThrow(AuthorityRevokedError);
    expect(h.calls).toBe(0);
    expect(ctx.executor.managedState.keys()).toEqual([]);
    expect(ctx.executor.getExecution("exec-1")).toBeUndefined();
    expect(ctx.executor.terminals()).toEqual([]);
  });

  it("C02 revoke after start, before commit: the commit is denied and the managed state is unchanged", async () => {
    const ctx = setup(Date.now()); const gate = deferred();
    const h = scriptedTool("read_record", async (_c, h) => { await gate.promise; tryCommit(h, "balance", 100); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c02", requestId: "c02-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    gate.resolve();
    await run;
    expect(h.log).toEqual(["start", "commit:balance:session_revoked"]);
    expect(ctx.executor.managedState.has("balance")).toBe(false);
    expect(ctx.executor.managedState.version).toBe(0);
    expect(eventsOf(ctx, "tool_commit_blocked").map(e => [e.metadata!.reason, e.metadata!.decision])).toEqual([["session_revoked", "deny"]]);
  });

  it("C03 commit before revocation stays a historical effect", async () => {
    const ctx = setup(Date.now()); const gate = deferred();
    const h = scriptedTool("read_record", async (c, h) => { tryCommit(h, "balance", 100); await gate.promise; tryCommit(h, "balance", 200); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c03", requestId: "c03-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: capabilityOf(ctx, req.params.request_id) });
    gate.resolve();
    await run;
    expect(h.log).toEqual(["start", "commit:balance:ok", "commit:balance:capability_revoked"]);
    expect(ctx.executor.managedState.get("balance")).toBe(100);
  });

  it("C04 revoke after commit, before delivery: the response is withheld and the commit stays", async () => {
    const ctx = setup(Date.now()); const gate = deferred();
    const h = scriptedTool("read_record", async (c, h) => { tryCommit(h, "order", { id: 7 }); await gate.promise; return { status: "ok", data: "tool-output" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c04", requestId: "c04-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    gate.resolve();
    const out = await run;
    expect(JSON.stringify(out)).not.toContain("tool-output");
    expect(ctx.executor.managedState.get("order")).toEqual({ id: 7 });
  });

  it("C11a revocation from the tool_commit_requested audit callback: the commit is denied", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async (_c, h) => { tryCommit(h, "k", 1); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c11a", requestId: "c11a-a" }, ctx.clock);
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      recordOriginal.call(this, id, t, meta);
      if (t === "tool_commit_requested") ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    });
    await ctx.executor.process(req);
    expect(h.log).toEqual(["start", "commit:k:session_revoked"]);
    expect(ctx.executor.managedState.has("k")).toBe(false);
  });

  it("C11b revocation from value serialization (toJSON) on the commit path: the commit is denied", async () => {
    const ctx = setup(Date.now()); let reqRef!: ReturnType<typeof makeRequest>;
    const h = scriptedTool("read_record", async (_c, h) => {
      tryCommit(h, "k", { toJSON: () => { ctx.executor.revoke({ scope: "session", session_id: sessionOf(reqRef) }); return "v"; } });
      return { status: "ok" };
    });
    reqRef = makeRequest({ tool: "read_record", sessionId: "c11b", requestId: "c11b-a" }, ctx.clock);
    await ctx.executor.process(reqRef);
    expect(h.log).toEqual(["start", "commit:k:session_revoked"]);
    expect(ctx.executor.managedState.has("k")).toBe(false);
  });

  it("C13 a commit requested after the terminal is denied", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async () => ({ status: "ok" }));
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c13", requestId: "c13-a" }, ctx.clock));
    await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(tryCommit(h, "late", 1)).toBe(false);
    expect(h.log).toEqual(["start", "commit:late:execution_terminal"]);
    expect(ctx.executor.managedState.has("late")).toBe(false);
    expect(() => h.ctx.track(Promise.resolve())).toThrow(/terminal/);
  });

  it("C16 audit failure on the commit path never opens the effect", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async (_c, h) => { tryCommit(h, "k", 1); return { status: "ok" }; });
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      if (t === "tool_commit_requested" || t === "tool_commit_blocked") throw new Error("audit sink unavailable");
      return recordOriginal.call(this, id, t, meta);
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c16", requestId: "c16-a" }, ctx.clock));
    expect(h.log).toEqual(["start", "commit:k:audit_unavailable"]);
    expect(ctx.executor.managedState.has("k")).toBe(false);
  });

  it("C16b a lost tool_commit_applied record does not undo the applied write", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async (_c, h) => { tryCommit(h, "k", 1); return { status: "ok" }; });
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      if (t === "tool_commit_applied") throw new Error("audit sink unavailable");
      return recordOriginal.call(this, id, t, meta);
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c16b", requestId: "c16b-a" }, ctx.clock));
    expect(h.log).toEqual(["start", "commit:k:ok"]);
    expect(ctx.executor.managedState.get("k")).toBe(1);
  });

  it("C08 natural completion without revocation: commit applied, terminal 'completed'", async () => {
    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async (_c, h) => { tryCommit(h, "k", "v"); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c08", requestId: "c08-a" }, ctx.clock);
    await ctx.executor.process(req);
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(ctx.executor.managedState.get("k")).toBe("v");
    expect(terminal).toMatchObject({ outcome: "completed", cancellation_requested: false, cancellation_acknowledged: false, request_id: req.params.request_id, session_id: sessionOf(req), capability_id: capabilityOf(ctx, req.params.request_id) });
    expect(ctx.executor.terminals()).toHaveLength(1);
  });
});

describe("A2 cancellation and terminal", () => {
  it("C05 acknowledgement without ending: no terminal until the managed work actually settles", async () => {
    const ctx = setup(Date.now()); const finish = deferred();
    const h = scriptedTool("read_record", async (c, h) => {
      c.cancellation.onCancel(() => { h.log.push(`ack:${c.acknowledgeCancellation()}`); });
      await finish.promise; h.log.push("end"); return { status: "ok" };
    });
    const req = makeRequest({ tool: "read_record", sessionId: "c05", requestId: "c05-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    // Listeners run synchronously inside revoke(); nothing needs to be awaited before the checks.
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    await flush();
    expect(h.log).toEqual(["start", "ack:true"]);
    expect(ctx.executor.getExecution(h.ctx.execution_id)).toMatchObject({ state: "running", cancellation_requested: true, cancellation_acknowledged: true });
    expect(ctx.executor.terminals()).toEqual([]);
    finish.resolve(); await run;
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(terminal).toMatchObject({ outcome: "completed", cancellation_requested: true, cancellation_acknowledged: true });
  });

  it("C06 a tool that ignores the signal: no false terminal, its commit is still denied, outcome is not 'cancelled'", async () => {
    const ctx = setup(Date.now()); const gate = deferred();
    const h = scriptedTool("read_record", async (_c, h) => { await gate.promise; tryCommit(h, "k", 1); return { status: "ok" }; });
    const req = makeRequest({ tool: "read_record", sessionId: "c06", requestId: "c06-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    await flush();
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.state).toBe("running");
    expect(ctx.executor.terminals()).toEqual([]);
    gate.resolve(); await run;
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(h.log).toEqual(["start", "commit:k:session_revoked"]);
    expect(terminal).toMatchObject({ outcome: "completed", cancellation_requested: true, cancellation_acknowledged: false });
    expect(ctx.executor.managedState.has("k")).toBe(false);
  });

  it("C07 a tool that reacts to cancellation: registered work ends, one terminal 'cancelled'", async () => {
    const ctx = setup(Date.now()); const workDone = deferred();
    const h = scriptedTool("read_record", (c, h) => new Promise((_resolve, reject) => {
      const work = c.track(workDone.promise.then(() => { h.log.push("work:end"); }));
      c.cancellation.onCancel(reason => {
        h.log.push(`ack:${c.acknowledgeCancellation()}`);
        workDone.resolve();
        work.then(() => reject(reason));
      });
    }));
    const req = makeRequest({ tool: "read_record", sessionId: "c07", requestId: "c07-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.cancellation_requested).toBe(true);
    await run;
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    await flush();
    expect(h.log).toEqual(["start", "ack:true", "work:end"]);
    expect(terminal).toMatchObject({ outcome: "cancelled", cancellation_requested: true, cancellation_acknowledged: true, tracked_registered: 1, tracked_fulfilled: 1, tracked_rejected: 0 });
    expect(ctx.executor.terminals()).toHaveLength(1);
    expect(ctx.executor.terminals()[0]).toMatchObject({ execution_id: h.ctx.execution_id, outcome: "cancelled" });
  });

  it("C20 'cancelled' requires this execution's own CancellationError", async () => {
    const ctx = setup(Date.now());
    const other = new CancellationError("exec-999", "session:x");
    const h = scriptedTool("read_record", c => new Promise((_res, reject) => { c.cancellation.onCancel(() => reject(other)); }));
    const req = makeRequest({ tool: "read_record", sessionId: "c20", requestId: "c20-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.cancellation_requested).toBe(true);
    await run;
    expect(await ctx.executor.whenTerminal(h.ctx.execution_id)).toMatchObject({ outcome: "failed", cancellation_requested: true });
  });

  it("C09 duplicate revoke does not signal again; repeated acknowledgement is idempotent", async () => {
    const ctx = setup(Date.now()); const gate = deferred(); let signals = 0; const acks: boolean[] = [];
    const h = scriptedTool("read_record", async (c) => {
      c.cancellation.onCancel(() => { signals++; acks.push(c.acknowledgeCancellation()); acks.push(c.acknowledgeCancellation()); });
      await gate.promise; acks.push(c.acknowledgeCancellation()); return { status: "ok" };
    });
    const req = makeRequest({ tool: "read_record", sessionId: "c09", requestId: "c09-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    const dup = ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    ctx.executor.revoke({ scope: "capability", capability_id: capabilityOf(ctx, req.params.request_id) });
    gate.resolve(); await run;
    expect(dup.status).toBe("already_revoked");
    expect(signals).toBe(1);
    expect(acks).toEqual([true, false, false]);
    expect(eventsOf(ctx, "execution_cancellation_requested")).toHaveLength(1);
    expect(eventsOf(ctx, "execution_cancellation_acknowledged")).toHaveLength(1);
  });

  it("C10 untargeted capability/session and parallel executions are unaffected", async () => {
    const ctx = setup(Date.now()); const gate = deferred(); const signalled: string[] = [];
    tools.read_record = async (args, c) => {
      c!.cancellation.onCancel(() => signalled.push(String(args.who)));
      await gate.promise;
      try { c!.commit(`k-${args.who}`, 1); } catch { /* denied */ }
      return { status: "ok", data: `out-${args.who}` };
    };
    const a = makeRequest({ tool: "read_record", sessionId: "c10-a", requestId: "c10-a1", args: { who: { value: "a" } } }, ctx.clock);
    const b = makeRequest({ tool: "read_record", sessionId: "c10-b", requestId: "c10-b1", args: { who: { value: "b" } } }, ctx.clock);
    const runA = ctx.executor.process(a); const runB = ctx.executor.process(b);
    await flush();
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(a) });
    ctx.executor.revoke({ scope: "capability", capability_id: "unrelated-capability" });
    gate.resolve();
    const [outA, outB] = await Promise.all([runA, runB]);
    expect(signalled).toEqual(["a"]);
    expect(ctx.executor.managedState.keys()).toEqual(["k-b"]);
    expect(JSON.stringify(outA)).not.toContain("out-a");
    expect(JSON.stringify(outB)).toContain("out-b");
  });

  it("C12 listener exceptions and re-entrancy cannot undo revocation, open the fence or stop other cancellations", async () => {
    const ctx = setup(Date.now()); const gate = deferred(); const log: string[] = [];
    let otherReq!: ReturnType<typeof makeRequest>;
    tools.read_record = async (args, c) => {
      const who = String(args.who);
      if (who === "a") {
        c!.cancellation.onCancel(() => { log.push("a:l1"); throw new Error("listener boom"); });
        c!.cancellation.onCancel(() => {
          log.push("a:l2");
          ctx.executor.revoke({ scope: "session", session_id: sessionOf(makeRequest({ sessionId: "c12-a" })) }); // duplicate
          try { c!.commit("from-listener", 1); log.push("a:commit:ok"); } catch (e) { log.push(`a:commit:${(e as CommitRejectedError).reason}`); }
          ctx.executor.revoke({ scope: "session", session_id: sessionOf(otherReq) }); // re-entrant revoke of another target
        });
        c!.cancellation.onCancel(() => { log.push("a:l3"); });
      } else {
        c!.cancellation.onCancel(() => { log.push(`${who}:signalled`); });
      }
      await gate.promise;
      return { status: "ok" };
    };
    const a = makeRequest({ tool: "read_record", sessionId: "c12-a", requestId: "c12-a1", args: { who: { value: "a" } } }, ctx.clock);
    otherReq = makeRequest({ tool: "read_record", sessionId: "c12-o", requestId: "c12-o1", args: { who: { value: "o" } } }, ctx.clock);
    const runA = ctx.executor.process(a); const runO = ctx.executor.process(otherReq);
    await flush();
    const receipt = ctx.executor.revoke({ scope: "session", session_id: sessionOf(a) });
    expect(receipt.status).toBe("revoked");
    expect(log).toEqual(["a:l1", "a:l2", "a:commit:session_revoked", "o:signalled", "a:l3"]);
    expect(ctx.executor.managedState.has("from-listener")).toBe(false);
    gate.resolve();
    await Promise.all([runA, runO]);
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c12-a", requestId: "c12-a2" }, ctx.clock))).rejects.toThrow(AuthorityRevokedError);
    const execA = ctx.executor.getExecution("exec-1")!;
    expect(execA.session_id).toBe(sessionOf(a));
    expect((await ctx.executor.whenTerminal("exec-1")).listener_errors).toBe(1);
  });

  it("C14 registered background work: the terminal waits for it; it may commit until then", async () => {
    const ctx = setup(Date.now()); const bg = deferred(); let execId = "";
    const h = scriptedTool("read_record", async (c, h) => {
      execId = c.execution_id;
      c.track(bg.promise.then(() => { tryCommit(h, "bg", 1); }));
      return { status: "ok" };
    });
    const out = await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c14", requestId: "c14-a" }, ctx.clock));
    expect((out as { result: { exit_status: string } }).result.exit_status).toBe("success");
    await flush();
    expect(ctx.executor.getExecution(execId)!.state).toBe("draining");
    expect(ctx.executor.terminals()).toEqual([]);
    bg.resolve();
    const terminal = await ctx.executor.whenTerminal(execId);
    expect(h.log).toEqual(["start", "commit:bg:ok"]);
    expect(terminal).toMatchObject({ outcome: "completed", tracked_registered: 1, tracked_fulfilled: 1 });
    expect(ctx.executor.managedState.get("bg")).toBe(1);
  });

  it("C15 unregistered detached work: the terminal does not wait for it, and its later commit is denied", async () => {
    const ctx = setup(Date.now()); const detached = deferred(); const done = deferred();
    const h = scriptedTool("read_record", async (_c, h) => {
      void detached.promise.then(() => { tryCommit(h, "detached", 1); done.resolve(); });
      return { status: "ok" };
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c15", requestId: "c15-a" }, ctx.clock));
    const terminal = await ctx.executor.whenTerminal(h.ctx.execution_id);
    expect(terminal.tracked_registered).toBe(0);
    detached.resolve(); await done.promise;
    expect(h.log).toEqual(["start", "commit:detached:execution_terminal"]);
    expect(ctx.executor.managedState.has("detached")).toBe(false);
  });

  it("C17 exactly one terminal whichever of the tool function and registered work settles last", async () => {
    for (const order of ["main-last", "work-last"] as const) {
      const ctx = setup(Date.now()); const main = deferred(); const work = deferred();
      const h = scriptedTool("read_record", async c => { c.track(work.promise); await main.promise; return { status: "ok" }; });
      const run = ctx.executor.process(makeRequest({ tool: "read_record", sessionId: `c17-${order}`, requestId: `c17-${order}-a` }, ctx.clock));
      await h.started.promise;
      if (order === "main-last") { work.resolve(); await flush(); expect(ctx.executor.terminals()).toEqual([]); main.resolve(); }
      else { main.resolve(); await run; await flush(); expect(ctx.executor.terminals()).toEqual([]); work.resolve(); }
      await run; await ctx.executor.whenTerminal(h.ctx.execution_id); await flush();
      expect(ctx.executor.terminals()).toHaveLength(1);
    }
  });

  it("C18 execution identity: each real invocation gets its own id bound to request, session and capability", async () => {
    const ctx = setup(Date.now()); const ids: string[] = [];
    tools.read_record = async (_a, c) => { ids.push(c!.execution_id); return { status: "ok" }; };
    const req = makeRequest({ tool: "read_record", sessionId: "c18", requestId: "c18-a" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.executor.clearSession(sessionOf(req));
    await ctx.executor.process(req);
    expect(new Set(ids).size).toBe(2);
    const caps = ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === "capability_verified").map(e => e.metadata!.capability_id);
    ids.forEach((id, i) => expect(ctx.executor.getExecution(id)).toMatchObject({ request_id: req.params.request_id, session_id: sessionOf(req), capability_id: caps[i] }));
  });

  it("C19 approval path: the approved execution is managed; a revoke cancels it and fences its commit", async () => {
    const ctx = setup(Date.now()); const gate = deferred(); let signalled = false;
    const h = scriptedTool("update_record", async (c, h) => { c.cancellation.onCancel(() => { signalled = true; }); await gate.promise; tryCommit(h, "k", 1); return { status: "ok" }; });
    const req = makeRequest({ tool: "update_record", sessionId: "c19", requestId: "c19-a" }, ctx.clock);
    await ctx.executor.process(req);
    const run = ctx.executor.resolveApproval(approve(ctx, req));
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    gate.resolve(); await run;
    expect(signalled).toBe(true);
    expect(h.log).toEqual(["start", "commit:k:session_revoked"]);
    expect(ctx.executor.managedState.has("k")).toBe(false);
  });

  it("C21 a listener registered after the request is called immediately; state is read-only for tools", async () => {
    const ctx = setup(Date.now()); const gate = deferred(); const seen: string[] = [];
    const h = scriptedTool("read_record", async c => {
      await gate.promise;
      c.cancellation.onCancel(reason => seen.push(reason.execution_id));
      expect(() => c.cancellation.throwIfRequested()).toThrow(CancellationError);
      return { status: "ok" };
    });
    const req = makeRequest({ tool: "read_record", sessionId: "c21", requestId: "c21-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    gate.resolve(); await run;
    expect(seen).toEqual([h.ctx.execution_id]);
    expect((ctx.executor.managedState as unknown as { issueWriter?: unknown }).issueWriter).toBeUndefined();
    expect(Object.isFrozen(h.ctx)).toBe(true);
  });
});

const runFixture = (scenario: string) => spawnSync(process.execPath, ["-r", "ts-node/register", path.join(__dirname, "fixtures", "rejected-subclass-tool.ts"), scenario], {
  cwd: path.join(__dirname, ".."),
  env: { ...process.env, TS_NODE_TRANSPILE_ONLY: "true", TS_NODE_PROJECT: path.join(__dirname, "..", "tsconfig.json") },
  encoding: "utf8",
});

describe("A2 settlement observation, registration and evidence", () => {
  /** A native Promise whose own `then` claims fulfilment immediately, although the Promise itself is still pending. */
  function lyingPromise<T>(claimed: T) {
    const real = deferred<T>();
    Object.defineProperty(real.promise, "then", {
      value: (onFulfilled?: (v: T) => unknown) => { onFulfilled?.(claimed); return Promise.resolve(); },
    });
    return real;
  }

  it("C22 a tool's Promise with its own `then` cannot produce a terminal before the Promise settles", async () => {
    const ctx = setup(Date.now()); const main = lyingPromise({ status: "ok" }); let c!: ExecutionContext;
    tools.read_record = (_a, ctxArg) => { c = ctxArg!; return main.promise; };
    const run = ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c22", requestId: "c22-a" }, ctx.clock));
    await flush();
    expect(ctx.executor.getExecution(c.execution_id)!.state).toBe("running");
    expect(ctx.executor.terminals()).toEqual([]);
    c.commit("k", 1);
    expect(ctx.executor.managedState.get("k")).toBe(1);
    main.resolve({ status: "ok" });
    await run;
    expect(await ctx.executor.whenTerminal(c.execution_id)).toMatchObject({ outcome: "completed" });
    expect(ctx.executor.terminals()).toHaveLength(1);
  });

  it("C22b a changed `constructor` never runs: a configurable one is pinned and restored, a non-configurable one makes the Promise unobservable without a terminal", async () => {
    const ctx = setup(Date.now());
    // Configurable accessor: the runtime pins Promise for the duration of the intrinsic `then` and restores it.
    const real = deferred<unknown>(); let c!: ExecutionContext; let getterCalls = 0;
    const getter = () => { getterCalls++; throw new Error("constructor getter must not run"); };
    Object.defineProperty(real.promise, "constructor", { get: getter, configurable: true });
    tools.read_record = (_a, ctxArg) => { c = ctxArg!; return real.promise; };
    const run = ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c22b", requestId: "c22b-a" }, ctx.clock));
    await flush();
    expect(ctx.executor.getExecution(c.execution_id)!.state).toBe("running");
    expect(Object.getOwnPropertyDescriptor(real.promise, "constructor")).toEqual({ get: getter, set: undefined, enumerable: false, configurable: true });
    real.resolve({ status: "ok" }); await run;
    expect(await ctx.executor.whenTerminal(c.execution_id)).toMatchObject({ outcome: "completed" });
    expect(getterCalls).toBe(0);

    // Non-configurable accessor: cannot be pinned, so the call fails. The Promise is still pending and unobserved,
    // so the failure is not evidence that the execution ended: no terminal, commits closed, still cancellable.
    const hidden = deferred<unknown>(); let d!: ExecutionContext; const log: string[] = [];
    Object.defineProperty(hidden.promise, "constructor", { get: getter });
    tools.read_record = (_a, ctxArg) => { d = ctxArg!; return hidden.promise; };
    const req = makeRequest({ tool: "read_record", sessionId: "c22b2", requestId: "c22b2-a" }, ctx.clock);
    await ctx.executor.process(req);
    const snapshot = ctx.executor.getExecution(d.execution_id)!;
    expect(snapshot.state).toBe("unobservable");
    expect(snapshot).not.toHaveProperty("terminal");
    expect(ctx.executor.terminals().map(t => t.execution_id)).toEqual([c.execution_id]);
    expect(eventsOf(ctx, "execution_terminal").filter(e => e.request_id === req.params.request_id)).toEqual([]);
    expect(eventsOf(ctx, "tool_execution_completed").find(e => e.request_id === req.params.request_id)!.metadata!.status).toBe("error");
    try { d.commit("late", 1); } catch (e) { log.push((e as CommitRejectedError).reason); }
    expect(log).toEqual(["settlement_unobservable"]);
    expect(ctx.executor.managedState.has("late")).toBe(false);
    expect(getterCalls).toBe(0);
    hidden.resolve({ status: "ok" });
    await flush();
    expect(ctx.executor.getExecution(d.execution_id)!.state).toBe("unobservable");
  });

  it("C23 registered work with its own `then` keeps the execution draining until the work really settles", async () => {
    const ctx = setup(Date.now()); const work = lyingPromise("done");
    const h = scriptedTool("read_record", async c => { c.track(work.promise); return { status: "ok" }; });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c23", requestId: "c23-a" }, ctx.clock));
    await flush();
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.state).toBe("draining");
    expect(ctx.executor.terminals()).toEqual([]);
    work.resolve("done");
    expect(await ctx.executor.whenTerminal(h.ctx.execution_id)).toMatchObject({ tracked_registered: 1, tracked_fulfilled: 1 });
  });

  it("C24 work that cannot be observed is refused before registration and never leaves a phantom pending entry", async () => {
    const ctx = setup(Date.now()); const errors: string[] = [];
    const throwingConstructor = Promise.resolve("already settled");
    Object.defineProperty(throwingConstructor, "constructor", { get() { throw new Error("constructor getter"); } });
    const candidates: unknown[] = [throwingConstructor, { then: (f: (v: unknown) => void) => f(1) }, 42];
    const h = scriptedTool("read_record", async c => {
      for (const w of candidates) {
        try { c.track(w as Promise<unknown>); errors.push("registered"); } catch (e) { errors.push((e as Error).name); }
      }
      return { status: "ok" };
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c24", requestId: "c24-a" }, ctx.clock));
    expect(errors).toEqual(["TypeError", "TypeError", "TypeError"]);
    await flush();
    expect(ctx.executor.getExecution(h.ctx.execution_id)).toMatchObject({ state: "terminal", terminal: { outcome: "completed", tracked_registered: 0 } });
  });

  it("C28 rejected registered work in a Promise subclass is observed and counted as rejected", async () => {
    const ctx = setup(Date.now());
    class SubPromise<T> extends Promise<T> {}
    const marker = new Error("SUBCLASS_REJECTION_MARKER");
    const work = deferred<void>(); const sub = new SubPromise<void>((_res, rej) => { work.promise.then(() => rej(marker)); });
    const h = scriptedTool("read_record", async c2 => { c2.track(sub); return { status: "ok" }; });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c28t", requestId: "c28t-a" }, ctx.clock));
    await flush();
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.state).toBe("draining");
    work.resolve();
    expect(await ctx.executor.whenTerminal(h.ctx.execution_id)).toMatchObject({ outcome: "completed", tracked_registered: 1, tracked_rejected: 1 });
  });

  it("C28b process-level: a tool returning a rejected Promise subclass leaves no unhandled rejection; the process exits normally", () => {
    const result = runFixture("rejected-subclass");
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("SUBCLASS_REJECTION_MARKER");
    expect(JSON.parse(result.stdout.trim().split("\n").pop()!)).toEqual({ outcome: "failed", delivered: true });
  }, 60_000);

  it("C29 the runtime never runs a species constructor: subclass and custom-species Promises are observed through a pinned intrinsic species", async () => {
    const ctx = setup(Date.now());
    let constructed = 0;
    class CountingSpecies<T> extends Promise<T> {
      constructor(executor: (resolve: (value: T | PromiseLike<T>) => void, reject: (reason?: unknown) => void) => void) {
        constructed++;
        super(executor);
      }
    }
    // (a) A plain native Promise whose own `constructor` data property is a custom species.
    const custom = Promise.resolve({ status: "ok" });
    Object.defineProperty(custom, "constructor", { value: CountingSpecies, writable: true, configurable: true });
    let c!: ExecutionContext;
    tools.read_record = (_a, ctxArg) => { c = ctxArg!; return custom; };
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c29a", requestId: "c29a-a" }, ctx.clock));
    expect(await ctx.executor.whenTerminal(c.execution_id)).toMatchObject({ outcome: "completed" });
    expect(Object.getOwnPropertyDescriptor(custom, "constructor")).toEqual({ value: CountingSpecies, writable: true, enumerable: false, configurable: true });

    // (b) A subclass instance returned by the tool and (c) one registered with track().
    const returned = CountingSpecies.resolve({ status: "ok" }); const tracked = CountingSpecies.resolve("work");
    const before = constructed;
    tools.read_record = (_a, ctxArg) => { c = ctxArg!; c.track(tracked); return returned; };
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c29b", requestId: "c29b-a" }, ctx.clock));
    expect(await ctx.executor.whenTerminal(c.execution_id)).toMatchObject({ outcome: "completed", tracked_registered: 1, tracked_fulfilled: 1 });
    expect(Object.prototype.hasOwnProperty.call(returned, "constructor")).toBe(false);
    expect(constructed).toBe(before);

    // (d) A frozen subclass instance cannot be pinned: track() refuses it, a returned one fails the call. Although
    // it is already fulfilled, the runtime cannot observe that, so the execution is unobservable and has no terminal.
    const frozen = Object.freeze(CountingSpecies.resolve("frozen")); const errors: string[] = [];
    const frozenBefore = constructed;
    tools.read_record = (_a, ctxArg) => {
      c = ctxArg!;
      try { c.track(frozen); } catch (e) { errors.push((e as Error).name); }
      return frozen as Promise<unknown>;
    };
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c29d", requestId: "c29d-a" }, ctx.clock));
    expect(errors).toEqual(["TypeError"]);
    expect(ctx.executor.getExecution(c.execution_id)).toMatchObject({ state: "unobservable" });
    expect(ctx.executor.getExecution(c.execution_id)).not.toHaveProperty("terminal");
    expect(constructed).toBe(frozenBefore);
  });

  it("C29c a modified Promise[Symbol.species] makes native Promises unobservable instead of running it", async () => {
    const ctx = setup(Date.now()); const errors: string[] = []; let speciesCalls = 0;
    const original = Object.getOwnPropertyDescriptor(Promise, Symbol.species)!;
    const h = scriptedTool("read_record", async c => {
      Object.defineProperty(Promise, Symbol.species, { get() { speciesCalls++; return Promise; }, configurable: true });
      try { c.track(Promise.resolve("work")); } catch (e) { errors.push((e as Error).name); }
      finally { Object.defineProperty(Promise, Symbol.species, original); }
      return { status: "ok" };
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c29c", requestId: "c29c-a" }, ctx.clock));
    expect(errors).toEqual(["TypeError"]);
    expect(speciesCalls).toBe(0);
    expect(ctx.executor.getExecution(h.ctx.execution_id)!.terminal).toMatchObject({ outcome: "completed", tracked_registered: 0 });
  });

  it("C29b process-level: a species constructor that would reject the derived Promise is never run; the process exits normally", () => {
    const result = runFixture("rejecting-species");
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("DERIVED_SPECIES_REJECTION");
    expect(JSON.parse(result.stdout.trim().split("\n").pop()!)).toEqual({ outcome: "completed", delivered: true });
  }, 60_000);

  it("C25 a failed execution_terminal record call leaves the local terminal intact and marks the recording unconfirmed", async () => {
    const ok = setup(Date.now());
    const h1 = scriptedTool("read_record", async () => ({ status: "ok" }));
    await ok.executor.process(makeRequest({ tool: "read_record", sessionId: "c25-ok", requestId: "c25-ok-a" }, ok.clock));
    expect(await ok.executor.whenTerminal(h1.ctx.execution_id)).toMatchObject({ audit_recorded: true });
    expect(eventsOf(ok, "execution_terminal")[0].metadata).not.toHaveProperty("audit_recorded");

    const ctx = setup(Date.now());
    const h = scriptedTool("read_record", async () => ({ status: "ok" }));
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      if (t === "execution_terminal") throw new Error("audit sink unavailable");
      return recordOriginal.call(this, id, t, meta);
    });
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c25", requestId: "c25-a" }, ctx.clock));
    expect(await ctx.executor.whenTerminal(h.ctx.execution_id)).toMatchObject({ outcome: "completed", audit_recorded: false });
    expect(ctx.executor.terminals()).toEqual([expect.objectContaining({ execution_id: h.ctx.execution_id, audit_recorded: false })]);
    expect(eventsOf(ctx, "execution_terminal")).toEqual([]);

    // A sink that writes and then throws: still unconfirmed locally, although the event is in the stream.
    const wt = setup(Date.now());
    const h2 = scriptedTool("read_record", async () => ({ status: "ok" }));
    jest.spyOn(wt.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
      recordOriginal.call(this, id, t, meta);
      if (t === "execution_terminal") throw new Error("sink failed after writing");
    });
    await wt.executor.process(makeRequest({ tool: "read_record", sessionId: "c25-wt", requestId: "c25-wt-a" }, wt.clock));
    expect(await wt.executor.whenTerminal(h2.ctx.execution_id)).toMatchObject({ outcome: "completed", audit_recorded: false });
    expect(eventsOf(wt, "execution_terminal")).toHaveLength(1);
    expect(wt.executor.terminals()).toHaveLength(1);
  });

  it("C26 the managed state store issues its writer once; the view cannot write and returns copies", () => {
    const store = new ManagedStateStore();
    const write = store.issueWriter();
    expect(() => store.issueWriter()).toThrow(/already issued/);
    expect(write("k", JSON.stringify({ a: 1 }))).toBe(1);
    const view = store.view();
    expect((view as unknown as { issueWriter?: unknown }).issueWriter).toBeUndefined();
    expect(Object.isFrozen(view)).toBe(true);
    (view.get("k") as { a: number }).a = 2;
    expect(view.get("k")).toEqual({ a: 1 });
    expect(view.version).toBe(1);
  });

  it("C27 commit values never reach the audit log, whether the commit is applied or blocked", async () => {
    const ctx = setup(Date.now()); const gate = deferred();
    const h = scriptedTool("read_record", async (_c, h) => {
      tryCommit(h, "applied-key", { secret: "VALUE-MARKER-APPLIED" });
      await gate.promise;
      tryCommit(h, "blocked-key", { secret: "VALUE-MARKER-BLOCKED" });
      return { status: "ok" };
    });
    const req = makeRequest({ tool: "read_record", sessionId: "c27", requestId: "c27-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await h.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    gate.resolve(); await run;
    expect(h.log).toEqual(["start", "commit:applied-key:ok", "commit:blocked-key:session_revoked"]);
    const serialized = JSON.stringify(ctx.audit.getEvents());
    expect(serialized).toContain("applied-key");
    expect(serialized).toContain("blocked-key");
    expect(serialized).not.toContain("VALUE-MARKER");
  });
});

describe("A2 unobservable settlement is not terminal evidence", () => {
  /**
   * A pending native Promise whose `constructor` is a non-configurable accessor: the runtime can neither pin nor
   * read it without running the object's code, so the Promise's settlement is unobservable.
   */
  function unobservablePromise() {
    const real = deferred<unknown>(); const counter = { getterCalls: 0 };
    Object.defineProperty(real.promise, "constructor", { get() { counter.getterCalls++; throw new Error("constructor getter must not run"); } });
    return { ...real, counter };
  }

  /** Runs a tool that registers its hooks and then returns an unobservable, still pending Promise. */
  async function runUnobservable(ctx: Ctx, sessionId: string, hooks: (c: ExecutionContext) => void = () => undefined) {
    const hidden = unobservablePromise(); let c!: ExecutionContext;
    tools.read_record = (_a, ctxArg) => { c = ctxArg!; hooks(c); return hidden.promise; };
    const req = makeRequest({ tool: "read_record", sessionId, requestId: `${sessionId}-a` }, ctx.clock);
    const result = await ctx.executor.process(req);
    return { hidden, c, req, result };
  }
  const noTerminalYet = async (ctx: Ctx, executionId: string) => {
    const pending = Symbol("pending");
    return (await Promise.race([ctx.executor.whenTerminal(executionId), flush().then(() => pending)])) === pending;
  };

  it("C22c API error: the call fails with TypeError and the request ends in a failed result, without running the object's code", async () => {
    const ctx = setup(Date.now());
    const { hidden, req, result } = await runUnobservable(ctx, "c22c");
    const rid = req.params.request_id;
    expect(eventsOf(ctx, "tool_execution_completed").filter(e => e.request_id === rid).map(e => e.metadata!.status)).toEqual(["error"]);
    expect(eventsOf(ctx, "tool_execution_blocked").filter(e => e.request_id === rid)).toHaveLength(1);
    expect(result).toBeDefined();

    // The invocation itself rejects with the documented TypeError.
    const store = new ManagedStateStore();
    const direct = new ManagedExecution("exec-direct", "r", "s", "cap", {
      audit: new AuditCollector(), revoked: () => undefined, write: store.issueWriter(), nextCommitId: () => "commit-x", onTerminal: () => undefined,
    });
    const error = await direct.invoke(() => hidden.promise, {}).then(() => undefined, (e: unknown) => e);
    expect(error).toBeInstanceOf(TypeError);
    expect((error as Error).message).toBe("Tool returned a native Promise whose settlement cannot be observed");
    expect((error as Error).cause).toBeInstanceOf(TypeError);
    expect(direct.terminal).toBe(false);
    expect(direct.snapshot().state).toBe("unobservable");
    expect(hidden.counter.getterCalls).toBe(0);
    hidden.resolve({ status: "ok" });
  });

  it("C22d no terminal evidence: no execution_terminal, no terminal record and no whenTerminal, also after the work settles", async () => {
    const ctx = setup(Date.now());
    const { hidden, c, req } = await runUnobservable(ctx, "c22d");
    const evidence = () => ({
      snapshot: ctx.executor.getExecution(c.execution_id),
      terminals: ctx.executor.terminals(),
      events: ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === "execution_terminal" && e.request_id === req.params.request_id),
    });
    expect(evidence()).toEqual({
      snapshot: { execution_id: c.execution_id, request_id: req.params.request_id, session_id: sessionOf(req), capability_id: capabilityOf(ctx, req.params.request_id),
        state: "unobservable", cancellation_requested: false, cancellation_acknowledged: false },
      terminals: [], events: [],
    });
    expect(await noTerminalYet(ctx, c.execution_id)).toBe(true);
    // The real work ends, but the runtime never observed it: its settlement is still not terminal evidence.
    hidden.resolve({ status: "ok" });
    expect(await noTerminalYet(ctx, c.execution_id)).toBe(true);
    expect(evidence().terminals).toEqual([]);
    expect(evidence().events).toEqual([]);
    expect(hidden.counter.getterCalls).toBe(0);
  });

  it("C22e commits are blocked after the failure (settlement_unobservable) and registration is closed; earlier commits stay", async () => {
    const ctx = setup(Date.now());
    const { hidden, c, req } = await runUnobservable(ctx, "c22e", ctxArg => { ctxArg.commit("before", 1); });
    const caught = (() => { try { c.commit("after", 2); return undefined; } catch (e) { return e; } })();
    expect(caught).toBeInstanceOf(CommitRejectedError);
    expect((caught as CommitRejectedError).reason).toBe("settlement_unobservable");
    expect(ctx.executor.managedState.keys()).toEqual(["before"]);
    expect(ctx.executor.managedState.version).toBe(1);
    expect(eventsOf(ctx, "tool_commit_blocked").filter(e => e.request_id === req.params.request_id).map(e => [e.metadata!.key, e.metadata!.reason, e.metadata!.decision]))
      .toEqual([["after", "settlement_unobservable", "deny"]]);
    expect(() => c.track(Promise.resolve("late work"))).toThrow(/unobservable settlement/);
    hidden.resolve({ status: "ok" });
    await flush();
    expect(() => c.commit("after-settle", 3)).toThrow(CommitRejectedError);
    expect(ctx.executor.managedState.version).toBe(1);
  });

  it("C22f a later revocation still signals cancellation to the unobservable execution; the signal is not a terminal", async () => {
    const ctx = setup(Date.now()); const seen: string[] = []; let listenerCommit: unknown;
    const { hidden, c, req } = await runUnobservable(ctx, "c22f", ctxArg => {
      ctxArg.cancellation.onCancel(reason => {
        seen.push(`${reason.execution_id}:${reason.revocation_id}`);
        try { ctxArg.commit("from-listener", 1); } catch (e) { listenerCommit = (e as CommitRejectedError).reason; }
      });
    });
    expect(c.cancellation.requested).toBe(false);
    const receipt = ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    expect(seen).toEqual([`${c.execution_id}:${receipt.revocation_id}`]);
    expect(c.cancellation.requested).toBe(true);
    expect(c.cancellation.reason).toBeInstanceOf(CancellationError);
    expect(listenerCommit).toBe("settlement_unobservable");
    expect(ctx.executor.managedState.has("from-listener")).toBe(false);
    expect(eventsOf(ctx, "execution_cancellation_requested").map(e => [e.metadata!.execution_id, e.metadata!.revocation_id]))
      .toEqual([[c.execution_id, receipt.revocation_id]]);
    expect(c.acknowledgeCancellation()).toBe(true);
    expect(ctx.executor.getExecution(c.execution_id)).toMatchObject({ state: "unobservable", cancellation_requested: true, cancellation_acknowledged: true });
    // A duplicate revoke does not signal again; none of this is terminal evidence.
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    expect(seen).toHaveLength(1);
    expect(await noTerminalYet(ctx, c.execution_id)).toBe(true);
    expect(ctx.executor.terminals()).toEqual([]);
    expect(eventsOf(ctx, "execution_terminal")).toEqual([]);
    hidden.resolve({ status: "ok" });
  });
});
