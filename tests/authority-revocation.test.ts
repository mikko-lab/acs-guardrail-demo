import { setup, makeRequest, fresh } from "./evals/eval-setup";
import { tools } from "../src/tools";
import { AuditCollector } from "../src/audit";
import { AuthorityRevokedError } from "../src/guarded-executor";
import { RevocationTargetError } from "../src/authority-revocation";
import type { AuditEvent, AuditEventType } from "../src/acs-types";
import { exportAuditToOcsf, validateOcsfEvent } from "../src/ocsf";
import { IncidentClassifier } from "../src/incident-evidence";

type Ctx = ReturnType<typeof setup>;
type Deferred = { promise: Promise<void>; resolve: () => void };
const deferred = (): Deferred => { let resolve!: () => void; const promise = new Promise<void>(r => (resolve = r)); return { promise, resolve }; };

const original = { ...tools };
afterEach(() => { for (const k of Object.keys(tools)) delete tools[k]; Object.assign(tools, original); });

/** Harness-owned latched tool double: it only records and pauses; it never decides or blocks anything. */
function latchedTool(log: string[], name: string) {
  const started = deferred(), beforeCommit = deferred(), committed = deferred(), beforeReturn = deferred();
  tools[name] = async () => {
    log.push(`${name}:start`); started.resolve();
    await beforeCommit.promise;
    log.push(`${name}:commit`); committed.resolve();
    await beforeReturn.promise;
    log.push(`${name}:return`);
    return { status: "success", data: "tool-output" };
  };
  return { started, beforeCommit, committed, beforeReturn };
}
/** Harness-owned instant double counting executions independently of the SUT's own counters. */
function countingTool(log: string[], name: string) {
  tools[name] = async () => { log.push(`${name}:executed`); return { status: "success", data: "tool-output" }; };
}

const types = (ctx: Ctx) => ctx.audit.getEvents().map((e: AuditEvent) => e.event_type);
const eventsOf = (ctx: Ctx, type: AuditEventType) => ctx.audit.getEvents().filter((e: AuditEvent) => e.event_type === type);
const approve = (ctx: Ctx, req: ReturnType<typeof makeRequest>) => ctx.testSigner.sign({
  version: 2, tool: req.params.payload.tool.name, decision: "approve", session_id: req.params.metadata.session_id,
  request_id: req.params.request_id, approver: { type: "human", id: "demo-operator" }, issued_at: fresh(ctx.clock.nowMs()),
});
const sessionOf = (req: ReturnType<typeof makeRequest>) => req.params.metadata.session_id;
/** Pins the provider to one signed grant so that a capability_id identifies the authority across requests. */
function fixCapability(ctx: Ctx, sessionLabel: string) {
  const cap = ctx.capabilityProvider.resolve({ agent_id: "agent-test", session_id: sessionOf(makeRequest({ sessionId: sessionLabel })), request_id: "x", tool: "update_record" }) as { capability_id: string };
  ctx.capabilityProvider.fixedCapability = cap;
  return cap.capability_id;
}
const capabilityOfAsk = (ctx: Ctx, requestId: string) =>
  ctx.audit.getEvents().find((e: AuditEvent) => e.event_type === "capability_verified" && e.request_id === requestId)!.metadata!.capability_id as string;

describe("Authority revocation: approval fence", () => {
  it("REV-01 pending approval -> capability revoke -> approve: no execution", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const req = makeRequest({ tool: "update_record", sessionId: "rev-01", requestId: "rev-01-r" }, ctx.clock);
    expect(await ctx.executor.process(req)).toEqual({ status: "pending" });
    const receipt = ctx.executor.revoke({ scope: "capability", capability_id: capabilityOfAsk(ctx, req.params.request_id) });
    expect(receipt.pending_approvals).toEqual([req.params.request_id]);

    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(AuthorityRevokedError);
    expect(log).toEqual([]);
    const enforced = eventsOf(ctx, "authority_revocation_enforced");
    expect(enforced.map(e => [e.metadata!.stage, e.metadata!.reason, e.metadata!.decision])).toEqual([["approval", "capability_revoked", "deny"]]);
    expect(types(ctx)).not.toContain("human_approval");
    expect(types(ctx)).not.toContain("tool_execution_started");
    // The pending action is consumed: a second approval cannot succeed either.
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(/No pending action found/);
  });

  it("REV-02 pending approval -> session revoke -> approve: no execution", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const req = makeRequest({ tool: "update_record", sessionId: "rev-02", requestId: "rev-02-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toMatchObject({ code: "AUTHORITY_REVOKED", stage: "approval", reason: "session_revoked" });
    expect(log).toEqual([]);
  });

  it("REV-03 pending approval -> provider no longer resolves the capability -> approve: no execution", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const req = makeRequest({ tool: "update_record", sessionId: "rev-03", requestId: "rev-03-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.capabilityProvider.returnNull = true;
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(/Capability rejected at approval: Missing capability/);
    expect(log).toEqual([]);
    const rejected = eventsOf(ctx, "capability_rejected");
    expect(rejected.map(e => [e.metadata!.reason, e.metadata!.stage])).toEqual([["missing_capability", "approval"]]);
    expect(types(ctx)).not.toContain("human_approval");
  });

  it("REV-03b the original capability's current validity is checked at approval, separately from the provider", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    // Original grant expires shortly after the ASK; the provider would still issue a fresh grant later.
    ctx.capabilityProvider.tamperCapability = cap => ({ ...cap, expires_at: fresh(ctx.clock.nowMs(), 10_000) });
    const req = makeRequest({ tool: "update_record", sessionId: "rev-03b", requestId: "rev-03b-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.capabilityProvider.tamperCapability = undefined;
    ctx.clock.currentMs += 20_000;
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(/capability has expired/);
    expect(log).toEqual([]);
    expect(eventsOf(ctx, "capability_rejected").map(e => e.metadata!.reason)).toEqual(["capability_expired"]);
  });

  it("REV-03c a provider re-issue never replaces a revoked original capability", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const req = makeRequest({ tool: "update_record", sessionId: "rev-03c", requestId: "rev-03c-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.executor.revoke({ scope: "capability", capability_id: capabilityOfAsk(ctx, req.params.request_id) });
    // The default provider mints a new capability_id on every resolve; it is not consulted as a substitute.
    const before = ctx.capabilityProvider.resolveCalled;
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(AuthorityRevokedError);
    expect(ctx.capabilityProvider.resolveCalled).toBe(before);
    expect(log).toEqual([]);
  });
});

describe("Authority revocation: request and start fences", () => {
  it("REV-04 revoked capability -> fresh-ID process: no execution", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    const capId = fixCapability(ctx, "rev-04");
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-04", requestId: "rev-04-a" }, ctx.clock));
    expect(log).toEqual(["read_record:executed"]);
    ctx.executor.revoke({ scope: "capability", capability_id: capId });
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-04", requestId: "rev-04-b" }, ctx.clock)))
      .rejects.toMatchObject({ code: "AUTHORITY_REVOKED", stage: "request", reason: "capability_revoked" });
    expect(log).toEqual(["read_record:executed"]);
    expect(types(ctx).filter(t => t === "capability_verified")).toHaveLength(1);
  });

  it("REV-05 revoked session -> fresh-ID process and replay: no execution", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    const first = makeRequest({ tool: "read_record", sessionId: "rev-05", requestId: "rev-05-a" }, ctx.clock);
    await ctx.executor.process(first);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(first) });
    const resolved = ctx.capabilityProvider.resolveCalled;
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-05", requestId: "rev-05-b" }, ctx.clock))).rejects.toThrow(AuthorityRevokedError);
    await expect(ctx.executor.process(first)).rejects.toMatchObject({ reason_code: "REPLAY_DETECTED" });
    expect(ctx.capabilityProvider.resolveCalled).toBe(resolved);
    expect(log).toEqual(["read_record:executed"]);
  });

  it("REV-06 revoke -> clearSession -> new request and old replay: revocation persists", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    const first = makeRequest({ tool: "read_record", sessionId: "rev-06", requestId: "rev-06-a" }, ctx.clock);
    await ctx.executor.process(first);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(first) });
    ctx.executor.clearSession(sessionOf(first));
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-06", requestId: "rev-06-b" }, ctx.clock))).rejects.toThrow(AuthorityRevokedError);
    // clearSession released replay state, so the replay reaches the revocation check and is denied there.
    await expect(ctx.executor.process(first)).rejects.toMatchObject({ code: "AUTHORITY_REVOKED", stage: "request", reason: "session_revoked" });
    expect(log).toEqual(["read_record:executed"]);
  });

  it("REV-07 duplicate revoke is idempotent and the authority stays revoked", async () => {
    const ctx = setup(Date.now());
    const sessionId = sessionOf(makeRequest({ sessionId: "rev-07" }));
    const a = ctx.executor.revoke({ scope: "session", session_id: sessionId });
    ctx.clock.currentMs += 5_000;
    const b = ctx.executor.revoke({ scope: "session", session_id: sessionId });
    expect(a.status).toBe("revoked"); expect(b.status).toBe("already_revoked");
    expect([b.revocation_id, b.effective_sequence, b.effective_at]).toEqual([a.revocation_id, a.effective_sequence, a.effective_at]);
    const other = ctx.executor.revoke({ scope: "capability", capability_id: "cap-x" });
    expect(other.effective_sequence).toBe(a.effective_sequence + 1);
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-07", requestId: "rev-07-a" }, ctx.clock))).rejects.toThrow(AuthorityRevokedError);
    expect(eventsOf(ctx, "authority_revoked").map(e => e.metadata!.status)).toEqual(["revoked", "already_revoked", "revoked"]);
  });

  it("REV-08 untargeted capability and session continue normally", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(makeRequest({ sessionId: "rev-08-revoked" })) });
    ctx.executor.revoke({ scope: "capability", capability_id: "some-other-capability" });
    const ok = await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-08-other", requestId: "rev-08-a" }, ctx.clock));
    expect(ok.status).toBe("executed");
    expect((ok as { result: { exit_status: string } }).result.exit_status).toBe("success");
    expect(log).toEqual(["read_record:executed"]);
    expect(types(ctx)).toContain("tool_result_delivered");
  });

  it("REV-start the start fence denies a revocation that lands after the request-time check", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-start", requestId: "rev-start-a" }, ctx.clock);
    // Deterministic hook: the revocation happens inside Guardian evaluation, i.e. after the request-time check.
    const guardian = (ctx.executor as any).guardian;
    const evaluate = guardian.evaluate.bind(guardian);
    jest.spyOn(guardian, "evaluate").mockImplementationOnce((r: unknown) => { ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) }); return evaluate(r); });
    await expect(ctx.executor.process(req)).rejects.toMatchObject({ code: "AUTHORITY_REVOKED", stage: "start" });
    expect(log).toEqual([]);
    expect(types(ctx)).not.toContain("tool_execution_started");
  });

  it("REV-start-approval the start fence also applies to the approval path", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const req = makeRequest({ tool: "update_record", sessionId: "rev-start-ap", requestId: "rev-start-ap-a" }, ctx.clock);
    await ctx.executor.process(req);
    // Deterministic hook after every approval-stage check: the human_approval audit write revokes the session.
    const recordOriginal = AuditCollector.prototype.record;
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, type: AuditEventType, meta?: Record<string, unknown>) {
      recordOriginal.call(this, id, type, meta);
      if (type === "human_approval") ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    });
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toMatchObject({ code: "AUTHORITY_REVOKED", stage: "start", reason: "session_revoked" });
    expect(log).toEqual([]);
    expect(types(ctx)).not.toContain("tool_execution_started");
  });

  it("REV-api revoke is not reachable through agent requests and rejects unsupported targets", async () => {
    const ctx = setup(Date.now());
    // A tool call named like the operation is an ordinary (unknown, out-of-scope) agent request.
    await expect(ctx.executor.process(makeRequest({ tool: "revoke", sessionId: "rev-api", requestId: "rev-api-a" }, ctx.clock))).rejects.toThrow();
    expect(types(ctx)).not.toContain("authority_revoked");
    for (const bad of [null, {}, { scope: "tenant", tenant_id: "t1" }, { scope: "session", session_id: "" }, { scope: "session", session_id: "s", extra: 1 }, { scope: "capability" }]) {
      expect(() => ctx.executor.revoke(bad)).toThrow(RevocationTargetError);
    }
    expect(types(ctx)).not.toContain("authority_revoked");
  });

  it("REV-id a capability_id cannot silently refer to two different grants", async () => {
    const ctx = setup(Date.now());
    const capId = fixCapability(ctx, "rev-id");
    await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-id", requestId: "rev-id-a" }, ctx.clock));
    ctx.capabilityProvider.fixedCapability = undefined;
    ctx.capabilityProvider.tamperCapability = cap => ({ ...cap, capability_id: capId, allowed_tools: ["read_record"] });
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-id", requestId: "rev-id-b" }, ctx.clock))).rejects.toThrow(/capability_id is already bound/);
    expect(eventsOf(ctx, "capability_rejected").map(e => e.metadata!.reason)).toEqual(["capability_id_conflict"]);
  });
});

describe("Authority revocation: delivery fence and A1 limits", () => {
  it("REV-09 running tool -> revoke -> tool returns: delivery withheld with a revocation reason", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; const t = latchedTool(log, "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-09", requestId: "rev-09-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await t.started.promise;
    const receipt = ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    log.push("harness:revoked");
    expect(receipt.in_flight_executions).toEqual([req.params.request_id]);
    expect(receipt.in_flight_side_effects).toBe("not_prevented");
    t.beforeCommit.resolve(); t.beforeReturn.resolve();
    const out = await run;
    expect(out.status).toBe("executed");
    const result = (out as { result: { exit_status: string; outputs: unknown[] } }).result;
    expect(result.exit_status).toBe("blocked");
    expect(JSON.stringify(result.outputs)).not.toContain("tool-output");
    expect(result.outputs).toEqual([{ value: { error: "Output withheld: authority revoked.", code: "session_revoked" } }]);
    expect(types(ctx)).not.toContain("tool_result_delivered");
    expect(eventsOf(ctx, "tool_result_withheld").map(e => e.metadata!.reason)).toEqual(["session_revoked"]);
    const enforced = eventsOf(ctx, "authority_revocation_enforced");
    expect(enforced.map(e => [e.metadata!.stage, e.metadata!.request_id_ref])).toEqual([["delivery", req.params.request_id]]);
  });

  it("REV-10 commit before revoke: the commit remains a historical fact, delivery is withheld", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; const t = latchedTool(log, "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-10", requestId: "rev-10-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    t.beforeCommit.resolve(); await t.committed.promise;
    ctx.executor.revoke({ scope: "capability", capability_id: (ctx.audit.getEvents().find((e: AuditEvent) => e.event_type === "capability_verified")!.metadata!.capability_id as string) });
    log.push("harness:revoked");
    t.beforeReturn.resolve();
    const out = await run;
    expect(log).toEqual(["read_record:start", "read_record:commit", "harness:revoked", "read_record:return"]);
    expect((out as { result: { exit_status: string } }).result.exit_status).toBe("blocked");
    expect(eventsOf(ctx, "tool_result_withheld").map(e => e.metadata!.reason)).toEqual(["capability_revoked"]);
  });

  it("REV-limit A1 does not fence in-flight commits: a running tool still commits after revocation (no containment claim)", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; const t = latchedTool(log, "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-limit", requestId: "rev-limit-a" }, ctx.clock);
    const run = ctx.executor.process(req);
    await t.started.promise;
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    log.push("harness:revoked");
    t.beforeCommit.resolve(); t.beforeReturn.resolve();
    await run;
    // Documented limitation: the effect happens after the revocation. Only delivery is withheld.
    expect(log).toEqual(["read_record:start", "harness:revoked", "read_record:commit", "read_record:return"]);
    expect(types(ctx)).toContain("tool_execution_completed");
  });

  it("REV-delivery-boundary a revocation after the result was returned does not recall it", async () => {
    const ctx = setup(Date.now()); countingTool([], "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-db", requestId: "rev-db-a" }, ctx.clock);
    const out = await ctx.executor.process(req);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    expect((out as { result: { exit_status: string } }).result.exit_status).toBe("success");
    expect(types(ctx).filter(t => t === "tool_result_delivered")).toHaveLength(1);
  });
});

describe("Authority revocation: compatibility and audit failure", () => {
  it("REV-11 unrevoked clearSession and replay behaviour is unchanged", async () => {
    const ctx = setup(Date.now());
    const first = makeRequest({ tool: "read_record", sessionId: "rev-11", requestId: "rev-11-a" }, ctx.clock);
    await ctx.executor.process(first);
    await expect(ctx.executor.process(first)).rejects.toMatchObject({ reason_code: "REPLAY_DETECTED" });
    ctx.executor.clearSession(sessionOf(first));
    await expect(ctx.executor.process(first)).resolves.toMatchObject({ status: "executed" });
    const pending = makeRequest({ tool: "update_record", sessionId: "rev-11", requestId: "rev-11-b" }, ctx.clock);
    await ctx.executor.process(pending);
    ctx.executor.clearSession(sessionOf(pending));
    await expect(ctx.executor.resolveApproval(approve(ctx, pending))).rejects.toThrow(/No pending action found/);
    expect(types(ctx)).not.toContain("authority_revocation_enforced");
  });

  it("REV-12 audit failure does not return revoked authority to use", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "read_record");
    const recordOriginal = AuditCollector.prototype.record;
    const failing = new Set<AuditEventType>(["authority_revoked", "authority_revocation_enforced"]);
    jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, type: AuditEventType, meta?: Record<string, unknown>) {
      if (failing.has(type)) throw new Error("audit sink unavailable");
      return recordOriginal.call(this, id, type, meta);
    });
    const sessionId = sessionOf(makeRequest({ sessionId: "rev-12" }));
    const receipt = ctx.executor.revoke({ scope: "session", session_id: sessionId });
    expect(receipt.status).toBe("revoked");
    expect(receipt.audit_recorded).toBe(false);
    await expect(ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "rev-12", requestId: "rev-12-a" }, ctx.clock))).rejects.toThrow(AuthorityRevokedError);
    expect(log).toEqual([]);
  });

  it("REV-receipt names the target and its effective point without claiming termination", async () => {
    const ctx = setup(Date.now());
    const receipt = ctx.executor.revoke({ scope: "capability", capability_id: "cap-receipt" });
    expect(receipt).toEqual({
      version: 1, revocation_id: "capability:cap-receipt", target: { scope: "capability", capability_id: "cap-receipt" },
      status: "revoked", effective_sequence: 1, effective_at: new Date(ctx.clock.nowMs()).toISOString(),
      enforced_at: ["request", "approval", "start", "delivery"], pending_approvals: [], in_flight_executions: [],
      in_flight_side_effects: "not_prevented", persistence: "in_memory_single_runtime_instance", audit_recorded: true,
    });
    const ev = eventsOf(ctx, "authority_revoked")[0];
    expect(ev.request_id).toBe("capability:cap-receipt");
    expect(ev.metadata).toMatchObject({ scope: "capability", capability_id: "cap-receipt", status: "revoked" });
    expect(ctx.audit.verifyIntegrity()).toEqual({ valid: true });
  });

  it("REV-ocsf revocation evidence exports as validated generic Base Events and is not an incident", async () => {
    const ctx = setup(Date.now()); countingTool([], "read_record");
    const req = makeRequest({ tool: "read_record", sessionId: "rev-ocsf", requestId: "rev-ocsf-a" }, ctx.clock);
    ctx.executor.revoke({ scope: "session", session_id: sessionOf(req) });
    await expect(ctx.executor.process(req)).rejects.toThrow(AuthorityRevokedError);
    const events = ctx.audit.getEvents();
    const result = exportAuditToOcsf(events, { expectedHeadHash: ctx.audit.getHeadHash() });
    for (const e of result.events) expect(validateOcsfEvent(e)).toEqual([]);
    const revocation = result.events.filter(e => ["authority_revoked", "authority_revocation_enforced"].includes(e.unmapped.acs.event_type));
    expect(revocation.map(e => [e.unmapped.acs.event_type, e.class_uid])).toEqual([["authority_revoked", 0], ["authority_revocation_enforced", 0]]);
    expect(revocation[1].unmapped.acs.metadata).toMatchObject({ stage: "request", decision: "deny", reason: "session_revoked" });
    expect(IncidentClassifier.fromAudit(events).filter((i: { source_event_type: string }) => i.source_event_type.startsWith("authority_"))).toEqual([]);
  });
});

describe("Approval-time capability validity versus the pending timeout boundary", () => {
  const TIMEOUT_MS = 300 * 1000; // Guardian ask_details.timeout_seconds for update_record

  it("REV-13a pending approved exactly at the timeout boundary while the capability is still valid", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    ctx.capabilityProvider.tamperCapability = cap => ({ ...cap, expires_at: fresh(ctx.clock.nowMs(), 2 * TIMEOUT_MS) });
    const req = makeRequest({ tool: "update_record", sessionId: "rev-13a", requestId: "rev-13a-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.clock.currentMs += TIMEOUT_MS; // elapsed == timeout: still within the strict `elapsed > timeout` rule
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).resolves.toMatchObject({ exit_status: "success" });
    expect(log).toEqual(["update_record:executed"]);
  });

  it("REV-13b pending rejected once the timeout boundary is exceeded, without starting the tool", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    ctx.capabilityProvider.tamperCapability = cap => ({ ...cap, expires_at: fresh(ctx.clock.nowMs(), 2 * TIMEOUT_MS) });
    const req = makeRequest({ tool: "update_record", sessionId: "rev-13b", requestId: "rev-13b-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.clock.currentMs += TIMEOUT_MS + 1;
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(/pending action has expired/);
    expect(log).toEqual([]);
    expect(types(ctx)).not.toContain("tool_execution_started");
  });

  it("REV-13c capability rejected exactly at expires_at while the pending action is still valid, without starting the tool", async () => {
    const ctx = setup(Date.now()); const log: string[] = []; countingTool(log, "update_record");
    const lifetime = 100 * 1000; // shorter than the pending timeout
    ctx.capabilityProvider.tamperCapability = cap => ({ ...cap, expires_at: fresh(ctx.clock.nowMs(), lifetime) });
    const req = makeRequest({ tool: "update_record", sessionId: "rev-13c", requestId: "rev-13c-r" }, ctx.clock);
    await ctx.executor.process(req);
    ctx.capabilityProvider.tamperCapability = undefined; // the provider would issue a fresh, valid grant now
    ctx.clock.currentMs += lifetime; // now == expires_at; pending elapsed (100 s) < timeout (300 s)
    await expect(ctx.executor.resolveApproval(approve(ctx, req))).rejects.toThrow(/capability has expired/);
    expect(log).toEqual([]);
    expect(types(ctx)).not.toContain("tool_execution_started");
    expect(types(ctx)).not.toContain("approval_expired");
    expect(eventsOf(ctx, "capability_rejected").map(e => [e.metadata!.reason, e.metadata!.stage])).toEqual([["capability_expired", "approval"]]);
  });
});
