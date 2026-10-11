/**
 * Test setup for the approval-permit lifecycle (permit mode, docs/approval-permit-lifecycle.md). The executor is built
 * as in tests/tenant-setup.ts (tenancy mode, the same issuer and approver keys), with { lifecycle: "permit" }. Chains
 * come from tests/chain-setup.ts and are served per session, so the provider answers every lookup of a session with
 * the same chain (a lineage's authority is that exact chain).
 *
 * Clock: the clock is the injected MutableClock. Tests that move it (expiry, chain validity) do so explicitly and,
 * where it matters, from inside a callback; no test waits for real time.
 *
 * Tool doubles: every test installs its own tool doubles, which count their own invocations and record the
 * arguments they received. "No tool call" is always asserted through these counters, never through the audit.
 */
import crypto from "crypto";
import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { CapabilityLookupContext, GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import { ApprovalGrantVerifier } from "../src/approval-verifier";
import { CapabilityGrantVerifier } from "../src/capability-grant";
import type { LineageSnapshot, LifecycleOptions } from "../src/approval-lifecycle";
import type { AcsToolCallRequest, AuditEventType } from "../src/acs-types";
import { tools, ToolImplementation } from "../src/tools";
import type { ExecutionContext } from "../src/managed-execution";
import { MutableClock, fresh, testSignatureService, toUuid } from "./evals/eval-setup";
import { TestSigner } from "./test-signer";
import { TenantCapabilityProvider, sessionUuid } from "./tenant-setup";
import type { TenancyCtx } from "./tenant-setup";

export function setupLifecycle(options: Omit<LifecycleOptions, "lifecycle"> = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const approverKeyId = "approver-1";
  const testSigner = new TestSigner(privateKey, approverKeyId);
  const clock = new MutableClock(Date.now());
  const audit = new AuditCollector();
  const capKeys = crypto.generateKeyPairSync("ed25519");
  const provider = new TenantCapabilityProvider("cap-key-1", capKeys.privateKey, clock);
  const verifier = new CapabilityGrantVerifier(capKeys.publicKey, "cap-key-1", clock, { tenancy: true });
  const guardian = new Guardian();
  const executor = new GuardedExecutor(
    new SchemaValidator(),
    new SignatureService("test-secret", "key-1"),
    new ReplayGuard({ skewWindowMs: 300_000, clock, audit }),
    guardian,
    audit,
    new ExecutionCorrelationStore(),
    new ApprovalGrantVerifier(publicKey, approverKeyId),
    clock,
    30000,
    provider,
    verifier,
    { lifecycle: "permit", ...options }
  );
  return { executor, audit, clock, provider, verifier, testSigner, guardian };
}

export type LifecycleCtx = ReturnType<typeof setupLifecycle>;

/** The chain helpers of tests/chain-setup.ts need only these members of the context. */
export const asTenancy = (ctx: LifecycleCtx): TenancyCtx => ctx as unknown as TenancyCtx;

export interface RequestSpec {
  id: string;
  session: string;
  tool?: string;
  args?: Record<string, unknown>;
  agent?: string;
  tenantId?: string;
}

/** A signed tool-call request with ACS argument values ({ name: { value } }). */
export function toolRequest(ctx: { clock: MutableClock }, o: RequestSpec): AcsToolCallRequest {
  const args = o.args ?? { n: 1 };
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: crypto.randomUUID(),
    params: {
      acs_version: "0.1.0",
      request_id: toUuid(o.id),
      timestamp: fresh(ctx.clock.nowMs()),
      ...(o.tenantId !== undefined ? { tenant_id: o.tenantId } : {}),
      metadata: { agent_id: o.agent ?? "agent-test", session_id: sessionUuid(o.session) },
      payload: { tool: { name: o.tool ?? "update_record" }, arguments: Object.fromEntries(Object.entries(args).map(([k, v]) => [k, { value: v }])) },
    },
  };
  return testSignatureService.signRequest(req) as AcsToolCallRequest;
}

/** A human ApprovalGrantV3 for a lineage snapshot; `overrides` replace signed fields (the grant is signed after). */
export function approvalV3(ctx: LifecycleCtx, snap: LineageSnapshot, overrides: Record<string, unknown> = {}) {
  return ctx.testSigner.sign({
    version: 3,
    decision: "approve",
    lineage_id: snap.lineage_id,
    session_id: snap.bindings.session_id,
    request_id: snap.bindings.request_id,
    tool: snap.bindings.tool,
    request_digest: snap.bindings.request_digest,
    authority_fingerprint: snap.bindings.authority_fingerprint,
    approver: { type: "human", id: "demo-operator" },
    issued_at: fresh(ctx.clock.nowMs()),
    ...overrides,
  } as Parameters<TestSigner["sign"]>[0]);
}

export interface ToolDouble { calls: number; args: Record<string, unknown>[]; ctx: ExecutionContext[] }

const originalTools = { ...tools };
export function restoreTools(): void {
  for (const k of Object.keys(tools)) delete tools[k];
  Object.assign(tools, originalTools);
}

/** Installs a tool double that counts its own invocations; `body` runs inside the tool after counting. */
export function toolDouble(name: string, body: (args: Record<string, unknown>, ctx: ExecutionContext) => unknown = () => ({ status: "ok" })): ToolDouble {
  const double: ToolDouble = { calls: 0, args: [], ctx: [] };
  const fn: ToolImplementation = async (args, ctx) => {
    double.calls++;
    double.args.push(JSON.parse(JSON.stringify(args)));
    double.ctx.push(ctx!);
    return body(args, ctx!);
  };
  tools[name] = fn;
  return double;
}

/** Runs `action` once, after the first audit record of `type` (optionally for one request id). */
export function onAudit(ctx: LifecycleCtx, type: AuditEventType, action: (meta?: Record<string, unknown>) => void, requestId?: string): void {
  const recordOriginal = AuditCollector.prototype.record;
  let fired = false;
  jest.spyOn(ctx.audit, "record").mockImplementation(function (this: AuditCollector, id: string, t: AuditEventType, meta?: Record<string, unknown>) {
    recordOriginal.call(this, id, t, meta);
    if (t === type && !fired && (requestId === undefined || id === requestId)) { fired = true; action(meta); }
  });
}

/** Runs `action` once, inside the next provider lookup (after the answer is computed, before it is returned). */
export function onNextResolve(ctx: LifecycleCtx, action: (context: CapabilityLookupContext) => void): void {
  const resolve = ctx.provider.resolve.bind(ctx.provider);
  let fired = false;
  jest.spyOn(ctx.provider, "resolve").mockImplementation((context: CapabilityLookupContext) => {
    const answer = resolve(context);
    if (!fired) { fired = true; action(context); }
    return answer;
  });
}

export { sessionUuid, toUuid, fresh };
