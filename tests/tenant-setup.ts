/**
 * Test setup for tenant scope (tenancy mode). The executor is built exactly as tests/evals/eval-setup.ts builds it,
 * except that the capability verifier runs in tenancy mode and the provider issues signed version 2 grants whose
 * tenant comes from a per-session table.
 *
 * Clock: the runtime stamps its own internal result requests with the real time and checks them against the
 * executor clock, so the clock starts at the real time (as in tests/evals/eval-setup.ts). It is never advanced, and
 * no expectation in the tenant tests depends on time (no expiry, timeout or ordering by time).
 */
import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { SchemaValidator } from "../src/schema-validator";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { CapabilityLookupContext, CapabilityProvider, GuardedExecutor } from "../src/guarded-executor";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { AuditCollector } from "../src/audit";
import { ApprovalGrantVerifier } from "../src/approval-verifier";
import { CapabilityGrantVerifier } from "../src/capability-grant";
import type { AcsToolCallRequest } from "../src/acs-types";
import { MutableClock, fresh, testSignatureService, toUuid } from "./evals/eval-setup";
import { TestSigner } from "./test-signer";

export interface GrantSpec {
  version: 1 | 2;
  tenant_id?: string;
  capability_id?: string;
}

/** Signs grants with the trusted issuer key. `grantFor` decides version, tenant and capability id per lookup. */
export class TenantCapabilityProvider implements CapabilityProvider {
  resolveCalled = 0;
  /** Tenant per runtime session id; sessions not listed use `defaultTenant`. */
  readonly tenants = new Map<string, string>();
  defaultTenant = "t1";
  /** Optional override of the grant issued for one lookup. */
  grantFor?: (context: CapabilityLookupContext) => GrantSpec;
  /** Optional override of the whole answer for one lookup (a chain envelope, for example); used by tests/chain-setup.ts. */
  answerFor?: (context: CapabilityLookupContext) => unknown;

  constructor(private readonly keyId: string, private readonly privateKey: crypto.KeyObject, private readonly clock: MutableClock) {}

  sign(body: Record<string, unknown>): Record<string, unknown> {
    const signature = crypto.sign(null, Buffer.from(canonicalize(body)), this.privateKey).toString("base64");
    return { ...body, signature: { algorithm: "Ed25519", key_id: this.keyId, value: signature } };
  }

  grant(context: CapabilityLookupContext, spec: GrantSpec): Record<string, unknown> {
    return this.sign({
      version: spec.version,
      capability_id: spec.capability_id ?? crypto.randomUUID(),
      agent_id: context.agent_id,
      session_id: context.session_id,
      ...(spec.tenant_id !== undefined ? { tenant_id: spec.tenant_id } : {}),
      allowed_tools: ["read_record", "update_record"],
      issued_at: fresh(this.clock.nowMs(), -1000),
      expires_at: fresh(this.clock.nowMs(), 300000),
    });
  }

  resolve(context: CapabilityLookupContext): unknown {
    this.resolveCalled++;
    if (this.answerFor) return this.answerFor(context);
    const spec = this.grantFor?.(context) ?? { version: 2, tenant_id: this.tenants.get(context.session_id) ?? this.defaultTenant };
    return this.grant(context, spec);
  }
}

export function setupTenancy(options: { tenancy?: boolean } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const approverKeyId = "approver-1";
  const testSigner = new TestSigner(privateKey, approverKeyId);
  const clock = new MutableClock(Date.now());
  const audit = new AuditCollector();
  const capKeys = crypto.generateKeyPairSync("ed25519");
  const provider = new TenantCapabilityProvider("cap-key-1", capKeys.privateKey, clock);
  const verifier = new CapabilityGrantVerifier(capKeys.publicKey, "cap-key-1", clock, { tenancy: options.tenancy ?? true });
  const executor = new GuardedExecutor(
    new SchemaValidator(),
    new SignatureService("test-secret", "key-1"),
    new ReplayGuard({ skewWindowMs: 300_000, clock, audit }),
    new Guardian(),
    audit,
    new ExecutionCorrelationStore(),
    new ApprovalGrantVerifier(publicKey, approverKeyId),
    clock,
    30000,
    provider,
    verifier
  );
  return { executor, audit, clock, provider, verifier, testSigner };
}

export type TenancyCtx = ReturnType<typeof setupTenancy>;

/** A signed tool-call request; `tenantId` sets the request's own (signed) tenant_id claim. */
export function tenantRequest(o: { requestId: string; sessionId: string; tool?: string; tenantId?: string }, clock: MutableClock): AcsToolCallRequest {
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: crypto.randomUUID(),
    params: {
      acs_version: "0.1.0",
      request_id: toUuid(o.requestId),
      timestamp: fresh(clock.nowMs()),
      ...(o.tenantId !== undefined ? { tenant_id: o.tenantId } : {}),
      metadata: { agent_id: "agent-test", session_id: toUuid(o.sessionId) },
      payload: { tool: { name: o.tool ?? "read_record" }, arguments: {} },
    },
  };
  return testSignatureService.signRequest(req) as AcsToolCallRequest;
}

export const sessionUuid = (name: string) => toUuid(name);
