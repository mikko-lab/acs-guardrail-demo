import { SchemaValidator } from "../../src/schema-validator";
import { SignatureService } from "../../src/signature-service";
import { ExecutionCorrelationStore } from "../../src/execution-correlation";
import { GuardedExecutor } from "../../src/guarded-executor";
import { ReplayGuard, Clock } from "../../src/replay-guard";
import { Guardian } from "../../src/guardian";
import { AuditCollector } from "../../src/audit";
import type { AcsToolCallRequest, AcsToolArgumentValue } from "../../src/acs-types";
import { ApprovalGrantVerifier } from "../../src/approval-verifier";
import { CapabilityGrantVerifier, CapabilityGrantV1 } from "../../src/capability-grant";
import { CapabilityProvider, CapabilityLookupContext } from "../../src/guarded-executor";
import { canonicalize } from "json-canonicalize";

import { TestSigner } from "../test-signer";
import crypto from "crypto";

export class MutableClock implements Clock {
  constructor(public currentMs: number) {}
  nowMs() { return this.currentMs; }
}

export const fresh = (nowMs: number, offsetMs = 0) =>
  new Date(nowMs + offsetMs).toISOString();

export const testSignatureService = new SignatureService("test-secret", "key-1");

function toUuid(prefix: string) {
  // Simple UUID generator from prefix for tests. Format: 00000000-0000-0000-0000-000000000000
  // Pad with 0s and hash if needed, but simple string replacement works for short prefixes.
  const hash = crypto.createHash('md5').update(prefix).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
}

export function makeRequest(overrides: {
  requestId?: string;
  sessionId?: string;
  timestamp?: string;
  tool?: string;
  args?: Record<string, AcsToolArgumentValue>;
}, clock?: Clock): AcsToolCallRequest {
  const reqId = toUuid(overrides.requestId || "req-1");
  const sessId = toUuid(overrides.sessionId || "sess-1");
  const now = clock ? clock.nowMs() : Date.now();
  const req: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: crypto.randomUUID(),
    params: {
      acs_version: "0.1.0",
      request_id: reqId,
      timestamp: overrides.timestamp || fresh(now),
      metadata: {
        agent_id: "agent-test",
        session_id: sessId,
      },
      payload: {
        tool: { name: overrides.tool || "read_record" },
        arguments: overrides.args || {},
      },
    },
  };
  return testSignatureService.signRequest(req) as AcsToolCallRequest;
}

export function makeResultRequest(overrides: {
  requestIdRef?: string;
  sessionId?: string;
  timestamp?: string;
  tool?: string;
}, clock?: Clock) {
  const reqRef = toUuid(overrides.requestIdRef || "req-1");
  const sessId = toUuid(overrides.sessionId || "sess-1");
  const now = clock ? clock.nowMs() : Date.now();
  
  return {
    jsonrpc: "2.0" as const,
    method: "steps/toolCallResult" as const,
    id: crypto.randomUUID(),
    params: {
      acs_version: "0.1.0" as const,
      request_id: crypto.randomUUID(),
      timestamp: overrides.timestamp || fresh(now),
      metadata: { agent_id: "agent-test", session_id: sessId },
      payload: { request_id_ref: reqRef, tool: { name: overrides.tool || "read_record" }, outputs: [] }
    }
  };
}

export function createAuthorityTestDeps(clock: Clock, keyId: string = "cap-key-1") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const provider = new MockCapabilityProvider(keyId, privateKey, clock);
  const verifier = new CapabilityGrantVerifier(publicKey, keyId, clock);
  return { provider, verifier, publicKey, privateKey };
}

export class MockCapabilityProvider implements CapabilityProvider {
  constructor(
    public keyId: string,
    public privateKey: crypto.KeyObject,
    public clock: Clock,
    public defaultTools: string[] = ["read_record", "update_record", "delete_record", "write_record", "system_shell", "read_all_records"]
  ) {}

  public resolveCalled = 0;
  public forceThrow = false;
  public returnNull = false;
  /** Runs BEFORE signing — modified data is signed; use for validly signed semantic mismatches */
  public tamperCapability?: (cap: CapabilityGrantV1) => CapabilityGrantV1;
  /** Runs AFTER signing — mutates signed data and therefore produces INVALID_SIGNATURE */
  public postTamperCapability?: (cap: CapabilityGrantV1) => CapabilityGrantV1;

  public fixedCapability?: unknown;

  resolve(context: CapabilityLookupContext): unknown | undefined {
    this.resolveCalled++;
    if (this.forceThrow) throw new Error("Mock provider error");
    if (this.returnNull) return undefined;
    if (this.fixedCapability) return this.fixedCapability;

    const cap: CapabilityGrantV1 = {
      version: 1,
      capability_id: crypto.randomUUID(),
      agent_id: context.agent_id,
      session_id: context.session_id,
      allowed_tools: [...this.defaultTools],
      issued_at: fresh(this.clock.nowMs(), -1000),
      expires_at: fresh(this.clock.nowMs(), 300000),
      signature: { algorithm: "Ed25519", key_id: this.keyId, value: "" }
    };

    const toSign = this.tamperCapability ? this.tamperCapability(cap) : cap;

    const clone = JSON.parse(JSON.stringify(toSign));
    delete clone.signature;
    const dataBuffer = Buffer.from(canonicalize(clone));
    const sig = crypto.sign(null, dataBuffer, this.privateKey);
    toSign.signature.value = sig.toString("base64");

    if (this.postTamperCapability) return this.postTamperCapability(toSign);
    return toSign;
  }
}


export function setup(nowMs: number) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const approverKeyId = "approver-1";
  const testSigner = new TestSigner(privateKey, approverKeyId);
  const approvalVerifier = new ApprovalGrantVerifier(publicKey, approverKeyId);

  const clock = new MutableClock(nowMs);
  const audit = new AuditCollector();
  const replayGuard = new ReplayGuard({ skewWindowMs: 300_000, clock, audit });
  const guardian = new Guardian();

  const schemaValidator = new SchemaValidator();
  const signatureService = new SignatureService("test-secret", "key-1");
  const correlation = new ExecutionCorrelationStore();
  const authority = createAuthorityTestDeps(clock);
  const capabilityProvider = authority.provider;
  const capabilityVerifier = authority.verifier;

  const executor = new GuardedExecutor(
    schemaValidator,
    signatureService,
    replayGuard,
    guardian,
    audit,
    correlation,
    approvalVerifier,
    clock,
    30000,
    capabilityProvider,
    capabilityVerifier
  );

  return { executor, audit, replayGuard, guardian, clock, publicKey, privateKey, signatureService, schemaValidator, correlation, testSigner, approverKeyId, capabilityProvider, capabilityVerifier };
}
export { toUuid };
