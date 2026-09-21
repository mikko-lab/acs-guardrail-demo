import { SchemaValidator } from "../../src/schema-validator";
import { SignatureService } from "../../src/signature-service";
import { ExecutionCorrelationStore } from "../../src/execution-correlation";
import { GuardedExecutor } from "../../src/guarded-executor";
import { ReplayGuard, Clock } from "../../src/replay-guard";
import { Guardian } from "../../src/guardian";
import { AuditCollector } from "../../src/audit";
import type { AcsToolCallRequest, AcsToolArgumentValue } from "../../src/acs-types";
import { ApprovalGrantVerifier } from "../../src/approval-verifier";
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
  const executor = new GuardedExecutor(
    schemaValidator,
    signatureService,
    replayGuard,
    guardian,
    audit,
    correlation,
    approvalVerifier,
    clock
  );

  return { executor, audit, replayGuard, guardian, clock, publicKey, privateKey, signatureService, schemaValidator, correlation, testSigner, approverKeyId };
}
export { toUuid };
