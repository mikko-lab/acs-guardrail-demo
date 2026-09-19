# Runtime Invariants and Evidence

## Scope
This document provides the definitive implementation and evidence matrix for the ACS Guardrail Demo. It acts as the source of truth for externally visible claims. It maps runtime invariant claims directly to implementation locations, enforcement mechanisms, and test evidence.

## Evidence Status Definitions

* **DEMONSTRATED**: The invariant is fully implemented and comprehensively verified by unit and integration tests.
* **PARTIAL**: The invariant is implemented with known limitations or lacks comprehensive adversarial testing.
* **NOT IMPLEMENTED**: The mechanism is explicitly out of scope, stubbed, or not supported by this demo.

## Runtime Invariant Matrix

| Invariant | Status | Implementation | Enforcement Mechanism | Evidence (Tests) |
| :--- | :--- | :--- | :--- | :--- |
| **JSON-RPC vs ACS validation boundary** | DEMONSTRATED | `src/schema-validator.ts` | First-pass JSON-RPC structural check throwing `-32600`, followed by ACS payload validation. | `tests/schema-validator.test.ts` (JSON-RPC layer suite) |
| **Request schema validation** | DEMONSTRATED | `src/schema-validator.ts` | `ajv` strict validation against vendored ACS v0.1.0 schemas. Unaddressable errors fail closed. | `tests/schema-validator.test.ts` |
| **Canonical HMAC-SHA256 request integrity** | DEMONSTRATED | `src/signature-service.ts` | Base64 strict decoding, JCS canonicalization minus `signature` key, `crypto.timingSafeEqual` over 32 bytes. | `tests/signature-service.test.ts` (Strict decoding tests) |
| **Response validate/sign/validate/verify** | DEMONSTRATED | `src/signature-service.ts`, `src/guarded-executor.ts` | `secureOutboundResponse` validates generated response against schema, signs it, and re-validates the signed envelope. | `tests/guarded-executor.test.ts` (M-03 suite) |
| **Replay protection** | DEMONSTRATED | `src/replay-guard.ts` | In-memory `Set` of observed `request_id`s within a strictly enforced `skewWindowMs` relative to `session_id`. | `tests/replay-guard.test.ts` |
| **ASK pause semantics** | DEMONSTRATED | `src/guarded-executor.ts` | Halt execution flow on `ask`, return `pending` status without invoking `ExecutionGate`. | `tests/guarded-executor.test.ts` (ASK branches) |
| **Immutable authenticated pending snapshot** | DEMONSTRATED | `src/guarded-executor.ts` | `JSON.parse(JSON.stringify())` deep clone of the validated request and decision before storing in `pendingActions`. | `tests/guarded-executor.test.ts` (H-01 immutable pending snapshot) |
| **Authenticated human ApprovalGrant** | DEMONSTRATED | `src/approval-verifier.ts` | Ed25519 signature verification over canonicalized `ApprovalGrantV1` payload matching expected `approverKeyId`. | `tests/execution-gate.test.ts`, `tests/guarded-executor.test.ts` |
| **ASK expiry** | DEMONSTRATED | `src/guarded-executor.ts` | `expiresAtMs` derived from `timeout_seconds`. Resumes block if `nowMs > expiresAtMs`. | `tests/guarded-executor.test.ts` (APPROVAL FRESHNESS suite) |
| **Single-use ExecutionPermit** | DEMONSTRATED | `src/execution-gate.ts` | Registry-based permit consumed from internal `WeakSet` prior to `toolFn` invocation. | `tests/execution-gate.test.ts` (H-02 permit suite) |
| **Request-gate DENY** | DEMONSTRATED | `src/guarded-executor.ts` | Evaluated policy throws immediately; no tool execution occurs. | `tests/guarded-executor.test.ts` |
| **Real tool execution** | DEMONSTRATED | `src/tools.ts`, `src/execution-gate.ts` | `toolFn(args)` executed asynchronously. `ExecutionGate` exclusively owns execution audit events. | `tests/audit.test.ts`, `tests/guarded-executor.test.ts` |
| **Sanitized tool failures** | DEMONSTRATED | `src/guarded-executor.ts` | Catch blocks intercept `Error`, safely mapping them to `exit_status: "failure"` and generic objects without leaking internal stacks. | `tests/guarded-executor.test.ts` |
| **toolCallResult generation** | DEMONSTRATED | `src/guarded-executor.ts` | Automatically generated wrapping the tool output/failure into an `AcsToolCallResultRequest` envelope. | `tests/guarded-executor.test.ts` |
| **Result-request HMAC verification** | DEMONSTRATED | `src/guarded-executor.ts` | Internally generated result request is routed through `SignatureService.verifyRequest`. | `tests/guarded-executor.test.ts` |
| **Session/request/tool result correlation** | DEMONSTRATED | `src/execution-correlation.ts` | Requires exact match of session_id + request_id_ref + executed tool name between the original request and the result. | `tests/execution-correlation.test.ts` |
| **Local strict request_id_ref profile** | DEMONSTRATED | `src/schema-validator.ts` | Post-schema validation enforcing `request_id_ref` existence, triggering addressable-deny on failure. | `tests/schema-validator.test.ts` (L-05 Local Strict Correlation Profile) |
| **Result Guardian** | DEMONSTRATED | `src/guardian.ts` | Sync/async policy evaluation over `outputs`, classifying results dynamically (e.g. `restricted`). | `tests/guardian.test.ts` |
| **Restricted-output withholding** | DEMONSTRATED | `src/guarded-executor.ts` | Post-execution DENY decision overrides output, returning a sanitized blocked message instead of raw data. | `tests/guarded-executor.test.ts` |
| **Session cleanup** | DEMONSTRATED | `src/guarded-executor.ts` | Explicit `GuardedExecutor.clearSession` clears ReplayGuard session state, pending ASK state, and ExecutionCorrelationStore state. | `tests/guarded-executor.test.ts` (session cleanup) |
| **In-memory event collection** | DEMONSTRATED | `src/audit.ts` | `AuditCollector` is an in-memory runtime demonstration event collector. | `tests/audit.test.ts` |
| **Runnable approval demo** | DEMONSTRATED | `examples/approval-demo.ts` | End-to-end executable TypeScript demo covering ASK, approval, and execution. | Validated via `npx ts-node examples/approval-demo.ts` |

## Mutation Evidence

Verified mutation testing scenarios confirming integration test coverage over security boundaries:

| Mutation | Component | Unit Caught? | Integration Caught? | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **ExecutionGate permit validation removal** | `ExecutionGate` | YES | YES | Bypassing internal ExecutionGate permit checks is caught by both unit and integration tests. |
| **GuardedExecutor correlation call-site removal** | `GuardedExecutor` (call site) | NO (relevant correlation-store unit) | YES | Bypassing correlation check allowed forged tool names / cross-session results. ExecutionCorrelationStore units pass, but integration flow caught it. |
| **GuardedExecutor result-withholding path** | `GuardedExecutor` | YES | YES | Allowing raw output to pass through a `deny` decision. Caught accurately by `guarded-executor.test.ts` unit tests and integration flow. |
| **ASK approval boundary** | `GuardedExecutor` | N/A | YES | Changing `ask` to execute directly bypassed pending snapshots. Caught by integration. |
| **GuardedExecutor request HMAC verify call-site** | `GuardedExecutor` (call site) | NO (SignatureService unit) | YES | Removing `verifyRequest` from `process()` call site passes `SignatureService` units, but integration tests fail immediately on forged requests. |

## Local Strict Profiles

This implementation deviates deliberately from upstream baseline leniency in specific documented ways:

1. **HKDF local profile**: Pending upstream ACS issue #118 clarification, this demo explicitly implements `HKDF-SHA256` with an empty salt for HMAC key derivation.
2. **request_id_ref local strict correlation profile**: While ACS v0.1.0 vendored schemas do not require `request_id_ref` on `toolCallResult`, this demo strictly requires it to perfectly match the originating request inside the same active session to prevent correlation hijacking.
3. **Human-only authenticated ApprovalGrant profile**: Approvals with `approver.type === "agent"` or `"service"` are explicitly rejected at runtime. Ed25519 payload signatures are securely verified, but browser/IdP-based human identity federation is not implemented.
4. **timeout_disposition: allow**: Deliberately unsupported. Any ASK decision specifying an `allow` fallback on timeout is immediately rejected.
5. **Restricted-output classification marker**: The Guardian uses a simplistic `classification === "restricted"` marker in JSON output to trigger withholding. This is a local demo policy, not a universal sensitive-data detection engine.

## Explicit Non-Claims

The following features, requirements, or mechanisms are **NOT IMPLEMENTED** and make no security claims in this repository:

* ACS-Core conformance certification
* Handshake / capability negotiation (e.g., `handshake/hello`)
* `MODIFY` and `DEFER` Guardian decisions
* Full `SessionContext` chain (only basic `session_id` routing is implemented)
* ACS-Trace pillar
* ACS-Inspect / AgBOM pillar
* ACS-Provenance profile (provenance signatures / structures are not validated)
* ACS-Crypto asymmetric ACS envelope signatures (only HMAC-SHA256 is supported)
* ACS-Audit pillar
* Persistent or tamper-evident cryptographic audit storage
* Browser / IdP human authentication flows (Ed25519 payload signatures are simulated)
* Network transport security (TLS / mTLS)
* Full-process compromise resistance (node environment/memory protection)

Note specifically on Audit: `AuditCollector` is an in-memory runtime demonstration event collector. It can be cleared, is non-persistent, is not cryptographically chained, is not ACS-Audit, and is not tamper-evident production storage.

## Verification Commands

To verify the current implementation invariants:

```bash
npm run typecheck
npm test
npm run verify
npx ts-node examples/approval-demo.ts
```
