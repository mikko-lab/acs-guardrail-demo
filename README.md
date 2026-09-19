# ACS Guardrail Demo — Phase 1 + Phase 2

**This project demonstrates selected ACS v0.1.0 control patterns. It does not claim ACS-Core conformance.**

This is a standalone, public demo of a deterministic Agent Control Standard (ACS) control flow. It proves how an external, deterministic guardian policy can mediate AI agent tool calls before they execute, blocking replays and stale requests, gating side-effects behind explicit human approval, and recording a minimal audit trail.

## Non-Goals & Limitations

This demo intentionally **DOES NOT** implement:
- Full ACS hook taxonomy
- Handshake / ServerHello negotiation
- HMAC envelope signatures
- Nonce replay detection (SHOULD in ACS §10.3; deferred)
- `modify` or `defer` decisions
- SessionContext
- Wrapped MCP
- ACS-Trace, ACS-Inspect / AgBOM, ACS-Provenance, ACS-Crypto, ACS-Audit

See the detailed crosswalk analysis in [docs/acs-crosswalk.md](./docs/acs-crosswalk.md).

## Purpose

To demonstrate a zero-dependency, local control flow that:

1. Checks requests for timestamp skew and session-scoped replay before policy evaluation.
2. Applies deterministic Guardian policy (ALLOW / DENY / ASK) without relying on LLM self-correction.
3. Enforces the execution gate: blocked requests never reach the tool implementation.
4. Records a minimal append-only audit trail of all lifecycle events.

## Architecture

```text
Untrusted parsed value
        ↓
JSON-RPC Protocol Validation
  — invalid JSON-RPC → -32600 Invalid Request
        ↓
ACS Schema Validation (Phase 3)
  — validate request-envelope and toolCallRequest payload
  — ACS-invalid but valid UUID request_id → local ACS DENY
  — unaddressable failures → typed Error
        ↓
HMAC Signature Verification (Phase 4)
  — verify request signature via HKDF session key
  — invalid signature → fail closed (-32004)
        ↓
ReplayGuard (Phase 2)
  — reject timestamp outside ±skewWindowMs
  — reject duplicate request_id within same session
        ↓
Request Guardian (Phase 1)
  — ALLOW: execute side effects
  — DENY: hard block, throw Error
  — ASK: pause and queue pending action for human approval
        ↓
ExecutionGate
  — Tool executes, side effects occur
        ↓
Result Gate (Phase 5)
  — Generated steps/toolCallResult goes through Schema & HMAC validation
  — Replay & Correlation check (request_id_ref bound to session)
  — Result Guardian: Evaluates output
  — ALLOW: delivers output
  — DENY: withholds output, returns safe blocked payload (side effects NOT undone)
        ↓
GuardedExecutor branches:
  — DENY blocks unconditionally
  — ALLOW executes immediately
  — ASK stores the exact request as a pending action
        ↓
(Later, for ASK decisions)
Human approval matches session_id + request_id
        ↓
Execution gate resumes SAME action
        ↓
Tool executes or does not execute
        ↓
AcsToolCallResult + minimal audit evidence
```

## Runtime Schema Validation (Phase 3)

The project implements a strict separation of protocol validation and schema validation boundaries:

1. **JSON-RPC Protocol Validation:** Validates the base JSON-RPC 2.0 object shape. Invalid requests immediately return `-32600 Invalid Request` without creating ACS dummy envelopes. JSON parse errors (`-32700 Parse error`) are considered out of scope for this layer and belong to the future transport boundary.
2. **ACS Schema Validation:** Validates both the `request-envelope` and `toolCallRequest` payloads using Ajv (Draft 2020-12).
3. **Fail Closed & Strict Correlation:** If an ACS-invalid request contains a valid UUID in `params.request_id`, the system produces a local ACS-shaped `DENY` decision. If no valid UUID exists, it throws a typed schema error and refuses to fabricate a UUID. *This intentionally avoids the behavior tracked in upstream ACS issue #163. JSON-RPC structural validation is performed before ACS validation. JSON-RPC params may be omitted; ACS request schemas then enforce the ACS-specific params object.*
4. **Outbound Defensive Checks:** Guardian responses are also checked against `response-envelope.json` before ExecutionGate accepts them.
5. **Pinned Schemas:** Schemas are pinned locally to a specific ACS v0.1.0 upstream commit.
6. **No ACS-Core Conformance Claim:** Do not call this full ACS interoperability.

## Envelope Integrity (Phase 4)

- **ACS §10-Oriented HMAC Integrity:** The demo implements envelope-level integrity using HMAC-SHA256. 
- **JCS Canonicalization:** Signatures bind the complete ACS envelope. The *entire* envelope (request or response), excluding only the nested `signature` field itself, is deep-cloned and canonicalized using exact RFC 8785 JSON Canonicalization Scheme (via the `json-canonicalize` package) before signing. This guarantees that top-level fields like `jsonrpc` and `id` are inextricably bound to the payload MAC.
- **Verification Ordering:** Request verification occurs *after* schema validation but *before* replay protection and policy evaluation, guaranteeing that invalid signatures cannot poison the replay state.
- **Outbound Responses Signed & Verified:** All ACS decision responses emitted by GuardedExecutor, including local addressable schema-deny responses, cross the same outbound validate/sign/validate/verify integrity boundary. JSON-RPC protocol errors are not ACS decision envelopes and are not signed through this ACS response path.
- **Local HKDF Profile (Issue #118):** ACS v0.1.0 requires a per-session HKDF-derived HMAC key, but the exact HKDF interoperability parameters remain underspecified (tracked in upstream issue #118). Therefore, this demo uses an explicitly documented **local derivation profile**:
  - `HKDF-SHA256`
  - Empty salt
  - UTF-8 `session_id` as the HKDF `info` parameter
  - 32-byte derived key length
  - Root key provided via deployment configuration
- **Warning:** Because of the ambiguity in upstream #118, this profile does not claim normative ACS-Core interoperability. It serves as a strict structural demonstration of the authenticated envelope boundary.

## Demo Policies

1. **`read_record`**
   - Read-only action. Guardian decides `allow`. Executes exactly once.
2. **`update_record`**
   - Side-effect action. Guardian decides `ask`. Requires explicit human approval bound to the exact `request_id` before execution.
3. **Unknown tools**
   - Fallback. Guardian decides `deny`. Never executes.

## Replay Protection (Phase 2 — ACS §10.3)

- **Timestamp validation:** requests whose `timestamp` falls outside ±`skewWindowMs` (default 300 000 ms / 5 min) are rejected with `TIMESTAMP_OUT_OF_WINDOW` (ACS error code `-32006`) before Guardian evaluation.
- **Session-scoped request_id deduplication:** duplicate `request_id` values within the same `session_id` are rejected with `REPLAY_DETECTED` (ACS error code `-32005`). The same `request_id` in a **different** session is not a replay.
- **Duplicate `request_id` protection is maintained for the in-memory lifetime of each session.** State is not time-pruned within an active session — a replay carrying a fresh timestamp is still rejected hours after the original.
- **Session cleanup is explicit in this demo.** Call `GuardedExecutor.clearSession(sessionId)` when a session ends to release memory. `clearSession` synchronously clears both replay state and pending approval state for the selected in-memory session. A production deployment should wire this to ACS `sessionEnd` events backed by a persistent store. This demo implements in-memory session lifecycle only; full ACS sessionStart/sessionEnd handling remains out of scope.
- **Skew window is locally configured**, not negotiated via an ACS handshake (handshake not implemented).
- **Nonce replay detection is not implemented** (SHOULD in §10.3; deferred to a future phase).
- **ACS-Core conformance is not claimed.**

### Mandatory enforcement boundary

`GuardedExecutor` is the single public entry point for processing requests. It wires `ReplayGuard → Guardian → ExecutionGate` in a non-bypassable sequence. A request that fails the replay/timestamp check structurally cannot reach Guardian policy evaluation or the tool implementation.

```text
GuardedExecutor.process(request)
  1. ReplayGuard.check(request)    ← throws on violation; stops here
  2. Guardian.evaluate(request)    ← only reached on clean requests
  3. ExecutionGate.execute(...)    ← only reached on allowed requests
  OR PendingAction store           ← paused for ASK decisions
```
- **Security ordering:** timestamp is validated before `request_id` is recorded. A stale or future-skewed request cannot "poison" a valid `request_id`.

> **ACS field naming note:** The ACS v0.1.0 response envelope names the verdict field **`decision`**, not `disposition`. Vocabulary values are `allow`, `deny`, `ask`, `modify`, `defer`. This demo uses the correct ACS field names throughout.

## Human Approval (`ask` decision)

Approval cannot be manufactured by the Guardian or the AI agent.

- `ASK` pauses an already accepted request without executing the tool.
- **ACS requirement:** Approver authentication is required.
- **Local implementation:** Approval grants are authenticated using an out-of-band Ed25519 approval authority configured by public key.
- **Explicit limitation:** This local profile supports authenticated human approval grants only. Human identity authentication itself remains out of band; the runtime verifies a cryptographic grant from the configured approval authority.
- **Expiry:** ASK expiry is strictly enforced. The timeout boundary uses strict `>` semantics (expires when `elapsedMs > timeout_seconds * 1000`).
- **Fail Closed:** This local human-approval profile fails closed on timeout. `timeout_disposition: allow` is deliberately unsupported and will cause the local profile to reject the ASK immediately.
- Pending ASK actions are stored as independent authenticated snapshots. Approval resumes the verified snapshot using `resolveApproval(grant)`, consuming the pending state.

## Security Properties Demonstrated

| Property | Phase |
|---|---|
| Deterministic Guardian policy | 1 |
| Execution gate: decision honoring | 1 |
| Unknown tools never execute | 1 |
| ASK blocks without approval | 1 |
| Approval bound to exact request_id | 1 |
| Audit trail of all lifecycle events | 1 |
| Timestamp skew rejection | 2 |
| Session-scoped replay detection | 2 |
| Stale/future requests never reach tool | 2 |
| Timestamp failure does not poison request_id | 2 |

## Usage

### Run Tests
```bash
npm install
npm test
```

### Typecheck
```bash
npm run typecheck
```

### Verify (typecheck + tests)
```bash
npm run verify
```

### Run Demo
```bash
npx ts-node examples/approval-demo.ts
```

## Result Gate & Output Delivery (Phase 5)

The execution boundary implements a two-sided security model separating request approval from output delivery:
- **Request Gate**: Controls whether the tool may run (and whether side effects may occur). A request-gate DENY strictly prevents execution.
- **Execution Permit**: ExecutionGate does not trust raw Guardian decision objects. GuardedExecutor owns the runtime authority used to mint permits for its ExecutionGate instance. Tool execution requires an internal single-use permit, minted only after verified ALLOW or approved pending ASK.
- **ASK Action Snapshots**: Pending ASK actions are stored as independent authenticated snapshots. Approval resumes the verified snapshot, not the caller-owned request object.
- **Result Gate**: Controls whether the tool's output may reach the agent. A result-gate DENY does NOT undo side effects (which have already happened) but firmly withholds the restricted output.
- **Strict Output Boundary**: Output is never exposed before Result Guardian approval. If denied, a safe blocked payload is delivered instead of raw output. Sensitive output is carefully scrubbed and never leaked into Audit logs, error messages, or reasoning text.
- **Correlation Profile (Issue #118)**: ACS \`request_id_ref\` correlation uses a local strict profile because upstream ACS issue #118 leaves unresolved-reference semantics underspecified. This demo requires \`request_id_ref\` to perfectly match the originating request inside the same active session.
