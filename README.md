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
Agent requests toolCallRequest
        ↓
ReplayGuard (Phase 2)
  — reject timestamp outside ±skewWindowMs
  — reject duplicate request_id within same session
        ↓
Guardian evaluates deterministic policy
  — ALLOW / DENY / ASK
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
- Approval resumes that exact pending action via `GuardedExecutor.approve(sessionId, requestId)`.
- The original `request_id` is preserved for correlation. No second `toolCallRequest` is generated.
- Replay protection applies to incoming hook requests, not to the local approval-resume transition.
- Full ACS approval transport semantics are still out of scope.

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
npx ts-node src/demo.ts
```
