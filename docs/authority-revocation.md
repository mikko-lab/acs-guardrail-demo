# Authority revocation (A1)

This document specifies the explicit authority revocation added to `GuardedExecutor`. It covers revocation of an authority and its enforcement at the **request, approval, start and delivery** boundaries. It does **not** stop a running tool, fence a tool's in-flight side effects (commit), provide cancellation, or report terminal evidence; those are separate, later work.

## Targets and identity

| Scope | Target object | Identity |
|---|---|---|
| Capability | `{ "scope": "capability", "capability_id": "<id>" }` | The `capability_id` of a signed, verified `CapabilityGrantV1` |
| Session | `{ "scope": "session", "session_id": "<id>" }` | The authenticated request `metadata.session_id` (which a valid capability is bound to) |

No other scope is supported. Tenant, agent and ancestor/descendant revocation are not modelled (`tenant_id` is a reserved wire field without isolation rules, and capabilities have no parent). Unknown scopes, empty or oversized identifiers and extra fields are rejected with `RevocationTargetError` and change nothing.

**Capability identity binding.** A `capability_id` is not a nonce: the same signed grant may be presented repeatedly while it is valid. To keep a revocation of an id unambiguous, the runtime binds every `capability_id` to the content of the first verified grant it sees with that id (all signed fields except the signature). A later grant with the same id but different content is rejected (`capability_rejected`, reason `capability_id_conflict`) before Guardian evaluation. A provider that issues a new grant with a **new** `capability_id` issues a new authority; revoking the session is the way to cut every capability of a session.

## API and trust boundary

`GuardedExecutor.revoke(target): RevocationReceiptV1` is a synchronous runtime API for the trusted integrator that owns the executor instance. It is not reachable through `process()` or `resolveApproval()`: agent requests can only issue `steps/toolCallRequest` messages, and a tool call named like the operation is an ordinary, denied request.

## Effective boundary

A revocation takes effect when `revoke()` records it in the registry, before it returns. Every check performed afterwards by the same executor denies the authority:

| Boundary | Where | Outcome when revoked |
|---|---|---|
| Request | `process()`: session check right after replay/timestamp checks and before capability resolution; capability check right after capability verification and before Guardian evaluation | `AuthorityRevokedError` (`stage: "request"`); no capability resolution for a revoked session |
| Approval | `resolveApproval()` after the grant is verified and the pending action is consumed, before `human_approval` is recorded | `AuthorityRevokedError` (`stage: "approval"`); the pending action is gone |
| Start | Immediately before the execution permit is minted and the tool is invoked, on both the ALLOW and the approval path | `AuthorityRevokedError` (`stage: "start"`); the tool is not invoked |
| Delivery | Result processing, synchronously immediately before the result is returned to the caller of `process()` / `resolveApproval()` | The result is returned as `exit_status: "blocked"` with `{ error: "Output withheld: authority revoked.", code: <reason> }`; raw output is not returned and `tool_result_delivered` is not recorded |

There is no asynchronous boundary between the start check and the tool invocation, and none between the delivery check and the return of the result from the runtime's result processing. The delivery boundary is the runtime's return of the result; what a caller does with an already returned result is outside the runtime. A revocation after the result was returned does not recall it. The `tool_result_delivered` audit event records the runtime's own delivery decision; it does not prove that an external consumer received the result.

**In-flight executions.** A tool that is already running when the revocation takes effect keeps running. Its side effects (including a commit after the revocation) are not prevented and remain historical facts; only its result delivery is withheld. The receipt lists such executions and states `in_flight_side_effects: "not_prevented"`.

## Approval re-check

`resolveApproval()` re-checks the authority the pending action was created under, as three separate checks bound to the original pending request:

1. **Runtime revocation** of the pending request's session and of its original `capability_id` (`authority_revocation_enforced`, `stage: "approval"`).
2. **Current validity of the original capability**: signature, validity window, agent, session and tool are verified again at approval time (`capability_rejected`, `stage: "approval"`, e.g. `capability_expired`).
3. **Provider withdrawal**: the capability provider must still resolve a valid capability for the identical agent/session/tool context (`missing_capability`, `capability_provider_error`, or a verification reason). The capability returned here is evidence that the context is still authorized; it never replaces the original authority (no regrant contract is defined), it is itself checked against the revocation registry and the id binding, and the execution stays bound to the original `capability_id`.

The pending action is consumed before these checks, so an authority failure at approval is final for that pending action.

**Behaviour change.** Before A1, an approval executed on the strength of the request-time capability check alone. Now an approval whose original capability has expired by the time of approval, or whose provider no longer resolves a capability, does not execute. The pending timeout keeps its strict `elapsed > timeout` rule; the capability keeps the verifier's `now >= expires_at` rule. The two boundaries are independent: an approval at exactly the pending timeout executes if the capability is still valid, and an approval at exactly `expires_at` is rejected even though the pending action is still valid.

## Receipt

```json
{
  "version": 1,
  "revocation_id": "session:<session_id>",
  "target": { "scope": "session", "session_id": "<session_id>" },
  "status": "revoked",
  "effective_sequence": 1,
  "effective_at": "<runtime clock time of the first revocation>",
  "enforced_at": ["request", "approval", "start", "delivery"],
  "pending_approvals": ["<request_id>"],
  "in_flight_executions": ["<request_id>"],
  "in_flight_side_effects": "not_prevented",
  "persistence": "in_memory_single_runtime_instance",
  "audit_recorded": true
}
```

`revocation_id` is `<scope>:<id>`. `effective_sequence` is a registry-local, strictly increasing order of first revocations; `effective_at` uses the executor's injected clock.

**Duplicates** are idempotent: the status is `already_revoked` and the original `revocation_id`, `effective_sequence` and `effective_at` are reported; the authority stays revoked. There is no un-revoke and no regrant.

## Audit evidence

| Event | `request_id` | Metadata |
|---|---|---|
| `authority_revoked` | `revocation_id` | `revocation_id`, `scope`, `session_id` or `capability_id`, `status`, `effective_sequence`, `effective_at`, `pending_approvals` (count), `in_flight_executions` (count) |
| `authority_revocation_enforced` | Request id (request, approval, start) or the result request id (delivery) | `stage`, `decision: "deny"`, `reason` (`session_revoked` / `capability_revoked`), `revocation_id`, `session_id`, `capability_id` when known, `tool`, and `request_id_ref` for delivery |
| `tool_execution_blocked` | Request id | `reason` (`session_revoked` / `capability_revoked`, or the approval re-check reason) for request, approval and start denials |
| `tool_result_withheld` | Result request id | `tool`, `reason` for delivery denials |
| `capability_rejected` | Request id | `reason`, `stage: "approval"` for approval re-check failures; `capability_id_conflict` for id-binding conflicts |

No grant, signature or secret is written to the audit log. Session revocation is reported before capability revocation when both apply. Revocation enforcement is a control working as intended and is not classified as a security incident; both new events export to OCSF as generic Base Events through explicit metadata allowlists.

The audit stream is the runtime's own report. Test harnesses must observe tool side effects independently (for example through their own tool doubles).

**Audit failure.** If writing `authority_revoked` fails, the revocation stays in effect and the receipt reports `audit_recorded: false`. If writing enforcement evidence fails, the denial still happens.

## State, restart and clearSession

Revocation state lives in the memory of one `GuardedExecutor` instance. It is not persistent, not distributed and not shared between processes or executor instances; a process restart, or a new executor, forgets every revocation. `clearSession()` keeps its meaning (release of replay, correlation and pending state) and never removes a revocation: after `revoke` and `clearSession`, new requests and replays of earlier requests in that session are still denied. In sessions that were never revoked, replay and `clearSession` behaviour is unchanged.

## Not provided by A1

- Stopping a running tool, cancellation signals, or fencing a commit that a running tool performs.
- Terminal evidence for executions.
- Tenant, agent or ancestor/descendant scopes; regrant.
- Persistent, distributed or cross-process revocation.
- A network endpoint or UI for revocation.
- Conformance to the `agent-control-evals` revocation-0.3.0 containment contract.
