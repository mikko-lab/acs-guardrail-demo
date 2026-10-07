# Authority revocation (A1)

This document specifies the explicit authority revocation added to `GuardedExecutor`. It covers revocation of an authority and its enforcement at the **request, approval, start and delivery** boundaries. It does **not** stop a running tool, fence a tool's in-flight side effects (commit), provide cancellation, or report terminal evidence; [cooperative containment (A2)](cooperative-containment.md) adds cancellation requests, a commit fence for runtime-mediated effects and terminal evidence for cooperating tools; it does not forcibly stop running code.

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
| Start | **Effective point: the call of the tool function.** Binding check inside `ExecutionGate.execute()` after every other step of the start path, including the `tool_execution_started` audit record, and immediately before the call; an earlier check before the permit is minted avoids creating execution state. Both the ALLOW and the approval path | `AuthorityRevokedError` (`stage: "start"`); the tool function is not called |
| Delivery | **Effective point: the fulfilment of the public `process()` / `resolveApproval()` promise with the result.** Binding check (`boundary: "api_return"`) after the method's last `await`, in its return statement; an earlier check in result processing (`boundary: "result_processing"`) avoids recording a delivery decision for already revoked authority | The result is returned as `exit_status: "blocked"` with `{ error: "Output withheld: authority revoked.", code: <reason> }`; raw output is not returned |

**Why these points.** A revocation can take effect from any synchronous callback on the path (an audit sink, a capability provider, a tool registry lookup, a Guardian) and from any Promise continuation that runs while the runtime awaits. A check is binding only if nothing of that kind can run between it and the protected effect:

- *Start.* After the binding check there is only the tool function call itself. The `tool_execution_started` record, the tool registry lookup and the argument unwrapping all happen before it, so a revocation from any of them prevents the call.
- *Delivery.* After the binding check there is only the `return` that fulfils the public promise; no callback runs and no `await` remains. A revocation that lands in any earlier Promise transition (while result processing, `executeAndProcessResult` or the method itself are suspended) is seen by the check. A revocation after the public promise is fulfilled does not recall the result; what a caller does with a returned result is outside the runtime.

**Audit events record decisions, not effects.** `tool_execution_started` records that the runtime is about to call the tool; it does not prove the call happened. `tool_result_delivered` records the runtime's delivery decision; it does not prove the hand-over, nor that an external consumer received the result. If a revocation takes effect during or after either record but before the effective point, the record is followed by `authority_revocation_enforced` (stage `start`, or stage `delivery` with `boundary: "api_return"`) and, for delivery, `tool_result_withheld`; the effect did not happen.

**In-flight executions.** A1 itself does not stop a tool that is already running when the revocation takes effect: it keeps running, A1 prevents none of its side effects, and those remain historical facts; A1 only withholds its result delivery. A2 adds a cancellation request and denies the tool's later commits through `ctx.commit()`; effects outside that commit fence are still not prevented. The receipt lists such executions and states `in_flight_side_effects: "not_prevented"`. With A2, a commit through the runtime commit fence (`ctx.commit()`) after the revocation is denied and a cooperating tool receives a cancellation request; `not_prevented` continues to describe every effect a tool performs outside the commit fence, and the receipt shape is unchanged.

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
| `authority_revocation_enforced` | Request id (request, approval, start) or the result request id (delivery) | `stage`, `decision: "deny"`, `reason` (`session_revoked` / `capability_revoked`), `revocation_id`, `session_id`, `capability_id` when known, `tool`; for delivery also `request_id_ref` and `boundary` (`result_processing` or `api_return`) |
| `tool_execution_blocked` | Request id | `reason` (`session_revoked` / `capability_revoked`, or the approval re-check reason) for request, approval and start denials |
| `tool_result_withheld` | Result request id | `tool`, `reason` for delivery denials |
| `capability_rejected` | Request id | `reason`, `stage: "approval"` for approval re-check failures; `capability_id_conflict` for id-binding conflicts |

No grant, signature or secret is written to the audit log. Session revocation is reported before capability revocation when both apply. Revocation enforcement is a control working as intended and is not classified as a security incident; both new events export to OCSF as generic Base Events through explicit metadata allowlists.

The audit stream is the runtime's own report. Test harnesses must observe tool side effects independently (for example through their own tool doubles).

**Audit failure.** If writing `authority_revoked` fails, the revocation stays in effect and the receipt reports `audit_recorded: false`. If writing enforcement evidence fails, the denial still happens.

## State, restart and clearSession

Revocation state lives in the memory of one `GuardedExecutor` instance. It is not persistent, not distributed and not shared between processes or executor instances; a process restart, or a new executor, forgets every revocation. `clearSession()` keeps its meaning (release of replay, correlation and pending state) and never removes a revocation: after `revoke` and `clearSession`, new requests and replays of earlier requests in that session are still denied. In sessions that were never revoked, replay and `clearSession` behaviour is unchanged.

## Not provided by A1

- Stopping a running tool, cancellation signals, or fencing a commit that a running tool performs, and terminal evidence for executions. A2 provides cancellation requests, a commit fence for runtime-mediated effects and terminal evidence for managed executions; see [cooperative-containment.md](cooperative-containment.md). Non-cooperating code and effects outside the commit fence remain uncontrolled.
- Tenant, agent or ancestor/descendant scopes; regrant.
- Persistent, distributed or cross-process revocation.
- A network endpoint or UI for revocation.
- Conformance to the `agent-control-evals` revocation-0.3.0 containment contract.
