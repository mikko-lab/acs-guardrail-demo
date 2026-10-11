# Approval–permit lifecycle (permit mode, G3/G4)

This document specifies the runtime's opt-in **permit mode**: an approval/permit lineage per approved request, with separate `approve`, `issuePermit` and single-use `start` operations. It implements the approved design plan `agent-control-evals` `docs/revocation/approval-permit-lifecycle-plan.md` @ `2e459adf5e334d83aff925b203e0b3e3fff48678` (recommendations D1–D20). Section numbers in brackets (§5.4) refer to that plan.

Legacy mode stays the default and is unchanged (§12 below).

Implementation: `src/approval-lifecycle.ts` (lineage record, digests, comparators, snapshots) and the lifecycle section of `src/guarded-executor.ts`. Tests: `tests/approval-lifecycle.test.ts` (L1–L16 and the transition table) and `tests/approval-lifecycle-components.test.ts` (component tests).

## 1. Three separate things

| Concept | Where | Never |
|---|---|---|
| **Authority validity**: the verified grant chain, within its validity windows, first-seen bound, covered by no revocation | `CapabilityGrantVerifier`, `AuthorityRevocationRegistry` | granted by a human; undone |
| **Human approval** of one concrete request under one authority snapshot | the lineage's approval part | makes revoked or invalid authority valid |
| **Permit use right**: the runtime's single-use right to start exactly one execution of the approved request | the lineage's permit part | a bearer credential; a substitute for authority validity |

Every operation re-checks authority validity at its own effective point. Approval and permit are added conditions, never replacements.

## 2. Enabling permit mode

```ts
const executor = new GuardedExecutor(schema, signatures, replayGuard, guardian, audit, correlation,
  approvalVerifier, clock, approvalFutureSkewMs, provider, verifier,
  { lifecycle: "permit", permitTtlMs: 60_000, policyApprovalTtlMs: 300_000 });
```

- The 12th constructor argument is optional. `lifecycle` defaults to `"legacy"`.
- The mode is independent of tenancy mode (D11). The eval pin uses both.
- `GuardedExecutor<M>` carries the mode as a type parameter, inferred from the options. A permit-mode executor's `process()` has the result type `PermitProcessResult`; a legacy executor keeps `ProcessResult` unchanged.
- `permitTtlMs` (default 60 s) is the permit lifetime from issuance, capped by the end of the chain's validity window (D16).
- `policyApprovalTtlMs` (default 300 s) is the approval lifetime of a lineage approved by policy (Guardian ALLOW), which has no `ask_details` timeout. A human approval's lifetime is `ask_details.timeout_seconds`, as in legacy mode.

## 3. API

| Operation | Signature | Notes |
|---|---|---|
| Create | `process(signedRequest)` → `{ status: "pending" \| "approved", lineage_id, audit_recorded }` | Guardian ASK → `pending`; ALLOW → `approved` (approver `{ type: "policy", id: "guardian" }`); DENY or any failed check throws, no lineage. Never starts a tool (D1). |
| Approve | `approve(grant: ApprovalGrantV3)` → `ApprovalReceipt` | synchronous |
| Reject | `reject(grant: ApprovalGrantV3 with decision "reject")` → `RejectionReceipt` | synchronous |
| Issue | `issuePermit({ lineage_id })` → `PermitReceipt { lineage_id, permit_id, issued_seq, expires_at, audit_recorded }` | synchronous |
| Start | `start({ lineage_id, request: freshSignedRequest })` → `Promise<StartResult>` | synchronous up to and including the tool call |
| Revoke | `revoke(target)` | unchanged; in permit mode the receipt adds `pending_lineages`, `approved_lineages`, `unused_permits` and `enforced_at` includes `issue` |
| Read | `getLineage(id)`, `lineages()` → deep-frozen `LineageSnapshot` copies; `authoritySequence()` | |

In permit mode `resolveApproval()` throws `LifecycleModeError`. In legacy mode `approve`, `reject`, `issuePermit`, `start`, `getLineage` and `lineages` throw `LifecycleModeError` (D3).

### 3.1 `ApprovalGrantV3`

`ApprovalGrantV2` plus three signed fields: `lineage_id`, `request_digest` and `authority_fingerprint` (D9). `ApprovalGrantVerifier.verifyV3()` checks the signature, the lineage, the session, the original request id, the tool, both digests (lowercase hex SHA-256) and the approver identity from the lineage's `ask_details`. A V3 grant names one lineage and cannot be replayed on another; a V2 grant is rejected in permit mode.

- `request_digest` = SHA-256 of the RFC 8785 canonical JSON of `{ agent_id, session_id, tool, arguments }` of the original request (`arguments` exactly as the request carries them, `{ name: { value } }`).
- `authority_fingerprint` = SHA-256 of the canonical JSON array of the content fingerprints of the leaf grant and its ancestors, leaf first.

Both values are in the lineage snapshot's `bindings`, so the approval UI shows and signs exactly what the lineage binds. `approve()` additionally checks `issued_at` freshness as legacy mode does (not before the lineage's creation, not beyond the future skew).

### 3.2 The lineage snapshot

```
{ lineage_id, state,                       // pending | approved | issued | consumed | rejected | approval_expired | permit_expired
  bindings: { agent_id, session_id, tenant_id?, tool, arguments_digest, capability_id, ancestor_capability_ids,
              request_id, request_digest, authority_fingerprint },
  approval: { state, approver, created_seq, created_at, expires_at, approved_seq?, decided_at? },
  permit:   { state, permit_id?, expires_at?, issued_seq?, consumed_seq?, execution_id?, start_request_id? },
  covered_by: { revocation_id, reason } | null }
```

- The bindings are copied and deep-frozen in `process()` right after the chain is verified and bound, before the first callback (the `capability_verified` audit, the Guardian, the `guardian_decision` audit). No callback can change what a lineage binds.
- Revocation is not a lifecycle state. `covered_by` is derived from the registry at read time.
- All `*_seq` values and `revoke()`'s `effective_sequence` come from **one** monotonic authority sequence (D13), so approvals, issues, consumptions and revocations are totally ordered by their effective points. `authoritySequence()` reads its current value.
- Expiry is evaluated by operations and recorded by them (D8). A read never changes state.

## 4. Lifecycle and transitions

```
 pending ──approve──► approved ──issue──► issued ──start (final guard)──► consumed
    │ reject → rejected            │                  │ start after permit_expires_at → permit_expired
    │ approve after expiry → approval_expired          
                                   │ issue after approval expiry → approval_expired
```

| # | From | Operation | Decision | New state |
|---|---|---|---|---|
| T1 | — | `process` ASK, all checks and the creation fence pass | ALLOW | `pending` |
| T2 | — | `process` ALLOW | ALLOW | `approved` (policy) |
| T3 | — | `process` DENY or a failed check | DENY | none |
| T3a | — | revocation or chain expiry in a callback after verification | DENY `revoked` (stage `request`, check `final`) / `capability_expired` | none |
| T4 | `pending` | `approve`, all fences pass | ALLOW | `approved` |
| T5 | `pending` | `approve` after `approval.expires_at` | DENY `approval_expired` | `approval_expired` |
| T6 | `pending` | `approve`, revoked | DENY `revoked` | unchanged |
| T7 | `pending` | `approve`, grant invalid, chain changed, provider error | DENY | unchanged |
| T8 | `pending` | `reject`, grant valid | ALLOW | `rejected` |
| T9 | not `pending` | `approve` / `reject` | DENY `not_pending` | unchanged |
| T10 | `approved` | `issuePermit`, all fences pass | ALLOW | `issued` |
| T11 | `approved` | `issuePermit`, revoked | DENY `revoked` (stage `issue`) | unchanged |
| T12 | `approved` | `issuePermit`, chain changed, provider error, approval expired | DENY | unchanged (`approval_expired` recorded when expired) |
| T13 | not `approved` | `issuePermit` | DENY `not_approved` | unchanged |
| T14 | `issued` | `start`, R′ valid, bindings equal, fences pass at the early check and at the final guard | ALLOW | `consumed` |
| T15 | `issued` | `start`, revoked | DENY `revoked` | `issued` |
| T16 | `issued` | `start`, binding mismatch, chain changed, R′ invalid or replayed | DENY | unchanged |
| T17 | `issued` | `start` after `permit.expires_at` | DENY `permit_expired` | `permit_expired` |
| T18 | `consumed` | `start` | DENY `permit_consumed` | unchanged |
| T19 | `pending`, `approved`, `rejected`, `approval_expired` | `start` | DENY `permit_not_issued` | unchanged |
| T20 | any | `revoke` covering it | ALLOW (receipt) | unchanged; listed by state in the receipt |
| T21 | `consumed` | the tool throws, a fence withholds commit or delivery | (the start was ALLOW) | `consumed` |
| T22 | — | unknown `lineage_id` | DENY `unknown_lineage` | — |

- No operation is idempotent except `revoke()`: a second `approve` is `not_pending`, a second `issuePermit` `not_approved`, a second `start` `permit_consumed`.
- A denied operation never changes lifecycle state, except an expiry it observed (T5, T12, T17) (D7). Unlike legacy `resolveApproval()`, a failed approval fence does not destroy the pending lineage.
- An error after an effective point never undoes it: an audit sink that throws after a transition sets `audit_recorded: false` in the receipt or result.
- A reject does not check revocation or validity: it only removes authority.

### 4.1 Errors

- Revocation: `AuthorityRevokedError` with `stage` (`request`, `approval`, `issue`, `start`) and, in permit mode, `check` (`early` or `final`).
- Every other lifecycle denial: `LifecycleDeniedError { stage, reason, lineage_id, detail }`, `stage` ∈ `create`, `approval`, `issue`, `start`. Reasons: `not_pending`, `not_approved`, `permit_not_issued`, `permit_consumed`, `approval_expired`, `permit_expired`, `unknown_lineage`, `approval_verification_failed` (with `detail.sub_reason`, for example `request_digest_mismatch` or `decision_mismatch`), `chain_snapshot_mismatch`, `lineage_binding_mismatch` (with `detail.field`; `qualifiedReason` gives `lineage_binding_mismatch:tool`), `malformed_lifecycle_call`, `tenant_mismatch`, `missing_capability`, `session_tenant_conflict` and the capability reasons (`capability_expired`, `capability_not_yet_valid`, `capability_session_mismatch`, `capability_agent_mismatch`, `capability_provider_error`, ...).
- Wrong mode: `LifecycleModeError`.
- Schema, signature and replay failures of a start request R′ throw the same errors as `process()`.

## 5. Security semantics

### 5.1 Binding comparisons per operation

| Binding | `approve` / `reject` | `issuePermit` | `start` (fresh request R′) |
|---|---|---|---|
| `lineage_id` | grant = lineage | names it | names it |
| original `request_id`, `request_digest`, `authority_fingerprint`, approver | grant = lineage | — | not compared |
| `session_id`, `agent_id` | grant session = lineage; provider context | provider context | R′ = lineage, field by field |
| `tenant_id` | re-resolved leaf = lineage | re-resolved leaf = lineage | verified leaf for R′ = lineage; R′'s own claim = verified tenant (`tenant_mismatch`) |
| chain snapshot (leaf and ancestors, by content fingerprint) | provider answer for the original context | same | provider answer for R′'s context — the only authority comparison at start |
| tool, `arguments_digest` | grant tool; arguments through `request_digest` | — | R′ = lineage, field by field |

- **Strict snapshot comparison.** The provider's raw answer must carry exactly the lineage's leaf and ancestors, compared by content fingerprint before verification. Unlike legacy approval, a grant without ancestors is compared too: a re-issued grant for the same context is another authority. A thenable, a Proxy, a different length or a member without a computable fingerprint does not match (fail closed, §5.8).
- **The fresh start request.** R′ is a new signed tool-call request: schema, signature and the replay guard apply, so re-using the original `request_id` is a replay. R′'s `request_id` becomes the gate permit's `requestId` and the lineage's `start_request_id` (D18).
- **Field-by-field start comparison** (D17). The order is session, agent, tenant, tool, arguments. `request_digest` is not recomputed at start.
- **The execution authority** of a start is always the lineage's snapshot A (session, leaf `capability_id`, tenant, ancestor ids), never the provider's answer for R′. The commit fence, both delivery checks and the cancellation fan-out therefore check A.

### 5.2 Effective points and final fences

Every operation has one binding effective point: a synchronous check-and-set after the operation's last integrator callback, with no callback and no Promise turn between the final fence and the transition. The final fence F(op) checks, on the executor clock, in order:

1. revocation of every bound scope (session, leaf, ancestors, tenant);
2. chain validity: every member's window contains the clock (`capability_expired` / `capability_not_yet_valid`);
3. the operation's own expiry (none at creation; `approval.expires_at` at approve and issue; `permit.expires_at` at start);
4. the state check-and-set.

Order of checks (⟲ = integrator callback):

- **create** (`process()`): schema, signature, replay; request-stage revocation (session, bound tenant); ⟲ provider; chain verification and binding; request-stage revocation (capability, ancestors, tenant); bindings frozen; ⟲ `capability_verified` audit; ⟲ Guardian; ⟲ `guardian_decision` audit; **F(create)** → lineage; ⟲ `approval_requested` (or `approval_granted` for policy).
- **approve**: lineage and state; V3 grant verification (⟲ audit on failure); early revocation; snapshot-chain validity; ⟲ provider; snapshot comparison; verification and binding; **F(approve)** → `approved`; ⟲ `approval_granted`.
- **reject**: lineage and state; V3 grant verification; state still `pending` → `rejected`; ⟲ `human_rejection`.
- **issue**: lineage and state; early revocation; snapshot-chain validity; ⟲ provider; snapshot comparison; verification and binding; **F(issue)** → `issued`; ⟲ `permit_issued`.
- **start**: lineage; R′ schema, signature, replay; ⟲ `tool_call_requested`; request-stage revocation (session, bound tenant); ⟲ provider for R′'s context; snapshot comparison; verification, tenant claim and binding; request-stage revocation (capability, ancestors, tenant); ⟲ `capability_verified`; binding comparisons of R′; early lineage-state check; early start revocation of A (`check: "early"`); correlation and gate permit; gate entry; ⟲ `tool_execution_started`; **inside the gate's final guard: F(start) (`check: "final"`) → `consumed`, `consumed_seq`, `start_request_id` → managed execution → tool function call.**

An operation's own expiry is checked only in its final fence, so the early checks never mask it. A revocation, a clock advance or a re-entrant call in any callback before an effective point is seen by that operation's final fence.

### 5.3 Revocation of pending approvals and unused permits

| Lineage state at the revocation | Effect (every scope: capability with descendants, session, tenant) | Receipt list |
|---|---|---|
| `pending` | approve, issue and start DENY | `pending_lineages` |
| `approved` | issue and start DENY | `approved_lineages` |
| `issued` (unused) | start DENY; the permit stays `issued` and is never usable again | `unused_permits` |
| `consumed`, running | existing containment: commit and delivery fences, cancellation request | `in_flight_executions` |
| `consumed`, terminal | historical effects stay | — |

No lifecycle step revives a revoked lineage. A new `process()` for the same revoked authority is denied at the request stage, or at the creation fence when the revocation happened in a callback after the request-stage checks.

### 5.4 Single use

- The lineage permit is consumed only at the start effective point, inside the gate's final guard (D6, no reservation). The early state check is fail-fast only.
- JavaScript runs one synchronous segment at a time, so of any number of concurrent or re-entrant starts on one lineage exactly one passes the final guard; the others are DENY `permit_consumed` (D14). This covers `Promise.all`, re-entry from an audit sink, from the provider and from the running tool.
- A start that fails before the effective point (invalid or replayed R′, binding mismatch, revocation, expiry, a throwing provider or audit sink) leaves the permit unchanged. A start that passed it keeps the permit `consumed`, also when the tool throws or its result is withheld.
- `ExecutionGate`'s per-request permit is unchanged and still required; it binds the execution to R′, the lineage permit binds it to one approval.

### 5.5 Evidence rules

An audit record (`approval_granted`, `permit_issued`, `tool_execution_started`, ...) shows that a code path ran, never that a transition happened or that a tool was called. Evidence of a lifecycle effect is the lineage snapshot (states, `*_seq`); evidence of a tool call is the tool's own invocation. Forged audit records change nothing.

## 6. Audit and OCSF

New audit event types: `approval_granted`, `permit_issued`, `permit_expired`, `lifecycle_operation_denied`. Existing events gain `lineage_id` in permit mode (`tool_call_requested`, `capability_verified`, `approval_requested`, `approval_expired`, `approval_verification_failed`, `human_rejection`, `authority_revocation_enforced`, which also gains `check`), and `authority_revoked` gains the counts `pending_lineages`, `approved_lineages`, `unused_permits`. The OCSF metadata allowlists list exactly these keys; `approver_id` stays excluded.

## 7. Limits

- Lifecycle state is in memory for one executor instance, like revocation; nothing persists across a restart.
- `clearSession()` does not change lineages (it releases replay and correlation state only).
- Oversight metrics (`src/oversight-metrics.ts`) count `human_approval` / `human_rejection`; permit-mode approvals (`approval_granted`) are not yet counted there.
- The runtime-test mutant gate for the lifecycle (plan §8.2, M53–M71) is a separate, later step; this change carries the deterministic tests and component tests only. Component tests (session, agent and tenant comparisons; the execution authority source) are component check-point evidence, not production-path containment evidence. The final fence's chain-validity check at approve and issue is masked by the verification of the provider's answer that directly precedes it (plan §8.2 M70): no test separates it there.
- No full ACS conformance or certification claim.

## 8. Compatibility

- Legacy mode is the default and unchanged: `process()`, `resolveApproval()`, `ProcessResult`, V2 grants, audit events and the revocation receipt (no lifecycle lists, `enforced_at` without `issue`).
- Additive API: the optional 12th constructor argument; `GuardedExecutor<M>` (default `"legacy"`); `approve`, `reject`, `issuePermit`, `start`, `getLineage`, `lineages`, `authoritySequence`, `lifecycleMode`; `ApprovalGrantV3` and `verifyV3()` with three new `ApprovalErrorCode`s; `RevocationStage` gains `issue`; `AuthorityRevokedError` gains an optional `check`; `RevocationReceiptV1` gains three optional lists; `AuthorityRevocationRegistry` gains `nextSequence()` and `currentSequence()`.
- Migration for integrators who opt in: switch to `approve()` / `reject()`, `issuePermit()` and `start()` with a fresh signed request, and issue `ApprovalGrantV3` grants from the lineage snapshot's bindings. The capability provider must answer a lineage's context with the identical chain it answered at creation.
