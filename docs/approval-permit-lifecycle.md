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

- **The request is runtime-owned.** In permit mode `process()` takes one JSON copy of the request at entry and deep-freezes it, before schema validation, signature verification and the first callback. Signature, replay, capability resolution, the Guardian decision and the lineage bindings all read this one object; the caller's object is never read again. The Guardian is handed the frozen copy, so it cannot change the operation it evaluates (a write attempt throws, and `process()` is denied). Without this, a callback holding the caller's object could rewrite the tool before the Guardian decided, so that an `update_record` lineage would receive the policy approval given to `read_record` (regression L17).
- The bindings are computed from that snapshot right after the chain is verified and bound, before the first callback (the `capability_verified` audit, the Guardian, the `guardian_decision` audit), and are frozen. No callback can change what a lineage binds.
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
- The lifecycle mutant gate (§8) carries component check-point evidence only for the session, agent and tenant comparisons of the start request (M55, M56) and for the source of the execution authority (M71); none of them has a production-path witness. The final fence's chain-validity check at approve and issue is masked by the verification of the provider's answer that directly precedes it (M70 approve/issue): no test separates it there, and it is recorded as a gap, not as evidence.
- No full ACS conformance or certification claim.

## 8. Mutant gate

`npm run mutants:lifecycle` runs the shared runtime-test mutant gate ([mutant-gate.md](mutant-gate.md)) with [`mutants/lifecycle/manifest.json`](../mutants/lifecycle/manifest.json). It covers M53–M71 of the plan (§8.2) and the plan's named variants: M58, M61 and M62 with inputs (i) and (iii), and M70 split by stage. The manifest pins, for every entry:
- the patch (SHA-256-bound) against the unchanged `src/` of the reviewed head `20a32e6`;
- the check it removes, the kept safeguards and the witness input;
- each witness label's exact control and mutant value, and the exact errors each witness may catch;
- the claimed evidence kind and, where the claim is narrower than the kind suggests, its limits (`claim_limits`);
- the collateral observations outside the named witnesses: for each such test its status, witness-log observations and, when it fails, its assertion failure.

**Counts.** The manifest has 26 entries with 20 distinct patches. 6 entries are variants (`variant_of`: M58-i/iii, M61-i/iii, M62-i/iii): each has its main entry's patch, so its jest run is identical to the main entry's, and it reads another witness of that run. A variant is not an independent failure mechanism, so the gate covers 20 mechanisms. 41 distinct witness tests are named. The gate report counts entries, distinct patches, mechanisms, variants and witness tests separately.

**Where the expected values come from.** The expected values were taken from a precheck run of every patch and pinned (manifest SHA-256) before the final run. A detection therefore shows that the final run reproduced the pinned precheck observations exactly: reproducibility evidence. Whether an observation shows the plan row's safety property is stated per entry (`claim_limits`, recorded gaps) and rests in addition on independent review.

The manifest uses the strict whole-run rule: every other test must pass with its control observations, so a witness never redeems an unexpected failure elsewhere.

**Evidence kinds** follow the plan (§8), with one change: M65 is reported as availability evidence.
- `lifecycle_effect` and `check_and_lifecycle` report lifecycle state and are never counted as containment.
- `availability_effect` and `check_and_availability` report an allowed action that is denied or not executed. They are never counted as containment. The plan names M65 `both`, but its effect is that the allowed follow-up start is denied, so M65 is `check_and_availability`.
- `component_check_point` is never production-path evidence.
- When a label outside the claimed kind also changes, the gate reports it under `observed_beyond_kind` and does not count it. Examples:
  - M67's tool call: the kind `check_and_lifecycle` is kept, conservatively;
  - M70-start's recorded permit expiry;
  - M59's denied follow-up start (availability);
  - the lifecycle state of several `both` entries.

| Entry | Removes | Witnesses | Changing labels (control → mutant, part) | Claimed kind | Pinned collateral |
|---|---|---|---|---|---|
| M53 | the state re-read at the start effective point: F(start) no longer re-checks the permit state and consumes on the state the early check saw (check-then-act split) | LC-L4c | `LC-L4c-outer` "permit_consumed" → "ok" (check)<br>`LC-L4c-tool-calls` 1 → 2 (effect) | `both` | 0 |
| M54 | the revocation part of F(start): the shared final fence skips its revocation check for stage start only | LC-L7b | `LC-L7b-start` "revoked:start/final" → "ok" (check)<br>`LC-L7b-permit` "issued" → "consumed" (lifecycle)<br>`LC-L7b-tool-calls` 0 → 1 (effect) | `both` | 0 |
| M55 | the session_id and agent_id comparisons of the fresh start request (compareStartBindings) | LC-C-session, LC-C-agent; control witnesses LC-L5-session, LC-L5-agent unchanged | `LC-C-comparator-session` "session" → null (check)<br>`LC-C-comparator-agent` "agent" → null (check) | `component_check_point` | 0 |
| M56 | the tenant comparison of the fresh start request (compareStartBindings) | LC-C-tenant, LC-C-tenant-absent; control witnesses LC-L5-tenant unchanged | `LC-C-comparator-tenant` "tenant" → null (check)<br>`LC-C-comparator-tenant-absent` "tenant" → null (check) | `component_check_point` | 0 |
| M57 | the early start revocation check of the lineage authority (start order step 10) | LC-L2b | `LC-L2b-start` "revoked:start/early" → "revoked:start/final" (check) | `check_point` | 0 |
| M58 | the snapshot comparison at start, the only authority comparison at start | LC-L6-start (ii) | `LC-L6-start` "chain_snapshot_mismatch" → "ok" (check)<br>`LC-L6-start-state` "issued" → "consumed" (lifecycle)<br>`LC-L6-start-calls` 0 → 1 (effect)<br>`LC-L6-start-execution-capability` undefined → "l6s-ii-L" (effect) | `both` | 4 |
| M58-i (variant of M58) | the snapshot comparison at start (variant i) | LC-L6-start (i) | `LC-L6-start` "chain_snapshot_mismatch" → "capability_id_conflict" (check) | `check_point` | 4 |
| M58-iii (variant of M58) | the snapshot comparison at start (variant iii) | LC-L6-start (iii) | `LC-L6-start` "chain_snapshot_mismatch" → "capability_chain_link_mismatch" (check) | `check_point` | 4 |
| M59 | the tool comparison of the fresh start request | LC-L5-tool | `LC-L5-tool` "lineage_binding_mismatch:tool" → "ok" (check)<br>`LC-L5-tool-state` "issued" → "consumed" (lifecycle)<br>`LC-L5-tool-T2-calls` 0 → 1 (effect)<br>`LC-L5-tool-follow` "ok" → "permit_consumed" (check)<br>`LC-L5-tool-T1-calls` 1 → 0 (availability) | `both` | 1 |
| M60 | the arguments-digest comparison of the fresh start request | LC-L5-arguments | `LC-L5-arguments` "lineage_binding_mismatch:arguments" → "ok" (check)<br>`LC-L5-arguments-state` "issued" → "consumed" (lifecycle)<br>`LC-L5-arguments-calls` 0 → 1 (effect)<br>`LC-L5-arguments-follow` "ok" → "permit_consumed" (check)<br>`LC-L5-arguments-args` [{"n":1}] → [{"n":2}] (effect) | `both` | 1 |
| M61 | the snapshot comparison at approve | LC-L6-approve (ii) | `LC-L6-approve` "chain_snapshot_mismatch" → "ok" (check)<br>`LC-L6-approve-state` "pending" → "approved" (lifecycle) | `check_and_lifecycle` | 2 |
| M61-i (variant of M61) | the snapshot comparison at approve (variant i) | LC-L6-approve (i) | `LC-L6-approve` "chain_snapshot_mismatch" → "capability_id_conflict" (check) | `check_point` | 2 |
| M61-iii (variant of M61) | the snapshot comparison at approve (variant iii) | LC-L6-approve (iii) | `LC-L6-approve` "chain_snapshot_mismatch" → "capability_chain_link_mismatch" (check) | `check_point` | 2 |
| M62 | the snapshot comparison at issue | LC-L6-issue (ii) | `LC-L6-issue` "chain_snapshot_mismatch" → "ok" (check)<br>`LC-L6-issue-state` "approved" → "issued" (lifecycle) | `check_and_lifecycle` | 3 |
| M62-i (variant of M62) | the snapshot comparison at issue (variant i) | LC-L6-issue (i) | `LC-L6-issue` "chain_snapshot_mismatch" → "capability_id_conflict" (check) | `check_point` | 3 |
| M62-iii (variant of M62) | the snapshot comparison at issue (variant iii) | LC-L6-issue (iii) | `LC-L6-issue` "chain_snapshot_mismatch" → "capability_chain_link_mismatch" (check) | `check_point` | 3 |
| M63 | the revocation part of F(issue): the shared final fence skips its revocation check for stage issue only | LC-L7a | `LC-L7a-issue` "revoked:issue/final" → "ok" (check)<br>`LC-L7a-permit` "none" → "issued" (lifecycle) | `check_and_lifecycle` | 0 |
| M64 | consumption is final: a start whose tool throws after the effective point resets the permit to issued | LC-L11 | `LC-L11-permit` "consumed" → "issued" (lifecycle)<br>`LC-L11-second` "permit_consumed" → "ok" (check)<br>`LC-L11-tool-calls` 1 → 2 (effect) | `both` | 1 |
| M65 | over-fencing control: a start denied by a binding mismatch consumes the permit | LC-L5-tool, LC-L5-arguments | `LC-L5-tool-state` "issued" → "consumed" (lifecycle)<br>`LC-L5-tool-follow` "ok" → "permit_consumed" (check)<br>`LC-L5-tool-T1-calls` 1 → 0 (availability)<br>`LC-L5-arguments-state` "issued" → "consumed" (lifecycle)<br>`LC-L5-arguments-follow` "ok" → "permit_consumed" (check)<br>`LC-L5-arguments-args` [{"n":1}] → [] (availability) | `check_and_availability` | 0 |
| M66 | the permit-expiry part of F(start): the shared final fence skips the operation's own expiry for stage start only | LC-L9-permit | `LC-L9-permit` "permit_expired" → "ok" (check)<br>`LC-L9-permit-state` "permit_expired" → "consumed" (lifecycle)<br>`LC-L9-permit-calls` 0 → 1 (effect) | `both` | 0 |
| M67 | the reject transition: a reject leaves the lineage pending | LC-L10 | `LC-L10` ["not_pending","not_approved","permit_not_issued"] → ["ok","ok","ok"] (check)<br>`LC-L10-state` "rejected" → "consumed" (lifecycle)<br>`LC-L10-calls` 0 → 1 (effect) | `check_and_lifecycle` | 1 |
| M68 | the revocation part of F(approve): the shared final fence skips its revocation check for stage approval only | LC-L1-provider | `LC-L1p-approve` "revoked:approval/final" → "ok" (check)<br>`LC-L1p-state` "pending" → "approved" (lifecycle) | `check_and_lifecycle` | 0 |
| M69 | the revocation part of the creation fence F(create) | LC-L15 | `LC-L15-process` "revoked:request/final" → "ok" (check)<br>`LC-L15-lineages` 0 → 1 (lifecycle) | `check_and_lifecycle` | 0 |
| M70-create | the chain-validity part of the creation fence F(create) | LC-L16-create | `LC-L16-create` "capability_expired" → "ok" (check)<br>`LC-L16-create-lineages` 0 → 1 (lifecycle) | `check_and_lifecycle` | 0 |
| M70-start | the chain-validity part of F(start): the shared final fence skips chain validity for stage start only | LC-L16-start | `LC-L16-start` "capability_expired" → "permit_expired" (check)<br>`LC-L16-start-permit` "issued" → "expired" (lifecycle) | `check_point` | 0 |
| M71 | the binding of a start's execution to the lineage's authority: the execution authority is built from the provider's verified chain for R' (authority substitution) | LC-C-execution-authority; control witnesses LC-L3 unchanged | `LC-C-execution-authority` ["A-L",["A-I"],"t1","s1"] → ["B-L",["B-I"],"t9","s1"] (check) | `component_check_point` | 0 |

**Claim limits** (from the manifest; also in the gate report):
- **M58:** Snapshot continuity only: a start whose provider answer is another valid, unrevoked authority B (input ii) runs, although it no longer matches the lineage's chain snapshot. The started execution stays bound to the lineage's authority A (LC-L6-start-execution-capability = A's leaf). It does not show the use of a revoked or expired authority, nor an authority substitution (that is M71, component evidence only).
- **M61:** Lifecycle evidence only: the approval is recorded for another authority's answer; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **M62:** Lifecycle evidence only: a permit is issued for another authority's answer; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **M63:** Lifecycle evidence only: a permit is issued after the authority was revoked; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **M65:** Availability evidence only: a start denied for a binding mismatch consumes the permit, so the allowed follow-up start is denied (permit_consumed) and its tool is not called. No unapproved action runs (the mismatched start's tool calls stay 0); this is not containment evidence.
- **M68:** Lifecycle evidence only: the approval is recorded after the authority was revoked; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **M69:** Lifecycle evidence only: a lineage is created for a revoked authority; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **M70-create:** Lifecycle evidence only: a lineage is created for an expired chain; no tool runs. That a later fence still denies the start is inferred from the stage-specific patch, not shown by a run: the witness stops at this operation.
- **Variants** (M58-i/iii, M61-i/iii, M62-i/iii): only the denial reason changes; not independent failure mechanisms.

**Recorded gaps** (repeated in the gate report):
- M55 and M71 have component check-point evidence only.
- M56's tenant comparison is structurally masked on the production path. It runs only after the snapshot comparison matched the provider's leaf to the lineage's leaf by content, and both compared tenants are read from that leaf. Its evidence is a component check point only.
- M70 at approve and issue is masked; at this head the patched trees pass all tests.
- M61, M62, M63, M68, M69 and M70-create are lifecycle evidence only. That a later fence still denies the start is inferred, not run.
- The eval-gate mutants of plan §8.1 (M12–M14, M24, M25, M49–M52) belong to the later eval integration.

The gate's own limitations (A5–A9 of the review of `ef0c9a8`) are listed in [mutant-gate.md](mutant-gate.md#known-limitations).

`npm run mutants:lifecycle:regressions` checks the gate itself under the strict rule (RL1–RL24, [mutant-gate.md](mutant-gate.md#lifecycle-gate-regressions)). `npm run mutants:lifecycle:determinism` runs the lifecycle witnesses three times and requires identical witness logs.

## 9. Compatibility

- Legacy mode is the default and unchanged: `process()`, `resolveApproval()`, `ProcessResult`, V2 grants, audit events and the revocation receipt (no lifecycle lists, `enforced_at` without `issue`).
- Additive API: the optional 12th constructor argument; `GuardedExecutor<M>` (default `"legacy"`); `approve`, `reject`, `issuePermit`, `start`, `getLineage`, `lineages`, `authoritySequence`, `lifecycleMode`; `ApprovalGrantV3` and `verifyV3()` with three new `ApprovalErrorCode`s; `RevocationStage` gains `issue`; `AuthorityRevokedError` gains an optional `check`; `RevocationReceiptV1` gains three optional lists; `AuthorityRevocationRegistry` gains `nextSequence()` and `currentSequence()`.
- Migration for integrators who opt in: switch to `approve()` / `reject()`, `issuePermit()` and `start()` with a fresh signed request, and issue `ApprovalGrantV3` grants from the lineage snapshot's bindings. The capability provider must answer a lineage's context with the identical chain it answered at creation.
