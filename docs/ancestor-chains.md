# Ancestor chains and descendant revocation (package 1b)

This document specifies issuer-attested ancestor chains and descendant coverage of capability revocation in `GuardedExecutor`. It implements §7.6 and the ancestor column of the fence matrix (§7.3, §7.8) of the approved [coverage expansion plan](https://github.com/mikko-lab/agent-control-evals/blob/main/docs/revocation/coverage-expansion-plan.md) of `agent-control-evals`.

Chains build on [tenant scope (package 1a)](tenant-scope.md) and exist only in tenancy mode. They have the limits of [authority revocation (A1)](authority-revocation.md) and [cooperative containment (A2)](cooperative-containment.md): one executor instance, in memory, cooperating tools, and effects through `ctx.commit()` only.

## Meaning of a parent link

A parent link is an **issuer-attested derivation**. The trusted issuer signs a child grant that names its parent, and the runtime enforces two consequences:
- **Revocation dependency.** The child can be used only while no capability in its chain is revoked.
- **Attenuation.** The child's `allowed_tools` are a subset of its parent's, and its validity window (`issued_at` to `expires_at`) lies within its parent's.

Every member of a chain belongs to the leaf's tenant. Members may name different sessions of that tenant.

Holder-to-holder delegation, where the parent's holder signs a child with its own key, is out of scope. It needs holder keys and its own design and review.

## Grant and provider format

A `CapabilityGrantV2` may carry a signed parent reference:

```json
"parent": { "capability_id": "<parent id>", "fingerprint": "<64 lowercase hex>" }
```

The fingerprint is the SHA-256 of the canonical JSON of the parent grant's body: every field except `signature`, including the parent's own `parent` reference and `tenant_id`. It is the same fingerprint the runtime uses to bind a `capability_id` to its content (`capabilityFingerprint`). A version 1 grant with `parent` is rejected (`MALFORMED_GRANT`).

The capability provider returns either a single grant or a chain envelope:

```json
{ "kind": "capability_chain", "leaf": { ... }, "ancestors": [ { "parent of leaf" }, ..., { "root" } ] }
```

- `leaf` is the grant bound to the request (agent, session, tool).
- `ancestors` are ordered from the leaf's parent up to the root, a grant without a parent.
- The envelope has no other fields. Outside tenancy mode it is rejected (`MALFORMED_CHAIN`).
- A single grant is a chain of one. A grant that names a parent must come in an envelope that supplies the parent.

**Depth.** `MAX_CHAIN_LENGTH = 8` grants, **counting the leaf**: a leaf with at most 7 ancestors. A longer chain is rejected (`CHAIN_TOO_DEEP`), never truncated.

## Verification

`CapabilityGrantVerifier.verifyChain(input, context)` verifies what the provider returned, in this order:

1. **Envelope.** Structure of the chain envelope (`MALFORMED_CHAIN`).
2. **Depth.** At most 8 grants, leaf included (`CHAIN_TOO_DEEP`).
3. **Repeated ids.** No `capability_id` occurs twice; this also rejects cycles (`CHAIN_REPEATED_ID`). Fingerprint linkage makes a cycle infeasible as well, but the runtime does not rely on that.
4. **Leaf.** Structure, signature, validity window, and the binding to the request's agent, session and tool, exactly as for a single grant.
5. **Ancestors.** Each member's structure, issuer signature and validity window. A signature failure names the chain position, for example `Invalid signature (chain position 2)` (`INVALID_SIGNATURE`).
6. **Links.** For each child, in both directions:
   - its `parent.capability_id` must equal the supplied parent's `capability_id`;
   - its `parent.fingerprint` must equal the fingerprint of the supplied parent.

   Either mismatch is `CHAIN_LINK_MISMATCH`, naming which part did not match. A child naming a parent the chain does not supply, and a chain that continues past a root, are `MALFORMED_CHAIN`. A missing parent is never treated as a root.
7. **Tenant.** Every member has the leaf's `tenant_id` (`TENANT_CHAIN_MISMATCH`). Tenant equality is checked here only, not as part of attenuation.
8. **Attenuation.** Each child's `allowed_tools` are a subset of its parent's, and its validity window lies within its parent's (`CHAIN_ATTENUATION`).

Nothing is bound during verification.

**Order and masking.** The order keeps each check point separately observable:
- Repeated ids are checked before any member is verified. Without this check, a repeated id is still rejected by the capability binding (two contents for one id).
- The capability-id link is compared before the fingerprint. Without the id comparison, a substituted parent is still rejected by the fingerprint.

The mutant table below lists these kept safeguards.

| Code | Audit reason (`capability_rejected`) |
|---|---|
| `MALFORMED_CHAIN` | `capability_malformed_chain` |
| `CHAIN_TOO_DEEP` | `capability_chain_too_deep` |
| `CHAIN_REPEATED_ID` | `capability_chain_repeated_id` |
| `CHAIN_LINK_MISMATCH` | `capability_chain_link_mismatch` |
| `TENANT_CHAIN_MISMATCH` | `capability_tenant_chain_mismatch` |
| `CHAIN_ATTENUATION` | `capability_chain_attenuation` |
| `INVALID_SIGNATURE` (any position) | `capability_authentication_failed` |
| approval snapshot differs | `chain_snapshot_mismatch` |

## Where a chain is rejected and what is bound

`process()` verifies the chain right after the provider returns it. A chain that fails any check is rejected there (`capability_rejected`, `Capability rejected: ...`), before:
- any new binding;
- the request-time revocation check and `capability_verified`;
- the Guardian decision and a pending approval;
- a permit, a managed execution and the tool call.

**Binding.** A verified chain is bound atomically:
- every member's `capability_id` to its content (fingerprint);
- in tenancy mode, every member's session to the tenant.

All conflicts are checked first, against earlier bindings and within the chain: `capability_id_conflict` and `session_tenant_conflict`. A conflicting chain binds nothing, not even its new members. A bound ancestor id cannot be presented later with other content, including another parent reference.

**No chain from memory.** The runtime never builds a chain from grants it has seen before. Earlier bindings serve only as conflict checks. A leaf that names a parent must come with its chain on every request, even if the parent was used and bound earlier.

## Execution and approval binding

- **Immutable from verification.** The list of verified ancestor ids is frozen right after chain verification, before the first callback (an audit sink, the Guardian) runs. Callbacks only receive copies: the `capability_verified` metadata and the enforcement evidence carry copies of the list. Changing or emptying such a copy, before or after start, never changes the authority (C6.01–C6.03, mutant M42c).
- **Start.** An execution is bound at start to its request's session, its original `capability_id`, its tenant and the `capability_id`s of its verified ancestor chain (`ancestor_capability_ids`, parent first). The binding is frozen. The commit fence, both delivery checks and the cancellation fan-out use it, and nothing is re-resolved after start. `getExecution()`, `terminals()`, the execution audit events and `capability_verified` report `ancestor_capability_ids` when the chain is not empty.
- **Pending approval.** A pending approval keeps a snapshot of the verified leaf and its ancestors. `resolveApproval()` then does the following:
  1. checks revocation of the snapshot, ancestors included;
  2. re-verifies the snapshot chain (signatures, validity, links, tenant, attenuation);
  3. re-resolves the chain from the provider.

  For a chained original, the re-resolved leaf and every ancestor must equal the snapshot, member by member by content fingerprint. This comparison runs on the provider's answer before it is verified, so a changed chain is rejected as `chain_snapshot_mismatch`. A pending request without ancestors keeps the earlier rule: the current grant may be a re-issued grant for the same context, but it must not bring ancestors (`chain_snapshot_mismatch`). The re-resolved chain is then verified, bound and checked for revocation. The execution stays bound to the original capability and the snapshot chain.

## Descendant revocation

`revoke({ scope: "capability", capability_id: X })` is unchanged: it records the tombstone `capability:X`. Every check point now checks the authority's bound ancestor ids as well, so the tombstone covers every descendant whose verified chain contains `X`.

The reason is `ancestor_revoked` (`AuthorityRevokedError.reason`, `CommitRejectedError.reason`, withheld-output `code`). When several revocations apply, the broadest is reported: tenant, then session, then an ancestor (nearest parent first), then the capability itself.

| Check point | Where | Ancestor source | Outcome when an ancestor is revoked |
|---|---|---|---|
| Request check after verification | `process()`, after chain verification and binding, before the Guardian decision | verified chain | `AuthorityRevokedError` stage `request` |
| Approval re-verification | `resolveApproval()`, both checks | pending chain snapshot (first check), re-resolved chain equal to it (second check) | `AuthorityRevokedError` stage `approval` |
| Early start check | before correlation and permit state | execution binding | `AuthorityRevokedError` stage `start`, before `tool_execution_started` |
| Start guard | immediately before the tool function call | execution binding | `AuthorityRevokedError` stage `start`; the tool is not called |
| Commit fence | `ctx.commit()` | execution binding | `CommitRejectedError` reason `ancestor_revoked`; managed state unchanged |
| Early delivery check | result processing | execution binding | output withheld (`boundary: "result_processing"`) |
| Hand-over | public API return | execution binding | output withheld (`boundary: "api_return"`), code `ancestor_revoked` |
| Cancellation fan-out | `revoke()` | execution binding | cancellation requested for every running descendant |

The early request check runs before capability resolution, when no chain is known, so ancestry has no early request check.

**Scope.**
- **Before first use.** The registry is keyed by id, so a revocation of an ancestor id the runtime has never seen covers every later chain that contains it.
- **Downward only.** A revocation never propagates to a parent or a sibling. Revoking a child leaves its parent and its siblings working. Revoking a common ancestor covers every branch below it, but not the ancestor's own parent.
- **Sessions.** Ancestor revocation covers descendants in any session of the tenant. A session revocation covers only executions bound to that session, even when other sessions share an ancestor.
- **Tenants.** Tenant revocation is unchanged and covers the tenant's chains. Ids are bound to one content (which includes the tenant), so one id cannot name grants of two tenants.

**Not undone, not proven.** The decision (a denial, a withheld output), the cancellation signal and an observed terminal are separate evidence:
- a revocation does not undo a commit made before it;
- a cancellation request and its acknowledgement do not prove that an execution ended; an acknowledged execution stays `running` until the runtime observes its settlement.

**Receipt.** `pending_approvals` and `in_flight_executions` list the target's own work and its descendants' work. The target is still `{ scope: "capability", capability_id }`. OCSF export allowlists `ancestor_capability_ids` only for grant- and execution-bound events (`capability_verified`, `authority_revocation_enforced`, the execution and commit events), never for a rejection.

## Compatibility

- **Legacy mode (default).** A chain envelope is rejected (`MALFORMED_CHAIN`, `capability_malformed_chain`). A version 1 grant that carries a `parent` field is now rejected (`MALFORMED_GRANT`); before 1b an issuer-signed extra `parent` field was ignored. Version 1 grants without it behave exactly as before.
- **Tenancy mode.** A `CapabilityGrantV2` without `parent` is a chain of one and behaves exactly as in 1a; every 1a test passes unchanged. A version 2 grant with `parent` is now a derived grant: its parent reference must be well formed, and it is accepted only with its verified chain. Before 1b, an issuer-signed `parent` field was ignored.
- **API.**
  - `CapabilityGrantV2.parent` is optional.
  - `CapabilityGrantVerifier.verifyChain()`, `MAX_CHAIN_LENGTH` and `capabilityFingerprint` are new exports of `capability-grant.ts`. `authority-revocation.ts` re-exports `capabilityFingerprint`.
  - `RevocationReason` and `CommitBlockReason` gain `ancestor_revoked`.
  - `CheckedAuthority`, `ExecutionSnapshot` and `ExecutionTerminal` gain optional `ancestor_capability_ids`.
  - `ManagedExecutionDeps` gains optional `ancestorIds`.
  - `AuthorityRevocationRegistry.capabilityConflicts()` is new.
  - Six new error codes, with the audit reasons listed above.
- **Audit.** `capability_verified` and `authority_revocation_enforced` carry `ancestor_capability_ids` for chained authorities, and approval rejections may carry `chain_snapshot_mismatch`. Nothing changes for authorities without a chain.

## Evidence

The tests are in `tests/ancestor-chain.test.ts`. The setup, `tests/chain-setup.ts`, acts as the trusted issuer: it signs every member and links each child by id and fingerprint, and its provider returns the full chain.
- **Effect evidence** comes only from runtime state: tool calls of the harness's tool doubles, `executor.managedState`, the returned result content, and the cancellation signal as seen inside the tool and in the execution snapshot.
- **Audit events** serve only as check-point evidence: rejection reasons, revocation stage and delivery boundary.
- **Chain-verification witnesses** use a fresh executor, no revocation record and members never seen before, so the verification under test is the only check that can reject the chain.
- **Determinism.** Revocations that must land between check points are injected from audit callbacks (`guardian_decision`, `tool_execution_started`, `tool_result_delivered`). Running tools wait on deferred latches that the test releases. The clock starts at the real time and is never advanced, as in [tenant-scope.md](tenant-scope.md#evidence).

## Mutant gate

The runtime-test mutants are named in [`mutants/ancestor/manifest.json`](../mutants/ancestor/manifest.json) before any run. `npm run mutants:ancestor` runs them through the shared gate ([mutant-gate.md](mutant-gate.md)), with the same rules as the tenant gate. Every ancestor mutant also names the valid-chain control C1.01 as a `control` witness, which must keep passing under the mutant with the same values.

| Mutant | Removes | Witness | Kind | Kept safeguards that still contain the effect |
|---|---|---|---|---|
| M20 | ancestry at the request check after verification, the early start check and the start guard | C3.02 | both | — |
| M21 | ancestry at the commit fence | C3.07 | both | — |
| M27b | ancestry at the request check after verification | C3.01 | check_point | early start check, start guard |
| M27g | ancestry at the early start check | C3.03 | check_point | start guard |
| M27d | ancestry at the start guard | C3.04 | both | — (revocation injected after the earlier checks) |
| M34 | ancestry at the approval re-verification, the early start check and the start guard | C3.06 | both | — |
| M34a | ancestry at the approval re-verification only | C3.05 | check_point | early start check, start guard |
| M35 | ancestry at both delivery checks | C3.09 | both | — |
| M35a | ancestry at the early delivery check | C3.10 | check_point | hand-over |
| M35b | ancestry at the hand-over | C3.11 | both | — (revocation injected after the early check) |
| M36 | ancestry in the cancellation fan-out | C3.12 | containment_effect | — |
| M37 | a revocation propagates to the parent chain (and so to siblings) | C4.01 | both | — |
| M38 | missing parent accepted as a root | C1.02 | both | — |
| M39 | depth not limited | C1.04 | both | — |
| M40 | repeated id accepted | C1.06 | check_point | capability binding (two contents for one id: `capability_id_conflict`) |
| M41 | a member of another tenant accepted | C1.08 | both | — (tenant equality is not part of attenuation) |
| M42a | chain re-resolved at the commit fence instead of the start-time binding | C2.04 | check_point | capability binding: the same chain is re-resolved |
| M42b | an already bound ancestor id accepted with other content | C2.01 | both | — (the new chain's own links are consistent) |
| M42c | the verified ancestor ids are not frozen before the first callback, and the `capability_verified` audit metadata aliases them | C6.01 | both | — (with the aliased list emptied by an audit sink, every later check point sees no ancestor) |
| M43 | attenuation not enforced (tools; validity window) | C1.09 | both | — (the leaf's own tools include the requested tool) |
| M44 | root signature not verified | C1.10 | both | — (fresh executor, first use) |
| M45 | intermediate signature not verified | C1.11 | both | — (fresh executor, first use) |
| M46 | parent fingerprint not compared | C1.12 | both | — (fresh executor: the replaced id is not bound yet) |
| M47 | parent `capability_id` not compared | C1.13 | check_point | fingerprint comparison |
| M48 | approval compares only the leaf, not the chain snapshot | C1.14 | check_point | link check of the re-resolved chain (fingerprint) |

M27g is a check point the plan did not list separately. The runtime has an early start check before the start guard, so it gets its own check-point witness, as M27f does for tenants.

**Coverage gaps and limits.**
- **M42a** re-resolves the chain at the commit fence only. The delivery checks and the fan-out read the same frozen binding, but they have no re-resolution mutant of their own.
- **Ancestor expiry between request and approval** has no isolated witness. Attenuation keeps every ancestor valid at least as long as its leaf, so the leaf's own expiry check rejects first. The snapshot is re-verified as a whole.
- **M40, M42a, M47 and M48** are check-point evidence only, as the plan states. Their kept safeguards still contain the effect.
- **Contract and supplement evidence** for the ancestor column (S5, S6, S8, S10, AM13, the `derived-in-flight-ancestor-revoked` and `sibling-isolation` corpus cases) is part of the later eval work order. This package provides runtime-own tests only.

## Not provided

- Holder-to-holder delegation, holder keys, and any chain source other than the provider's answer for the request.
- Revocation of a whole subtree by anything other than an ancestor's `capability_id`.
- Persistent, distributed or cross-process revocation; the limits of A1 and A2 apply unchanged.
