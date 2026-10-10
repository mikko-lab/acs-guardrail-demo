# Tenant scope (package 1a)

This document specifies tenant-bound authority and tenant-scope revocation in `GuardedExecutor`. It implements §7.5 and the tenant column of the fence matrix (§7.3, §7.8) of the approved [coverage expansion plan](https://github.com/mikko-lab/agent-control-evals/blob/main/docs/revocation/coverage-expansion-plan.md) of `agent-control-evals`. Ancestor chains and descendant coverage (package 1b) are not part of it.

Tenant scope extends [authority revocation (A1)](authority-revocation.md) and [cooperative containment (A2)](cooperative-containment.md). It has the same limits: one executor instance, in memory, cooperating tools, and effects through `ctx.commit()` only.

## Tenancy mode

Tenancy is a property of the capability verifier, which is the single source of the mode:

```ts
new CapabilityGrantVerifier(publicKey, keyId, clock, { tenancy: true });
```

| | Tenancy mode | Legacy mode (default) |
|---|---|---|
| Accepted grants | `CapabilityGrantV2` only: `version: 2` with a non-empty `tenant_id` (at most 256 characters) | `CapabilityGrantV1` only: `version: 1` without `tenant_id` |
| A tenantless grant | rejected (`MISSING_TENANT`, audit reason `capability_missing_tenant`); there is no default tenant | accepted, as before |
| A grant with `tenant_id` | accepted, if version 2 | rejected (`MALFORMED_GRANT`) |
| `revoke({ scope: "tenant", ... })` | supported | rejected (`RevocationTargetError`); nothing is recorded |
| A request's own `tenant_id` | must equal the grant's tenant | ignored, as before |

No verifier accepts both grant versions, so there is no mixed mode in which a tenantless grant could sit outside every tenant revocation.

## Trust and binding rules

- **Trusted source.** An authority's tenant is the `tenant_id` of its verified, issuer-signed grant. It is never taken from request metadata, `agent_id`, a session-id prefix or caller state.
- **Request and grant.** The request envelope's reserved ACS field `params.tenant_id` is covered by the request signature, but it is only a claim. In tenancy mode, if it is present it must equal the grant's tenant. Otherwise the request is rejected before the Guardian decision (`capability_rejected`, reason `tenant_mismatch`) and no tool is called.
- **Capability identity.** The capability fingerprint covers every signed field except the signature, `tenant_id` included. A grant with an already bound `capability_id` but another tenant is therefore a `capability_id_conflict`.
- **Session namespace.** A runtime `session_id` is bound to the tenant of the first verified grant that names it. The binding is monotonic. A later grant of another tenant for that session is rejected (`session_tenant_conflict`).
  - The session-tenant conflict is checked before the capability id is bound, so a rejected grant binds nothing.
  - A session revocation therefore never crosses tenants, and the early request check can apply a tenant revocation to an already bound session before any capability is resolved.
- **Execution binding.** An execution is bound at start to its request's session, its original `capability_id` and its grant's tenant. The commit fence, both delivery checks and the cancellation fan-out use this start-time binding, and nothing is re-resolved after start. `getExecution()`, `terminals()` and the execution audit events report the bound `tenant_id`.
- **Approval.** A pending approval keeps its grant snapshot. Re-verification requires the provider's current grant to carry the same tenant (`tenant_mismatch` otherwise). The execution stays bound to the original capability and tenant.

## Tenant revocation

`revoke({ scope: "tenant", tenant_id })` records a monotonic, idempotent tombstone, `revocation_id` `tenant:<tenant_id>`. It is checked at use time, so it covers every grant, session and execution bound to the tenant, including grants first seen after the revocation; nothing is enumerated in advance. A use is denied if any applicable record matches, that is tenant, session or capability. When several match, the broadest scope is reported, in the order tenant, then session, then capability.

| Check point | Where | Tenant source | Outcome when the tenant is revoked |
|---|---|---|---|
| Early request check | `process()`, before capability resolution | session-tenant binding (bound sessions only) | `AuthorityRevokedError` stage `request`, no capability resolved |
| Request check after verification | `process()`, after capability verification and binding, before the Guardian decision | verified grant | `AuthorityRevokedError` stage `request` |
| Approval re-verification | `resolveApproval()`, both checks | pending grant snapshot | `AuthorityRevokedError` stage `approval` |
| Early start check | before correlation and permit state | execution binding | `AuthorityRevokedError` stage `start`, before `tool_execution_started` |
| Start guard | immediately before the tool function call | execution binding | `AuthorityRevokedError` stage `start`; the tool is not called |
| Commit fence | `ctx.commit()` | execution binding | `CommitRejectedError` reason `tenant_revoked`; managed state unchanged |
| Early delivery check | result processing | execution binding | output withheld (`boundary: "result_processing"`) |
| Hand-over | public API return | execution binding | output withheld (`boundary: "api_return"`), code `tenant_revoked` |
| Cancellation fan-out | `revoke()` | execution binding | cancellation requested for every running execution of the tenant |

**Other tenants keep working.** A tenant revocation never matches an authority of another tenant: their starts, commits and deliveries stay allowed, and they receive no cancellation request.

**Not undone, not proven.**
- A revocation does not undo a commit that happened before it; the commit stays a historical effect.
- A cancellation request and its acknowledgement do not prove that an execution ended: an acknowledged execution stays `running` until the runtime observes its settlement.

**Receipt.** The receipt's `target` is `{ scope: "tenant", tenant_id }`. `pending_approvals` and `in_flight_executions` list only the tenant's, and `authority_revoked` records `scope: "tenant"` and `tenant_id`. OCSF export allowlists the verified `tenant_id` for grant- and execution-bound events, never a request's own claim.

## Evidence

The tests are in `tests/tenant-scope.test.ts` (setup: `tests/tenant-setup.ts`).

- **Effect evidence** comes only from runtime state: tool calls of the harness's tool doubles, `executor.managedState`, the returned result content, and the cancellation signal as seen inside the tool and in the execution snapshot.
- **Audit events** serve only as check-point evidence: rejection reasons, revocation stage and delivery boundary.
- **Clock.** Tests start the clock at the real time, because the runtime stamps its internal result requests with it, and never advance it. No expectation depends on time.

## Mutant gate

The runtime-test mutants are named in [`mutants/tenant/manifest.json`](../mutants/tenant/manifest.json) before any run. For each mutant the manifest gives:
- its patch, bound by SHA-256;
- its witness tests (file, describe and title);
- for every witness label, the exact value the unmodified runtime and the mutant must produce;
- the exact errors each witness may catch in each run.

The manifest's own SHA-256 is checked first. `npm run mutants:tenant` runs `scripts/mutants/run-tenant-mutants.mjs`.

**Witness log.** `tests/witness.ts` logs every witness check (label, actual, expected, with undefined encoded as `{"$undefined":true}`) and every error a witness caught through `outcome()` to the file named by `WITNESS_LOG`. It logs whether or not the check passed. The gate compares these observations with the manifest, so a label alone is never enough.

**Control.** The unpatched tree must pass all of the following:
- `npm run typecheck` and `npm run build` (`tsc --outDir dist`; `dist/src/guarded-executor.js` must exist);
- jest exiting 0, with no signal and no timeout, every test passing;
- every witness logging exactly its manifest control values and exactly its accepted control errors.

**Technical soundness of a mutant.** All of the following must hold:
- the patch applies;
- typecheck and build pass;
- jest exits 0 or 1, with no signal and no timeout, and writes its JSON result;
- no suite execution error;
- the **test inventory is identical to the control's**: the same number of tests and the same test ids (file, describe path and title).

**Detection.** All of the following must hold:
- jest exits 1;
- every named witness fails with `WitnessAssertionError`;
- every label logs exactly its manifest mutant value;
- the failed labels are exactly those whose mutant value differs from the control value;
- the errors the witness caught are exactly the accepted mutant errors.

**Unexpected failures.** A label value that is neither the control nor the mutant value, or a caught error the manifest does not accept, is an unexpected failure. It is reported with its details (value, error name and message) as a technical failure and is never check-point evidence.

**Never a detection; these are technical failures (exit 2):**
- a patch that does not apply;
- a typecheck or build error;
- a load error;
- a changed test inventory;
- a jest exit status other than 0 or 1, a signal or a timeout;
- a failure that is not a `WitnessAssertionError`;
- an unexpected value or error;
- a failing control.

**Evidence kinds:**
- **`check_point`:** a check label changes from its control value to its mutant value; the value is a stage, boundary, reason or call count.
- **`containment_effect`:** an effect label changes in runtime state: tool calls, managed state, returned content or the cancellation signal.
- **`both`:** both of the above in the same run.
- **`component_check_point`:** a component test's check label changes; this is never production-path evidence.

A changed rejection code alone is never containment. Safeguards that mask a check point are kept.

### Gate regressions

`npm run mutants:tenant:regressions` (`scripts/mutants/gate-regressions.mjs`) runs the gate on three fixed, hash-checked manifests in `mutants/tenant/regressions/` and requires their exit statuses:

| Case | Patch | Required gate result |
|---|---|---|
| R1-inventory | the M27e patch plus deletion of an unrelated test (582 → 581 tests) | technical failure, exit 2 (test inventory differs) |
| R2-syntax | an unexpected `SyntaxError` on the request path; the M27e witness stage becomes undefined | technical failure, exit 2 (unexpected value and unaccepted caught error) |
| R3-m27e | the real M27e mutant | detected at stage `start` (control `request`), exit 0 |

| Mutant | Removes | Witness | Kind | Kept safeguards that still contain the effect |
|---|---|---|---|---|
| M15 | tenant at the commit fence | T2.08 | both | — |
| M16 | tenant match (over-reach to every tenant) | T3.01 | both | — |
| M22 | tenant at the request checks, the early start check and the start guard | T2.03 | both | — |
| M26 | tenant at the approval re-verification, the early start check and the start guard | T2.07 | both | — |
| M26a | tenant at the approval re-verification only | T2.06 | check_point | early start check, start guard |
| M27a | tenant at the early request check | T2.01 | check_point | request check after verification, start checks |
| M27e | tenant at the request check after verification | T2.02 | check_point | early start check, start guard |
| M27f | tenant at the early start check | T2.04 | check_point | start guard |
| M27c | tenant at the start guard | T2.05 | both | — (revocation injected after the earlier checks) |
| M28 | tenant at both delivery checks | T2.10 | both | — |
| M28a | tenant at the early delivery check | T2.11 | check_point | hand-over |
| M28b | tenant at the hand-over | T2.12 | both | — (revocation injected after the early check) |
| M29 | tenant in the cancellation fan-out | T2.13 | containment_effect | — |
| M30 | tenant from the request claim instead of the grant | T1.02 | both | — (first use of the session) |
| M30b | request/grant tenant mismatch check | T1.03 | both | — |
| M31 | rejection of tenantless grants in tenancy mode | T1.05 | both | — |
| M32 | session-tenant conflict check | T1.07 | both | — |
| M33 | `tenant_id` in the capability fingerprint | T1.09 (component) | component_check_point | the fingerprint's `session_id` and the session-tenant binding |
| M33b | start-time binding at the commit fence (tenant re-resolved from the provider) | T2.14 | check_point | capability binding: the same tenant is re-resolved |

M27f is a check point the plan did not list separately: the runtime has an early start check before the start guard, and it gets its own check-point witness.

**Recorded gap (M33).** No production-path witness separates the control from M33.
- T1.08 is a regression test of the kept safeguards. With a new session, the `session_id` field still gives `capability_id_conflict`. With the same session after a tenant revocation, the early request check denies first. It is not M33 evidence.
- M33's only evidence is the component check point A-M33.

## Not provided

- Ancestor chains, delegated authority and descendant coverage (package 1b).
- Tenants as separate trust domains for keys or audit. One issuer key and one executor serve all tenants.
- Persistent, distributed or cross-process tenant revocation.
