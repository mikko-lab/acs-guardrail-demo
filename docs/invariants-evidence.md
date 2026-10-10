# Invariants and Evidence Map

This document maps architectural security invariants to automated evidence across the repository, including evaluation, runtime-authority, incident, correlation, and metrics test suites.

**Current verified baseline:** 394 automated tests, 23 Jest suites, 0 snapshots, TypeScript typecheck clean.

## A. Request Policy
- **ALLOW proceeds to execution**: `tests/evals/request-policy.test.ts` (`EVAL-A1`)
- **DENY blocks execution**: `tests/evals/request-policy.test.ts` (`EVAL-A2`)
- **ASK blocks pending approval**: `tests/evals/request-policy.test.ts` (`EVAL-A3`)
- **ASK + valid approval proceeds**: `tests/evals/request-policy.test.ts` (`EVAL-A4`)
- **ASK + human rejection blocks**: `tests/evals/request-policy.test.ts` (`EVAL-A5`)
- **ASK + expired approval blocks**: `tests/evals/request-policy.test.ts` (`EVAL-A6`)

## B. Replay Protection
- **Same session duplicate blocked**: `tests/evals/replay.test.ts` (`EVAL-B1`)
- **Cross-session duplicate allowed**: `tests/evals/replay.test.ts` (`EVAL-B2`)
- **Consumed correlation reference blocks**: `tests/evals/replay.test.ts` (`EVAL-B3`)
- **Replay failure fail-closed**: `tests/evals/replay.test.ts` (`EVAL-B4`)

## C. Correlation
- **Unknown request_id_ref fails**: `tests/evals/correlation.test.ts` (`EVAL-C1`)
- **Consumed request_id_ref fails**: `tests/evals/correlation.test.ts` (`EVAL-C2`)
- **Tool name mismatch fails**: `tests/evals/correlation.test.ts` (`EVAL-C3`)
- **Cross-session steal fails**: `tests/evals/correlation.test.ts` (`EVAL-C4`)

## D. Human Oversight & Isolation
- **Approval from Session A does not apply to Session B**: `tests/evals/isolation.test.ts` (`EVAL-D1`)
- **Approval for Request A does not resolve Request B**: `tests/evals/isolation.test.ts` (`EVAL-D2`)
- **Tool binding in the authority-enabled runtime**: `ApprovalGrantV2` cryptographically binds the exact tool and is required for `ASK` resolution; `ApprovalGrantV1` remains non-tool-bound at primitive level. Evidence: `tests/runtime-authority.test.ts` and `tests/evals/authority-adversarial.test.ts`.
- **Expired action retry fails**: `tests/evals/isolation.test.ts` (`EVAL-D4`)
- **Rejection is final**: `tests/evals/isolation.test.ts` (`EVAL-D5`)

## E. Runtime Authority
- **Request authentication and replay precede capability resolution**: `tests/evals/authority-adversarial.test.ts` (`AEV-015`, `AEV-016`)
- **Capability failures stop before Guardian evaluation**: `AEV-001..AEV-008`
- **Valid capability does not override Guardian DENY**: `AEV-009`
- **ApprovalGrantV1 is rejected by the authority-enabled runtime; a valid V2 can later resolve the pending action**: `AEV-010`
- **Tool-bound V2 failures and post-signature tampering fail closed while pending state is preserved**: `AEV-011`, `AEV-012`
- **Wrong approver identity fails closed using trusted pending-action context**: `AEV-013`
- **Expired approval cannot resurrect a pending action**: `AEV-014`
- **Result Guardian remains independent after authority verification and execution**: `AEV-017`
- **Unknown/non-pending approval does not mutate unrelated pending state**: `AEV-018`
- **Normal authority and oversight controls**: `NORMAL-001..003`
- **Dedicated runtime authority suite**: `tests/runtime-authority.test.ts` (`AUTHR-001..021`)

## F. Result Gate
- **ALLOW + ALLOW -> Result delivered**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F1`)
- **ALLOW + DENY -> Result withheld**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F2`)
- **ASK + Approve + DENY -> Result withheld**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F3`)
- **Result decision does not alter request metrics**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F4`)
- **Result DENY does not mutate original request event**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F5`)

## G. Authority Revocation (A1)
Specification: [authority-revocation.md](authority-revocation.md). Evidence: `tests/authority-revocation.test.ts`.
- **Pending approval cannot execute after capability or session revocation**: `REV-01`, `REV-02`, `REV-03c`
- **Approval re-checks provider withdrawal and the original capability's current validity**: `REV-03`, `REV-03b`
- **Revoked capability or session denies fresh-ID requests and replays; clearSession does not lift a revocation**: `REV-04`, `REV-05`, `REV-06`
- **Duplicate revocation is idempotent; revocation is monotonic**: `REV-07`
- **Untargeted capabilities and sessions continue**: `REV-08`
- **Start fence after the request-time check, on the ALLOW and approval paths**: `REV-start`, `REV-start-approval`
- **Delivery withheld with an explicit revocation reason; earlier commit retained**: `REV-09`, `REV-10`
- **Documented limitation: a running tool still commits after revocation**: `REV-limit`
- **Delivery boundary: a returned result is not recalled**: `REV-delivery-boundary`
- **Trusted-integrator API, unsupported targets rejected; capability_id bound to one grant**: `REV-api`, `REV-id`
- **Unrevoked clearSession/replay behaviour unchanged; audit failure does not re-open access; receipt content**: `REV-11`, `REV-12`, `REV-receipt`
- **Pending timeout boundary versus approval-time capability validity**: `REV-13a` (approved at exactly the timeout while the capability is valid), `REV-13b` (rejected past the timeout), `REV-13c` (rejected at exactly `expires_at` while the pending action is valid); no tool start on rejection
- **Revocation evidence exports as validated OCSF Base Events and is not an incident**: `REV-ocsf`
- **Start effective point is the tool function call: a revocation from the `tool_execution_started` audit callback prevents the call (session and capability, ALLOW and approval paths)**: `REV-14`, `REV-16`
- **Delivery effective point is the fulfilment of the public promise: a revocation from the `tool_result_delivered` audit callback withholds the raw output; a revocation in any Promise transition before fulfilment is honoured, after it is not**: `REV-15`, `REV-16b`, `REV-19`, `REV-18`
- **Untargeted revocations from the same callbacks do not affect the execution or its output**: `REV-17`

## G1. Tenant Scope (package 1a)
Specification: [tenant-scope.md](tenant-scope.md). Evidence: `tests/tenant-scope.test.ts`; runtime-test mutants: `mutants/tenant/manifest.json` (`npm run mutants:tenant`). Effects are observed through tool doubles, `executor.managedState`, returned content and the cancellation signal; audit events are check-point evidence only.
- **The tenant comes from the signed grant; a request's tenant claim must match it**: `T1.01`, `T1.02` (M30), `T1.03` (M30b), `T1.04`
- **Tenancy mode rejects tenantless or malformed grants; legacy mode rejects tenant grants and tenant targets**: `T1.05` (M31), `T1.06`, `T3.04`
- **A session belongs to one tenant; a capability_id cannot be re-bound to another tenant**: `T1.07` (M32), `T1.09` (M33, component check point), `T1.08` (regression of the kept safeguards; not M33 evidence)
- **Tenant revocation at every check point**: request `T2.01` (M27a), `T2.02` (M27e), `T2.03` (M22); start `T2.04` (M27f), `T2.05` (M27c); approval `T2.06` (M26a), `T2.07` (M26); commit `T2.08` (M15); delivery `T2.10` (M28), `T2.11` (M28a), `T2.12` (M28b)
- **Cancellation is requested for the tenant's running executions; acknowledgement is not termination**: `T2.13` (M29)
- **Execution binding is fixed at start; nothing is re-resolved**: `T2.14` (M33b)
- **A commit before the revocation stays; the later delivery is withheld**: `T2.09`
- **Other tenants are unaffected (start, commit, delivery, no cancellation); receipt lists only the tenant's work**: `T3.01` (M16), `T3.02`, `T3.03`
- **Tenant targets validated fail closed; OCSF exports only the verified tenant**: `T3.05`, `T3.06`

## G1b. Ancestor Chains and Descendant Revocation (package 1b, plan gap G2)
Specification: [ancestor-chains.md](ancestor-chains.md). Evidence: `tests/ancestor-chain.test.ts` (setup: `tests/chain-setup.ts`); runtime-test mutants: `mutants/ancestor/manifest.json` (`npm run mutants:ancestor`, shared gate [mutant-gate.md](mutant-gate.md)). Effects are observed through tool doubles, `executor.managedState`, returned content and the cancellation signal; audit events are check-point evidence only.
- **A valid issuer-signed chain executes and the execution is bound to it (control under every ancestor mutant)**: `C1.01`, `C1.05` (exactly 8 grants), `C5.01` (approval)
- **Chain authentication: every member's signature, both link directions**: `C1.10` (M44, root), `C1.11` (M45, intermediate), `C1.12` (M46, fingerprint), `C1.13` (M47, capability_id)
- **Fail closed: missing parent, chain past a root, no chain from memory, depth, repeated id and cycles, tenant, attenuation, malformed envelopes**: `C1.02` (M38), `C1.03`, `C1.04` (M39), `C1.06` (M40), `C1.07`, `C1.08` (M41), `C1.09` (M43), `C1.16`, `C5.03` (legacy mode)
- **A rejected chain stops before the Guardian decision, pending approval, permit, execution and tool call, and binds nothing**: `C1.15`, `C2.02`, `C2.03`
- **An ancestor id stays bound to its first verified content**: `C2.01` (M42b)
- **The execution's chain is fixed at start; nothing is re-resolved**: `C2.04` (M42a), `C2.05`
- **Approval compares the re-resolved chain with the snapshot, member by member**: `C1.14` (M48), `C5.02`
- **Ancestor revocation at every check point, also before first use**: request `C3.01` (M27b), `C3.02` (M20); start `C3.03` (M27g), `C3.04` (M27d); approval `C3.05` (M34a), `C3.06` (M34); commit `C3.07` (M21); delivery `C3.09` (M35), `C3.10` (M35a), `C3.11` (M35b)
- **Cancellation is requested for running descendants; acknowledgement is not termination**: `C3.12` (M36)
- **A commit before the revocation stays; the later commit and delivery are denied**: `C3.08`
- **No propagation to the parent or siblings; a common ancestor covers both branches**: `C4.01` (M37), `C4.02`
- **Sessions and tenants: an ancestor covers descendants in other sessions of the tenant, a session revocation only its own session; tenant precedence and isolation**: `C4.03`, `C4.04`, `C4.05`
- **Evidence and export name only the verified chain**: `C5.04`, `C5.05`

## G2. Cooperative Containment (A2)
Specification: [cooperative-containment.md](cooperative-containment.md). Evidence: `tests/cooperative-containment.test.ts`. Commits are observed through `executor.managedState`, tool behaviour through harness-owned doubles.
- **Revoke before start: no tool call, no execution, no terminal**: `C01`
- **Commit fence: a commit after revocation is denied and the managed state is unchanged; an earlier commit stays; delivery still withheld**: `C02`, `C03`, `C04`, `C19`
- **Revocation from a callback on the commit path (audit callback, `toJSON`) is seen by the binding check**: `C11a`, `C11b`
- **Commit after the terminal and from detached work is denied**: `C13`, `C15`
- **Audit failure never opens the effect; a lost applied record does not undo the write**: `C16`, `C16b`
- **Acknowledgement is not termination; ignoring the signal gives no false terminal and no `cancelled` outcome**: `C05`, `C06`
- **Reacting tool ends with one `cancelled` terminal; `cancelled` requires this execution's own CancellationError; natural completion is `completed`**: `C07`, `C20`, `C08`
- **Duplicate revoke does not signal again; repeated acknowledgement is idempotent**: `C09`
- **Untargeted and parallel executions are unaffected**: `C10`
- **Tombstone before callbacks; listener exceptions and re-entrancy cannot undo revocation, open the fence or stop other cancellations; late listener called immediately**: `C12`, `C21`
- **Terminal waits for registered work; exactly one terminal in either settlement order**: `C14`, `C17`
- **Execution identity per real invocation, bound to request, session and capability**: `C18`
- **Settlement is observed through the Promise's internal state: a tool's own `then` on its returned or registered Promise cannot produce an early terminal; a changed `constructor` never runs (pinned and restored), and an unpinnable one makes the Promise unobservable and fails the call without a terminal**: `C22`, `C22b`, `C23`
- **An unobservable settlement is not terminal evidence: the call fails with `TypeError`; no terminal record, `execution_terminal` or `whenTerminal()`, also after the work settles; commits are denied with `settlement_unobservable` and registration is closed; a later revocation still signals cancellation**: `C22c`, `C22d`, `C22e`, `C22f`, `C29`
- **A rejected Promise subclass is observed and its rejection handled, in process and at process level (normal exit)**: `C28`, `C28b`
- **No species constructor runs during observation (custom species, subclasses, frozen subclass refused); a species that would reject the derived Promise leaves the process exiting normally**: `C29`, `C29b`
- **Unobservable work is refused before registration and leaves no phantom pending entry**: `C24`
- **A failed `execution_terminal` record call leaves the local terminal intact (`audit_recorded: false`, unconfirmed)**: `C25`
- **The managed state writer is issued once; the view cannot write and returns copies**: `C26`
- **Commit values never reach the audit log**: `C27`

## H. Audit Evidence
- **H1 DENY evidence**: `tests/evals/request-policy.test.ts` (`EVAL-A2`)
- **H2 ASK evidence**: `tests/evals/request-policy.test.ts` (`EVAL-A3`)
- **H3 approval / rejection evidence**: `tests/evals/request-policy.test.ts` (`EVAL-A4` & `EVAL-A5`)
- **H4 correlation_failed**: `tests/evals/correlation.test.ts` (`EVAL-C1`), backed by internal unit evidence in `tests/execution-correlation.test.ts`
- **H5 result withheld + no delivered**: `tests/evals/result-gate-evals.test.ts` (`EVAL-F2` & `EVAL-F3`)
- **H6 identifier semantics**: `tests/execution-correlation.test.ts` exact identifier tests (e.g. "event.request_id is the result-request's own ID")

## Authority Incident Evidence
- **Authority authentication failures**: invalid capability or approval signatures map to `authority_authentication_failure` (`tests/incident-evidence.test.ts`, `AIM-001`, `AIM-006`, `REAL-AUTH-001`, `REAL-AUTH-005`)
- **Authority boundary violations**: capability agent/session/tool-scope mismatch and approval tool/approver mismatch map to `authority_boundary_violation` (`AIM-002..AIM-004`, `AIM-007`, `AIM-008`, `REAL-AUTH-002..REAL-AUTH-004`, `REAL-AUTH-006`, `REAL-AUTH-007`)
- **Operational and lifecycle negative controls are not automatically security incidents**: `AIM-005`, `AIM-009`, `REAL-AUTH-008`
- **Trusted authority context participates in incident identity**: `AIM-010`
- **Legacy pre-authority incident fingerprint compatibility**: `AIM-009A`
- **Real runtime authority evidence reaches the classifier without synthetic event injection**: `REAL-AUTH-001..008`

## I. Oversight Metrics
- **Accuracy and state handling**: `tests/evals/metrics.test.ts` (`EVAL-I1`)
- **Metrics independent of enforcement**: `tests/oversight-metrics.test.ts`

## Adversarial Sequences
- **Sequence 1 (ASK -> attempt to execute before approval)**: `tests/evals/adversarial.test.ts`
- **Sequence 2 (ALLOW -> double consume correlation)**: `tests/evals/adversarial.test.ts`
- **Sequence 3 (Session B uses Session A's reference)**: `tests/evals/adversarial.test.ts`
