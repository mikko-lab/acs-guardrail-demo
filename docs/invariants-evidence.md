# Invariants and Evidence Map

This document maps architectural security invariants to automated evidence across the repository, including evaluation, runtime-authority, incident, correlation, and metrics test suites.

**Current verified baseline:** 378 automated tests, 22 Jest suites, TypeScript typecheck clean.

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
