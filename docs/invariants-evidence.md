# Invariants and Evidence Map

This document maps the architectural security invariants to their respective automated tests in the evaluation suite (`tests/evals/`).

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
- **Tool Binding**: NOT IMPLEMENTED / NOT CLAIMED (`D3`)
- **Expired action retry fails**: `tests/evals/isolation.test.ts` (`EVAL-D4`)
- **Rejection is final**: `tests/evals/isolation.test.ts` (`EVAL-D5`)

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

## I. Oversight Metrics
- **Accuracy and state handling**: `tests/evals/metrics.test.ts` (`EVAL-I1`)
- **Metrics independent of enforcement**: `tests/oversight-metrics.test.ts`

## Adversarial Sequences
- **Sequence 1 (ASK -> attempt to execute before approval)**: `tests/evals/adversarial.test.ts`
- **Sequence 2 (ALLOW -> double consume correlation)**: `tests/evals/adversarial.test.ts`
- **Sequence 3 (Session B uses Session A's reference)**: `tests/evals/adversarial.test.ts`
