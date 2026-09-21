# ACS Guardrail Demo v0.2.0

A reference implementation demonstrating a deterministic enforcement boundary for a scoped subset of ACS v0.1.0 JSON-RPC tool-call hooks.

> **Disclaimer**: This is a demo/reference implementation, not production infrastructure. It is strictly scoped to demonstrate execution gating and architectural security boundaries. It is not affiliated with, nor endorsed by, the OWASP Foundation or the Agent Control Standard project. **No ACS certification claim is made.**

## Architecture & Control Flow

Within the demo's controlled runtime path, `GuardedExecutor` applies the following enforcement sequence:

```text
Tool request
  ↓
Schema / signature / replay checks
  ↓
Guardian request decision
  ├── DENY → blocked + evidence
  ├── ASK → pending human oversight
  │          ├── reject → blocked
  │          ├── expire → blocked
  │          └── approve → execution
  └── ALLOW → execution
               ↓
          correlation
               ↓
          result Guardian (Result Gate)
          ├── DENY → withheld
          └── ALLOW → delivered
```

Audit events are generated for the instrumented lifecycle and decision points described below.

## Implemented Runtime Controls (v0.2.0)

### Request Guardian & Execution Gate
- **Request Policy**: Enforces `allow`, `deny`, and `ask` decisions strictly. Unknown tools default to `deny`.
- **Human Approval**: `ask` decisions require an out-of-band cryptographic approval grant.
- **Fail-Closed Paths**: Rejections and expirations fail closed.

### Replay & Session Protection
- **Timestamp validation**: Requests outside a fixed skew window are rejected.
- **Session-scoped deduplication**: Identical `request_id`s within the same session are rejected.

### Result Gate & Correlation
- **Result Guardian**: Evaluates tool output. If denied, raw output is withheld and the executor returns a blocked/withheld result representation.
- **Strict Correlation**: The Result Gate is tightly coupled to the execution phase. Correlation is enforced internally, binding `session_id`, `request_id_ref`, and tool name.

## Audit Evidence & Oversight Metrics

### Audit Collection
The system implements an in-memory `AuditCollector` to record lifecycle events.
- **Fail-closed Correlation**: Unresolved references or correlation mismatches generate a `correlation_failed` event and fail closed. Events include `request_id`, `request_id_ref`, `session_id`, `tool`, `disposition`, and `reason` (`unresolved_request_id_ref` or `tool_name_mismatch`).

### Oversight Metrics
A post-hoc observability layer deriving metrics from the audit event stream:
- **Decision distribution**: Total decisions, allow/deny/ask counts and rates.
- **Review latency**: Decision latency and human review latency (completed, expired, pending).
- **Correlation failures**: Counts and reason breakdown.
- **Escalation rate**.

## Limitations / Non-goals

- **Infrastructure**: Demo/reference implementation, not production infrastructure.
- **State Durability**: Replay, correlation, pending approvals, and audit states are strictly in-memory. There are no durable state guarantees across process restarts, and no distributed/multi-process state synchronization.
- **Audit Backend**: No persistent, tamper-evident audit backend, immutable log, or SIEM integration.
- **Coverage**: No universal mediation or coverage proof. The current audit model cannot structurally guarantee 100% mediation without independent external instrumentation.
- **Tool Binding**: No cryptographic tool binding in `ApprovalGrantV1`. The grant signs the `session_id` and `request_id`, but not the tool identity itself.
- **Human Identity**: No external IAM integration or physical human intent authentication (institutional identity proofs are out of scope).
- **Enforcement**: Metrics are post-hoc observability only, not an enforcement layer.
- **Certification**: No ACS certification claim is made.

## Evaluation & Conformance Evidence

The repository contains an evaluation test layer spanning 17 test suites and 266 automated tests. These verify schemas, signatures, replay protection, isolation, adversarial sequences, and oversight metrics.

Key evaluation vectors tested:
- **Domain A**: Request policy (ALLOW, DENY, ASK).
- **Domain B**: Replay and duplicate attempts.
- **Domain C**: Correlation attacks (unknown references, wrong tools, cross-session steals).
- **Domain D & G**: Session and approval isolation (cross-session state theft attempts, finality of rejections).
- **Domain F**: Result gate (withheld outputs, metric independence).
- **Domain I**: Oversight metrics accuracy.
- **Negative Assertions**: Tests explicitly assert that forbidden outcomes (e.g., `tool_execution_started` without authorization) do not occur.

## License & Attribution

- **Project Code:** [Apache License 2.0](LICENSE)
- **Vendored ACS Schemas:** Retain their upstream attribution and Apache 2.0 license.

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md) for full details.
