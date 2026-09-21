# ACS Guardrail Demo

A reference implementation demonstrating a deterministic enforcement boundary for a scoped subset of ACS v0.1.0 JSON-RPC tool-call hooks.

**Status / Scope:**
- Release candidate: v0.2.0
- Scope: Runtime controls, human oversight, execution correlation, audit evidence, oversight metrics, and conformance-oriented evaluation.
- No certification or full ACS conformance claim is made.

## Architecture & Control Flow

Within the demo's controlled runtime path, the `GuardedExecutor` applies the following enforcement sequence:

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
          Result Guardian
          ├── DENY → raw output withheld
          └── ALLOW → result delivered
```

## Security Model

The security model separates the AI agent's intent from execution authority:
- The AI agent (or LLM) can interpret tasks and propose tool calls.
- A deterministic runtime strictly decides execution rights.
- Authorization, state transitions, replay protection, human approval, correlation, and result delivery are handled programmatically by the execution environment, independent of the AI agent's instructions. The LLM itself does not enforce or monitor security.

## Runtime Controls

### Guardian request gate
Implemented dispositions:
- `ALLOW`: Proceeds to execution.
- `DENY`: Blocks execution.
- `ASK`: Blocks execution pending explicit approval.

Unknown tools default to deny. `MODIFY` and `DEFER` dispositions are not implemented.

### Human oversight
Implemented for `ASK` decisions:
- Cryptographically signed approval grant verification.
- `approve` / `reject` / expiry semantics.
- Session binding and request binding.
- Pending-state isolation.
- Rejection and expiry finality.

An approval grant for one session or request_id cannot resolve a different request. 
**Note**: `ApprovalGrantV1` signs `session_id` and `request_id`, but NOT the tool identity itself. The executor safely resumes the stored pending action (preventing runtime tool swapping), but the grant itself does not cryptographically bind tool identity. Tool binding inside the grant is NOT IMPLEMENTED / NOT CLAIMED.

### Replay protection
- Timestamp skew validation.
- Session-scoped `request_id` replay detection.
- Same request in the same session fails.

### Execution correlation
Correlation tightly binds the execution phase to the Result Gate using:
- `session_id`
- `request_id_ref`
- `tool` name

Tested failure scenarios include unknown reference, consumed reference, tool name mismatch, and cross-session reference.

### Result gate
Request authorization does not imply result authorization. If the Result Guardian evaluates to `DENY`:
- Raw output is withheld.
- A blocked/withheld result representation is returned instead.
- A `tool_result_withheld` audit event is emitted.
- No `tool_result_delivered` event is emitted.

## Audit Evidence

The system implements an in-memory `AuditCollector`. 

Correlation failures generate a `correlation_failed` event containing the following relevant fields:
- `request_id`
- `request_id_ref`
- `session_id`
- `tool`
- `disposition` (deny)
- `reason`

Reasons for correlation failure are `unresolved_request_id_ref` or `tool_name_mismatch`. Note that unknown and already consumed references share the same `unresolved_request_id_ref` reason at this layer.

The audit collection is purely local. It is NOT a tamper-evident, immutable ledger, a persistent audit backend, or a SIEM integration.

## Oversight Metrics

A post-hoc observability layer deriving metrics from the audit event stream. It includes:
- Total decisions
- Allow / deny / ask counts
- Allow / deny / ask rates
- Escalation rate
- Decision latency
- Completed human reviews
- Pending human reviews
- Expired reviews
- Human review latency
- Correlation failure count
- Correlation reason breakdown

Latency and review-event correlation uses session-aware request identity to prevent cross-session event pairing.

**No Guardian coverage metric is reported.**
Current internal audit events cannot prove universal mediation or reliably measure executions that might bypass the controlled runtime path without independent external instrumentation.

## Evaluation / Test Evidence

The repository includes an automated evaluation layer covering conformance-oriented and adversarial scenarios. 

**Current baseline**:
- 266 automated tests
- 17 Jest suites
- TypeScript typecheck clean

The evaluation exercises the following domains:

### A Request policy
`EVAL-A1..A6`

### B Replay
`EVAL-B1..B4`

### C Correlation
`EVAL-C1..C4`

### D Human oversight / isolation
`EVAL-D1`, `EVAL-D2`, `EVAL-D4`, `EVAL-D5`
(D3 Tool Binding: NOT IMPLEMENTED / NOT CLAIMED)

### F Result gate
`EVAL-F1..F5`

### H Audit evidence
`H1..H6`

### I Metrics
`EVAL-I1`

### Adversarial sequences
`Sequence 1–3` (exercising state-machine bypass attempts).

## Evidence Links

For exact mappings from claims to implementation and test code, see:
- [docs/invariants-evidence.md](docs/invariants-evidence.md)
- [docs/acs-crosswalk.md](docs/acs-crosswalk.md)
- [CHANGELOG.md](CHANGELOG.md)
- [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md)

## ACS Provenance

- **ACS version**: v0.1.0
- **Upstream commit**: `dc265475139a922824f0c817e2ecc2a2ce31c06c`
- **Vendored path**: `schemas/`

The crosswalk explicitly distinguishes between pinned normative requirements, underspecified pinned behavior, local implementation policy, and non-normative context.

## Limitations / Non-goals

- This is a reference/demo implementation, not production infrastructure.
- In-memory audit only.
- No persistent / tamper-evident audit backend.
- No universal mediation proof.
- No coverage proof.
- No cryptographic tool binding inside `ApprovalGrantV1`.
- No external IAM integration.
- No institutional identity proof.
- No physical human intent proof.
- No durable replay/correlation/pending state across process restart.
- No distributed/multi-process state guarantees.
- No full ACS Audit implementation.
- No ACS certification.
- No full ACS conformance claim.
- Metrics are observability, not enforcement.

## Verification

To run the automated verification suite:

```bash
npm run verify
```

Current baseline: 266 tests passed, 17 test suites passed, TypeScript typecheck clean.

## License / Attribution

- **Project Code:** [Apache License 2.0](LICENSE)
- **Vendored ACS Schemas:** Retain their upstream attribution and Apache 2.0 license.

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md) for full details.
