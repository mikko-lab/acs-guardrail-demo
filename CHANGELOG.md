# Changelog

## [v0.2.0] - 2026-09-21

### Added
- **Correlation failure evidence**: The `ExecutionCorrelationStore` now generates detailed audit events on failure (including `request_id`, `request_id_ref`, `session_id`, `tool`, `disposition`, and `reason`).
- **Runtime oversight metrics**: A post-hoc observability layer computing decision distributions, review latency, correlation failure breakdown, and escalation rates.
- **Conformance-oriented evaluation suite**: A new testing layer covering request policy, replay protection, correlation, human oversight/isolation, result gating, audit evidence, oversight metrics, and verifying/exercising adversarial state-machine scenarios. Total test count is now 266 across 17 suites.

### Security / Correctness
- **Fail-closed unresolved correlation**: Correlation strictly fails closed on missing, reused, or cross-session references.
- **Session-aware metrics correlation**: Decision latency relies on a composite `session_id:request_id` key to prevent cross-correlation errors.
- **Human review expiry semantics**: Pending states cannot be resurrected once rejected or expired.
- **Adversarial / state-isolation verification**: Negative assertions explicitly verify the absence of unauthorized side effects (no `tool_execution_started` without valid authorization).

### Limitations
- **Coverage intentionally not reported**: The audit model cannot structurally guarantee 100% mediation without independent external instrumentation.
- **ApprovalGrant tool binding not implemented**: The grant signs the `session_id` and `request_id`, but not the tool identity itself.
- **Audit remains in-memory**: No persistent, tamper-evident ledger or SIEM integration is claimed.
