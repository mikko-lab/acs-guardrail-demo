# Changelog

## Unreleased

### Added
- **Tamper-evident audit chain:** Audit events now carry a deterministic SHA-256 `event_hash` linked through `previous_hash`, with an explicit `GENESIS` convention.
- **Trusted head verification:** Added `getHeadHash()` and `verifyIntegrity(events, expectedHeadHash?)` / `assertIntegrity(events?, expectedHeadHash?)` so callers can combine linked validation with a trusted expected head for suffix-truncation detection.
- **Fail-closed audit verification:** Added deterministic integrity results and `AuditIntegrityError` for callers that require verification to fail closed. Regression coverage includes payload mutation, deletion, reordering, hash tampering, trusted-head checks, and request-scoped reads.

### Trust model and limitations
- Linked verification detects inconsistent modification within the same stream.
- A trusted expected head detects suffix truncation and a different final event, even when the remaining prefix is otherwise structurally valid.
- Without a trusted expected head or external anchor, an attacker who rewrites the entire stream can recompute the chain and evade detection.
- The chain is in-memory and restart persistence is not provided. It does not provide immutable storage, non-repudiation, external anchoring, or a durable audit backend.

## [v0.3.0] - 2026-09-22

### Added
- **Deterministic incident evidence (WP-05):** Added `IncidentEnvelopeV1` and deterministic incident classification for selected runtime security and boundary events.
- **Scoped runtime capabilities (WP-06A):** Added Ed25519-signed `CapabilityGrantV1` with agent, session, exact-tool, and time-window scope.
- **Tool-bound approval (WP-06A):** Added `ApprovalGrantV2` with cryptographic binding to session, request, exact tool, decision, and configured approver claim.
- **Runtime authority enforcement (WP-06B):** Integrated capability verification before Guardian evaluation and required `ApprovalGrantV2` for authority-enabled `ASK` flows.
- **Authority adversarial evaluation (WP-07A):** Added `AEV-001..018` and `NORMAL-001..003` covering authority ordering, fail-closed behavior, trusted evidence, approval lifecycle, and result governance.
- **Authority incident mapping (WP-07B):** Added `authority_authentication_failure` and `authority_boundary_violation` classifications derived from selected runtime authority evidence.

### Security / Correctness
- Request signature and replay checks occur before capability resolution.
- Capability verification occurs before Guardian policy evaluation.
- A valid capability is necessary authority context but is not sufficient execution authorization.
- The authority-enabled runtime rejects `ApprovalGrantV1` and requires tool-bound `ApprovalGrantV2` for `ASK` resolution.
- Invalid authority signatures and selected agent/session/tool/approver boundary violations fail closed and produce deterministic incident evidence.
- Operational and lifecycle outcomes are deliberately not promoted automatically to security incidents.
- Legacy pre-authority incident fingerprint behavior is regression-tested for backward compatibility.

### Evaluation
- Automated baseline: 378 tests across 22 Jest suites.
- TypeScript typecheck clean.
- Runtime authority suite: `AUTHR-001..021`.
- Authority adversarial suite: `AEV-001..018` and `NORMAL-001..003`.

### Limitations
- No external IAM or independent workload identity.
- No capability revocation or distributed capability store.
- No durable replay, correlation, or pending-action state across process restart.
- No physical-human identity or intent proof.
- Approval `issued_at` freshness failures currently lack a dedicated audit event.
- Audit remains in-memory; no tamper-evident ledger or SIEM integration is claimed.
- No ACS certification or full ACS conformance claim.

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
