# ACS Guardrail Demo

A reference implementation demonstrating a deterministic enforcement boundary for a scoped subset of ACS v0.1.0 JSON-RPC tool-call hooks.

**Status / Scope:**
- Release: v0.3.0
- Scope: Runtime controls, scoped capabilities, human oversight, execution correlation, result gating, audit evidence, oversight metrics, adversarial evaluation, and deterministic incident classification.
- No certification or full ACS conformance claim is made.

## Architecture & Control Flow

Within the demo's controlled runtime path, the `GuardedExecutor` applies the following enforcement sequence:

```text
Tool request
  ↓
Schema validation
  ↓
Request signature verification
  ↓
Replay / freshness checks
  ↓
Scoped capability verification
  ↓
Guardian request decision
  ├── DENY → blocked + evidence
  ├── ASK → pending human oversight
  │          ├── reject → blocked
  │          ├── expire → blocked
  │          └── ApprovalGrantV2 → verification
  │                                  ↓
  │                              execution
  └── ALLOW → execution
                  ↓
              correlation
                  ↓
             Result Guardian
              ├── DENY → raw output withheld
              └── ALLOW → result delivered
```

A valid capability is necessary authority context, but it is not sufficient execution authorization. Guardian policy and, for `ASK`, human approval remain separate gates. Result authorization is evaluated separately after execution.

## Security Model

The security model separates AI-proposed intent from execution authority:
- The AI agent or LLM can interpret tasks and propose tool calls.
- A deterministic runtime decides execution rights.
- Request authentication, replay protection, scoped capabilities, Guardian policy, human approval, correlation, result gating, and audit evidence are handled programmatically outside the LLM.
- The LLM itself does not enforce or monitor these controls.

This demo does not claim independent workload identity, institutional identity proof, or physical-human identity verification.

## Runtime Authority

### Request authentication
ACS request envelopes are authenticated before capability resolution. The current request-authentication mechanism uses HMAC-SHA256; capability and approval grants use Ed25519 separately.

### Scoped capabilities
The runtime requires a server-side `CapabilityGrantV1` before Guardian evaluation.

The signed capability binds:
- `capability_id`
- `agent_id`
- `session_id`
- exact `allowed_tools`
- `issued_at`
- `expires_at`

Capability verification uses Ed25519 signatures and exact tool matching. Wildcard tool scopes are unsupported.

The capability provider is repository-local runtime authority context and is not part of the ACS v0.1.0 wire schema.

`agent_id` is an authenticated request claim in this demo, not an independently verified workload identity.

Capabilities may be reused while their signed agent/session/tool/time scope remains valid. `capability_id` is not a nonce.

## Runtime Controls

### Guardian request gate
Implemented dispositions:
- `ALLOW`: Proceeds toward execution.
- `DENY`: Blocks execution.
- `ASK`: Blocks execution pending explicit human approval.

Unknown tools default to deny. `MODIFY` and `DEFER` are not implemented. `timeout_disposition: allow` is deliberately unsupported.

### Human oversight
The authority-enabled `ASK` path requires `ApprovalGrantV2`.

The signed V2 grant binds:
- decision (`approve` / `reject`)
- `session_id`
- `request_id`
- exact `tool`
- approver claim
- `issued_at`

The runtime verifies the grant against trusted pending-action context before execution. Implemented behavior includes Ed25519 signature verification, exact tool binding, session/request binding, configured approver binding, approval/rejection semantics, expiry, pending-state isolation, and rejection/expiry finality.

`ApprovalGrantV1` remains available at primitive level for historical/backwards-compatible tests, but the authority-enabled runtime rejects V1 grants.

A valid V2 signature proves that the configured approval authority signed a payload containing the approver claim. It does not prove the physical identity or intent of a human person.

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

## Audit & Incident Evidence

The system implements an in-memory `AuditCollector`. Runtime authority evidence includes `capability_verified`, `capability_rejected`, `approval_verification_failed`, `human_approval`, `human_rejection`, and `approval_expired`.

`IncidentClassifier` deterministically derives selected security and boundary incidents from audit evidence.

Current incident types are:
- `replay_attempt`
- `correlation_failure`
- `result_policy_violation`
- `request_freshness_violation`
- `authority_authentication_failure`
- `authority_boundary_violation`

Authority authentication incidents currently cover invalid capability or approval signatures.

Authority boundary incidents currently cover:
- capability agent mismatch
- capability session mismatch
- capability tool-scope mismatch
- approval tool-binding mismatch
- wrong configured approver identity

Not every authorization failure is promoted to a security incident. Missing capabilities, provider failures, expired or not-yet-valid capabilities, malformed or unsupported scopes, ApprovalGrantV1 rejection, pending-action lookup failures, ordinary human rejection, and approval expiry are not automatically classified as security incidents.

Authority incident evidence preserves trusted request or pending-action context rather than treating spoofed grant fields as trusted facts. Legacy pre-authority incident fingerprint behavior is regression-tested for backward compatibility.

Correlation failures emit `correlation_failed` evidence containing relevant request, session, reference, tool, disposition, and reason fields. Unknown and already-consumed references currently share the `unresolved_request_id_ref` reason at this layer.

The audit collection is local and in memory, with a deterministic SHA-256 hash chain for detecting changes to the collected evidence. The first event uses the explicit `GENESIS` previous-hash value; each later event hashes its canonical content and the preceding event hash. `verifyIntegrity()` returns a deterministic failure result and `assertIntegrity()` raises `AuditIntegrityError`, so callers can fail closed. This detects mutation, deletion, reordering, and hash tampering in the verified event stream; it does not provide a persistent ledger, a SIEM integration, protection against compromise of the live process, or proof of universal mediation.

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

The repository includes automated conformance-oriented, adversarial, authority, isolation, result-gate, audit, incident, and metrics tests.

**Current baseline:**
- 378 automated tests
- 22 Jest suites
- TypeScript typecheck clean

### Request policy
`EVAL-A1..A6`

### Replay
`EVAL-B1..B4`

### Correlation
`EVAL-C1..C4`

### Human oversight / isolation
Existing `EVAL-D` isolation tests plus the authority runtime and adversarial suites below.

### Runtime authority
`AUTHR-001..021` in `tests/runtime-authority.test.ts`.

The suite covers scoped capabilities, fail-closed capability verification, ApprovalGrantV2 enforcement, tool and approver binding, approval lifecycle behavior, capability reuse, Guardian composition, and Result Guardian composition.

### Authority adversarial evaluation
`AEV-001..018` plus `NORMAL-001..003` in `tests/evals/authority-adversarial.test.ts`.

The suite covers invalid signatures, agent/session/tool-scope mismatches, missing/provider-failed capabilities, ApprovalGrantV1 rejection, tool-bound V2 failures, wrong approver identity, approval expiry, replay/signature ordering, result withholding, trusted evidence, and normal oversight outcomes.

### Result gate
`EVAL-F1..F5`

### Audit and incident evidence
Dedicated audit and incident tests verify authority incident mapping, trusted-context preservation, negative classification controls, real runtime evidence, and legacy incident fingerprint compatibility.

### Oversight metrics
`EVAL-I1` plus dedicated metrics unit tests.

### Adversarial sequences
State-machine and isolation sequences under `tests/evals/adversarial.test.ts`.

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
- In-memory audit only; the hash chain is tamper-evident for the verified stream but is not durable across process restart, an external immutable ledger, or a SIEM integration.
- No universal mediation proof or coverage proof.
- No external IAM integration or independent workload-identity provider.
- `agent_id` is an authenticated request claim in the local request-authentication model, not independent workload identity.
- No institutional identity proof.
- No physical-human identity or intent proof.
- No capability revocation mechanism.
- No distributed capability store.
- No durable replay/correlation/pending state across process restart.
- No distributed or multi-process state guarantees.
- No full ACS Audit implementation.
- No ACS certification or full ACS conformance claim.
- Metrics are observability, not enforcement.
- `ApprovalGrantV1` itself remains non-tool-bound; the active authority-enabled runtime instead requires tool-bound `ApprovalGrantV2`.
- Approval verifier `SESSION_MISMATCH` and `REQUEST_MISMATCH` checks exist at primitive level but are not normally runtime-reachable through `GuardedExecutor`, because pending-action lookup by session/request happens first.
- Approval `issued_at` freshness failures currently fail closed but do not emit a dedicated audit event.

## Verification

To run the automated verification suite:

```bash
npm run verify
```

Current baseline: 378 tests passed, 22 Jest suites passed, TypeScript typecheck clean.

## License / Attribution

- **Project Code:** [Apache License 2.0](LICENSE)
- **Vendored ACS Schemas:** Retain their upstream attribution and Apache 2.0 license.

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md) for full details.
