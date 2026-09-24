# ACS Guardrail Demo

A reference implementation and demonstrator for deterministic runtime controls around agent tool execution. The repository implements a controlled subset of ACS v0.1.0 JSON-RPC tool-call patterns; it does **not** claim full ACS conformance and is not production infrastructure.

**Current scope:** schema and protocol validation, authenticated requests, replay protection, scoped capability authority, deterministic Guardian policy, human oversight, guarded execution, result correlation and gating, in-memory audit evidence, oversight metrics, adversarial evaluation, and deterministic incident classification.

## Architecture and runtime pipeline

The controlled runtime path is:

```text
untrusted tool request
  → schema validation
  → authenticated request envelope
  → replay / timestamp protection
  → scoped capability verification
  → deterministic Guardian policy
  → human oversight when required
  → execution permit boundary
  → correlated result
  → result Guardian / result gating
  → audit evidence
```

`GuardedExecutor` wires these stages in a fixed order. Schema failures are addressable and produce signed denial responses where the protocol permits. Request signatures are verified before replay checks; replay and timestamp failures stop processing before capability lookup. A capability is then resolved from authenticated request context and verified before Guardian policy evaluation.

Guardian decisions are `ALLOW`, `ASK`, or `DENY`. `DENY` blocks execution. `ASK` creates a pending action that must be resolved through the local human-approval path. `ALLOW`, or a valid approval for `ASK`, crosses an execution-permit boundary. The execution result is registered against the originating request, converted into a signed result request, correlated back to that request, and evaluated by the Result Guardian before delivery. Result-policy denial withholds raw output and records evidence.

## Trust boundaries and bounded authority

The model separates agent-proposed intent from execution authority:

- The agent or language model may interpret a task and propose a tool call.
- The deterministic runtime verifies authentication, freshness, capability scope, policy, approval, correlation, and result authorization.
- The LLM does not enforce or monitor these controls.

Capabilities are signed `CapabilityGrantV1` objects and bind authenticated authority context to:

- `agent_id`
- `session_id`
- an exact `allowed_tools` list
- an `issued_at` / `expires_at` validity window

Wildcard tool scopes are deliberately unsupported. Missing, expired, not-yet-valid, malformed, wrong-agent, wrong-session, and wrong-tool capabilities fail closed before Guardian evaluation. A capability is necessary authority context, but is not by itself execution authorization: Guardian policy remains a separate gate. Capability grants may be reused while their signed agent/session/tool/time scope remains valid; `capability_id` is not a nonce.

The capability provider is repository-local runtime authority context, not an ACS wire-schema field. `agent_id` is an authenticated request claim in this demonstrator, not independently verified workload identity.

## Human oversight

An `ASK` decision creates a pending action. The local profile supports human approval only; agent or service approvers are rejected. Approval uses a cryptographically verified, tool-bound `ApprovalGrantV2` whose decision is bound to:

- the pending `session_id` and `request_id`
- the exact tool
- the configured human approver claim
- the approval timestamp

Invalid signatures, mismatched request/session/tool/approver bindings, unsupported `ApprovalGrantV1` grants, and expired or not-yet-valid approvals do not authorize execution. `timeout_disposition=allow` is deliberately rejected. Pending approval and rejection/expiry state are consumed fail closed, and duplicate concurrent approval consumes the pending authority at most once.

Verification of an approval signature demonstrates that the configured approval authority signed the claim; it does not prove the physical identity or intent of a human person, nor does this repository integrate with a generic enterprise identity provider.

## Execution correlation and result gating

Execution results are correlated to the originating request using the session, request reference, and exact tool name. Missing, consumed, cross-session, or mismatched references fail closed. Request authorization does not imply result authorization: the Result Guardian evaluates the correlated result before delivery. A result denial withholds raw output, returns a blocked representation, records `tool_result_withheld`, and does not record `tool_result_delivered`.

This is evidence about the controlled runtime path, not a proof that every possible execution in an environment is universally mediated.

## Concurrent authority isolation

The concurrency regression suite records tested invariants of this implementation, not universal race-condition safety:

- same-session concurrent `ALLOW` and `DENY` decisions remain request-local;
- concurrent `ASK` actions remain independently bound to their requests; and
- duplicate concurrent approval executes at most once.

## Tamper-evident audit evidence

`AuditCollector` stores runtime evidence in memory. Each event contains a canonicalized, deterministic SHA-256 hash chain with:

- explicit `GENESIS` as the first `previous_hash`;
- `previous_hash` linking each event to its predecessor;
- `event_hash` over the canonical event content; and
- detached metadata snapshots on record and detached event copies on read.

The integrity APIs are:

- `audit.getHeadHash()`
- `audit.verifyIntegrity(expectedHeadHash?)`
- `AuditCollector.verifyIntegrity(events, expectedHeadHash?)`
- `audit.assertIntegrity(events?, expectedHeadHash?)`

`verifyIntegrity` returns a deterministic integrity result. `assertIntegrity` is the fail-closed form and raises `AuditIntegrityError` when verification fails.

### Structural verification

With only the supplied linked event stream, structural verification detects missing hashes, a wrong genesis value, broken links, event mutation, reordering, and other inconsistent modification within that stream.

### Trusted-head verification

When a separately trusted expected head hash is supplied, verification can also detect suffix truncation and replacement with a different final chain head, even when the remaining prefix is structurally valid.

Without a trusted head or external anchor, an attacker capable of rewriting the entire event stream can recompute the hash chain. The current audit mechanism therefore does **not** provide immutable storage, non-repudiation, external anchoring, restart persistence, durable append-only storage, SIEM integration, or distributed verification.

The audit collector is intentionally mutable and in memory; it is evidence for the controlled runtime, not an immutable ledger.

## Oversight metrics and incident evidence

The post-hoc metrics layer derives decision counts and rates, escalation and latency measures, human-review state, and correlation-failure breakdowns from the audit stream. It does not prove universal mediation or act as an enforcement gate.

`IncidentClassifier` deterministically derives selected security and boundary incidents from trusted audit evidence, including replay, freshness, correlation, result-policy, authority-authentication, and selected authority-boundary failures. Not every authorization or lifecycle outcome is promoted to a security incident.

## Evaluation and test evidence

`npm run verify` runs the TypeScript typecheck and Jest suite. The current verification result is:

- **23 test suites passed**
- **394 tests passed**
- **0 snapshots**

The major tested categories are:

- schema and protocol validation;
- authentication and signature integrity;
- replay protection;
- capability authority and fail-closed scope checks;
- human approval binding and lifecycle behavior;
- execution permits;
- concurrent authority isolation;
- result correlation;
- result gating and withholding;
- audit evidence and detached reads;
- tamper detection and trusted-head verification;
- adversarial runtime cases and state-machine isolation;
- oversight metrics; and
- incident evidence and deterministic classification.

Relevant focused coverage includes `tests/runtime-authority.test.ts`, `tests/evals/authority-adversarial.test.ts`, `tests/evals/concurrent-authority.test.ts`, and `tests/audit.test.ts`.

## Evidence links

For exact mappings from claims to implementation and tests, see:

- [docs/invariants-evidence.md](docs/invariants-evidence.md)
- [docs/acs-crosswalk.md](docs/acs-crosswalk.md)
- [CHANGELOG.md](CHANGELOG.md)
- [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md)

## ACS provenance

- **ACS wire/specification version:** v0.1.0
- **Upstream repository/project version at current review:** 0.1.2
- **Vendored source commit:** `dc265475139a922824f0c817e2ecc2a2ce31c06c`
- **Vendored path:** `schemas/`

The crosswalk distinguishes pinned normative requirements, underspecified pinned behavior, local implementation policy, and non-normative context.

## Limitations and non-goals

- This is a reference/demo implementation, not production infrastructure.
- No full ACS conformance or certification claim is made.
- Runtime, replay, correlation, pending-action, and audit state are in memory; there is no durable persistence across process restart.
- The audit hash chain is tamper-evident for the supplied verified stream, but there is no immutable storage, durable append-only backend, non-repudiation, external anchoring, SIEM integration, or distributed verification.
- There is no external identity provider, independent workload-identity provider, institutional identity proof, or physical-human identity/intent proof.
- There is no capability revocation mechanism or distributed capability store.
- There is no universal mediation proof or coverage proof.
- There are no production SLA, high-availability, or distributed-state guarantees.
- Metrics are observability, not enforcement.
- The local authority profile requires tool-bound `ApprovalGrantV2`; primitive `ApprovalGrantV1` remains available only for historical/backwards-compatible tests and is rejected by the authority-enabled runtime.
- Approval `issued_at` freshness failures fail closed but do not emit a dedicated audit event.

## Verification

```bash
npm run verify
```

## License and attribution

- **Project code:** [Apache License 2.0](LICENSE)
- **Vendored ACS schemas:** retain their upstream attribution and Apache 2.0 license.

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [schemas/ATTRIBUTION.md](schemas/ATTRIBUTION.md) for full licensing details.
