# ACS Crosswalk: Implementation vs. ACS Specification

This document maps the actual implementation of the ACS Guardrail Demo against the Agent Control Standard (ACS) v0.1.0 conformance requirements.

## Claim Discipline

- This document reflects the CURRENT implemented state of the repository.
- **It is not an ACS conformance claim.** The project explicitly scopes down features to focus on a minimal, high-assurance execution boundary.
- **Crosswalk evaluated against pinned ACS schemas:**
  - ACS version: v0.1.0
  - Upstream Commit SHA: `dc265475139a922824f0c817e2ecc2a2ce31c06c`
  - Vendored path: `schemas/`
- Status mapping: `IMPLEMENTED`, `PARTIAL`, `NOT IMPLEMENTED`, `NOT CLAIMED`, `OUT OF SCOPE`, `UNDERSPECIFIED IN PINNED SPEC`.

For exact test evidence of these claims, see `docs/invariants-evidence.md` and the referenced evaluation, runtime-authority, incident, correlation, and metrics test suites.

## Repository-Local Runtime Authority

The following controls are repository-local security policy layered around the scoped ACS tool-call runtime. They are not additions to the normative ACS v0.1.0 wire specification and do not constitute an ACS conformance claim.

- `CapabilityGrantV1`: server-side authority context binding `agent_id`, `session_id`, exact `allowed_tools`, and a signed validity window. Verification uses Ed25519 and exact tool matching; wildcard scopes are unsupported.
- `ApprovalGrantV2`: repository-local signed approval payload binding decision, session, request, exact tool, approver claim, and `issued_at`.
- The authority-enabled `GuardedExecutor` path requires a valid scoped capability before Guardian evaluation and requires `ApprovalGrantV2` when Guardian returns `ASK`.
- A valid capability is necessary authority context but is not sufficient execution authorization; Guardian and Result Guardian remain independent controls.
- `ApprovalGrantV1` remains available at primitive level but is rejected by the authority-enabled runtime path.

Known local-policy limitations include no external IAM, no independent workload identity, no capability revocation, and no distributed authority-state store.

## ACS-Core

### Hook Taxonomy
- **Normative pinned requirement:** The ACS specification defines JSON-RPC hooks under prefixes like `steps/*`, `handshake/*`, and `system/*`.
- **ACS profile:** ACS-Core
- **Status:** PARTIAL
- **Implementation:** The runtime exclusively routes and validates `steps/toolCallRequest` and `steps/toolCallResult` using vendored ACS v0.1.0 JSON schemas (`src/schema-validator.ts`).
- **Limitations:** Does not support `handshake/*` or `system/*` hooks.

### Dispositions & Decision Honoring
- **Normative pinned requirement:** The observed agent must honor Guardian decisions and support the defined dispositions: ALLOW, DENY, MODIFY, ASK, DEFER.
- **ACS profile:** ACS-Core
- **Status:** PARTIAL
- **Implementation:** The `GuardedExecutor` implements a hard execution gate that natively enforces `allow`, `deny`, and `ask` decisions (`tests/evals/request-policy.test.ts`).
- **Limitations:** `modify` and `defer` dispositions are explicitly NOT IMPLEMENTED in this demo. `timeout_disposition: allow` is deliberately unsupported.

### Baseline Signature (HMAC-SHA256)
- **Normative pinned requirement:** Authenticate the channel using a baseline HMAC-SHA256 signature over the canonical envelope.
- **ACS profile:** ACS-Core
- **Status:** IMPLEMENTED
- **Implementation:** `SignatureService` enforces strict base64 standard decoding, canonicalizes the envelope (JCS), and uses `timingSafeEqual` to verify signatures (`tests/signature-service.test.ts`).
- **Repository local policy:** Uses a local strict profile for HKDF-SHA256 derivation (empty salt, UTF-8 `session_id`).

### Request ID Correlation & Resolution (Issue #118)
- **Normative pinned requirement:** The schema defines `request_id_ref` as a field intended to correlate a result back to its original request.
- **ACS profile:** ACS-Core
- **Status:** UNDERSPECIFIED IN PINNED SPEC
- **Local implementation policy:** IMPLEMENTED
- **Implementation:** Current pinned ACS text does not fully specify the exact behavioral lifecycle of `request_id_ref`. This demo implements a session-bound resolution policy: it correlates references against local state, checks tool-name matching, records `correlation_failed` audit evidence upon failure, and fails closed for unresolved references (`tests/evals/correlation.test.ts`).

## ACS-Trace (Audit & Metrics)

### OTel / OCSF Event Emission
- **Normative pinned requirement:** Emit OTel or OCSF events for supported ACS steps.
- **ACS profile:** ACS-Trace
- **Status:** NOT IMPLEMENTED
- **Limitations:** No OpenTelemetry or OCSF conformant event emission. Relies entirely on an in-memory custom `AuditCollector`.

### Immutable Audit Ledger & Persistence
- **Non-normative context:** Tamper-evident ledger, cryptographic receipt chain, SIEM integration.
- **ACS profile:** ACS-Trace (Related capability)
- **Status:** NOT IMPLEMENTED / OUT OF SCOPE
- **Limitations:** The audit log is strictly in-memory for observability and metrics extraction. No persistent or tamper-evident features are claimed. Distributed state is out of scope.

### Oversight Metrics & Coverage
- **Repository target:** Derive oversight metrics from the event stream.
- **Status:** PARTIAL
- **Implementation:** Post-hoc calculation of decision distribution, escalation rates, and latency (`tests/evals/metrics.test.ts`).
- **Limitations:** COVERAGE METRICS ARE EXPLICITLY NOT IMPLEMENTED. It is structurally impossible to prove 100% mediation solely from internal audit events without independent instrumentation.

## ACS-Human (Human Oversight)

### Approval Grant Processing
- **Normative pinned requirement:** Authenticate human approval grants before proceeding with an `ask` decision.
- **ACS profile:** ACS-Human
- **Status:** IMPLEMENTED
- **Implementation:** The authority-enabled runtime uses `ApprovalGrantVerifier.verifyV2()` to verify Ed25519-signed `ApprovalGrantV2` payloads against trusted pending-action context, including session, request, exact tool, and configured approver binding. `GuardedExecutor` rejects V1 grants on this runtime path. `ApprovalGrantV1` remains available at primitive level for historical/backwards-compatible verification tests. Evidence includes `tests/runtime-authority.test.ts` and `tests/evals/authority-adversarial.test.ts`.

### Tool Identity Binding
- **Related capability:** Cryptographic tool identity binding inside the grant object.
- **ACS profile:** ACS-Human
- **Status:** IMPLEMENTED AS REPOSITORY-LOCAL POLICY
- **Implementation:** `ApprovalGrantV2` includes the exact tool in the Ed25519-signed payload, and `verifyV2()` checks it against the trusted pending-action tool before execution. The authority-enabled runtime requires V2 for `ASK` resolution.
- **Claim boundary:** This is a repository-local control layered around the scoped ACS runtime. It is not, by itself, a claim of full ACS-Human or full ACS conformance.
- **Limitations:** `ApprovalGrantV1` itself remains non-tool-bound and is rejected by the authority-enabled runtime path.

### External Identity & IAM
- **Non-normative context:** External IAM integration and institutional identity proofs.
- **ACS profile:** ACS-Human
- **Status:** OUT OF SCOPE
- **Limitations:** Physical human intent authentication and institutional identity proofs are not implemented.
