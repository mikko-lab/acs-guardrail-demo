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

For exact test evidence of these claims, see the evaluation test suites in `tests/evals/`.

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
- **Implementation:** `ApprovalGrantVerifier` verifies Ed25519 signatures on `ApprovalGrantV1` payloads. `GuardedExecutor` strictly enforces approve/reject/expiry semantics and session/request isolation (`tests/evals/isolation.test.ts`).

### Tool Identity Binding
- **Related capability:** Cryptographic tool identity binding inside the grant object.
- **ACS profile:** ACS-Human
- **Status:** NOT IMPLEMENTED / NOT CLAIMED
- **Limitations:** `ApprovalGrantV1` does not include a tool identifier field in the signed payload. While `GuardedExecutor` safely resumes the exact `pendingAction` (preventing runtime tool swapping), the grant mathematically doesn't claim to sign the tool identity.

### External Identity & IAM
- **Non-normative context:** External IAM integration and institutional identity proofs.
- **ACS profile:** ACS-Human
- **Status:** OUT OF SCOPE
- **Limitations:** Physical human intent authentication and institutional identity proofs are not implemented.
