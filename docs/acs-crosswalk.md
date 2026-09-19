# ACS Crosswalk: Implementation vs. ACS Specification

This document maps the actual implementation of the ACS Guardrail Demo against the Agent Control Standard (ACS) v0.1.0 conformance requirements.

## Claim Discipline

- This document reflects the CURRENT implemented state of the repository.
- **It is not an ACS conformance claim.** The project explicitly scopes down features to focus on a minimal, high-assurance execution boundary.
- **DEMONSTRATED** means the repository directly implements and strictly enforces the mapped requirement semantics.
- **PARTIAL** means conceptually related evidence exists or the feature is only partially implemented.
- **MISSING / NOT IMPLEMENTED** means no implementation exists or the feature is explicitly out of scope.

For exact test evidence of these claims, see `docs/invariants-evidence.md`.

## ACS-Core

### Hook Taxonomy
- **ACS requirement:** Support the ACS wire hooks (e.g. `steps/toolCallRequest`, `steps/toolCallResult`, `protocols/MCP/*`).
- **ACS profile:** ACS-Core
- **Evidence:** The runtime exclusively routes and validates `steps/toolCallRequest` and `steps/toolCallResult` using vendored ACS v0.1.0 JSON schemas.
- **Status:** PARTIAL (Only specific steps/* hooks implemented)
- **Limitations:** Does not support `protocols/MCP/*`, `handshake/hello`, or `system/*` hooks.

### Dispositions & Decision Honoring
- **ACS requirement:** The observed agent must honor Guardian decisions and support all five dispositions: ALLOW, DENY, MODIFY, ASK, DEFER.
- **ACS profile:** ACS-Core
- **Evidence:** The GuardedExecutor implements a hard execution gate that natively enforces `allow`, `deny`, and `ask` decisions. Side effects cannot occur without an explicit permit.
- **Status:** PARTIAL
- **Limitations:** `modify` and `defer` dispositions are explicitly not implemented. `timeout_disposition: allow` is also deliberately unsupported.

### Baseline Signature (HMAC-SHA256)
- **ACS requirement:** Authenticate the channel using a baseline HMAC-SHA256 signature over the canonical envelope.
- **ACS profile:** ACS-Core
- **Evidence:** `SignatureService` enforces strict base64 standard decoding, canonicalizes the envelope (JCS), and uses `timingSafeEqual` to verify the HMAC-SHA256 signature for all requests and addressable responses.
- **Status:** DEMONSTRATED
- **Limitations:** Uses a local strict profile for HKDF-SHA256 derivation (empty salt) pending clarification on upstream issue #118.

## ACS-Trace

### OTel / OCSF Event Emission
- **ACS requirement:** Emit OTel or OCSF events for every supported ACS step, including decisions.
- **ACS profile:** ACS-Trace
- **Evidence:** The demo relies entirely on a custom, in-memory `AuditCollector`.
- **Status:** NOT IMPLEMENTED
- **Limitations:** No OpenTelemetry or OCSF conformant event emission.

## ACS-Inspect / Inspect-Dynamic

### AgBOM Snapshot and Serialization
- **ACS requirement:** Emit `agbom/snapshot` before content-bearing hooks and serialize canonical AgBOM.
- **ACS profile:** ACS-Inspect
- **Evidence:** No implementation.
- **Status:** NOT IMPLEMENTED

## ACS-Provenance

### Field-Level Provenance
- **ACS requirement:** Attach a Provenance object to every data-bearing field in every hook payload.
- **ACS profile:** ACS-Provenance
- **Evidence:** No implementation.
- **Status:** NOT IMPLEMENTED

## ACS-Crypto

### Asymmetric and Post-Quantum Signatures
- **ACS requirement:** Support at least ML-DSA-65 (RECOMMENDED primary) or SLH-DSA-128s, and optional hybrid composites for ACS envelope signatures.
- **ACS profile:** ACS-Crypto
- **Evidence:** Envelopes use symmetric HMAC-SHA256 exclusively. (Note: Ed25519 is used for off-band human approval payloads, but not for the ACS channel itself).
- **Status:** NOT IMPLEMENTED

## ACS-Audit

### Content Committing Request Hash
- **ACS requirement:** Populate `request_hash` on every ContextEntry to ensure the chain commits to request content in a tamper-evident log.
- **ACS profile:** ACS-Audit
- **Evidence:** The `AuditCollector` is strictly an in-memory utility.
- **Status:** NOT IMPLEMENTED
- **Limitations:** No persistent or tamper-evident cryptographic audit storage. Not cryptographically chained.

---

## Local Strict Profiles & Deviations

This implementation deviates deliberately from upstream baseline leniency in specific documented ways to ensure a high-assurance boundary:

1. **request_id_ref Correlation:** While ACS v0.1.0 vendored schemas do not require `request_id_ref` on `toolCallResult`, this demo strictly requires it. The local strict profile requires request_id_ref and binds toolCallResult to the originating session, request_id_ref and executed tool name (see upstream issue #118).
2. **Human-Only ASK:** Approvals with `approver.type === "agent"` or `"service"` are explicitly rejected. ApprovalGrant uses real Ed25519 signatures verified against the configured approval authority. Browser/IdP-based human identity authentication is not implemented and remains out of band.
3. **Timeout Disposition:** `timeout_disposition: allow` is deliberately unsupported.
4. **Classification Withholding:** Uses a simplistic `classification === "restricted"` marker in JSON output to trigger withholding. This is a local demo policy, not a universal sensitive-data detection engine.
