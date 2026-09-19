# ACS Crosswalk: Public Evidence Mapping

This document maps publicly available architectural evidence against the Agent Control Standard (ACS) v0.1.0 conformance requirements.

## Claim discipline

- This document maps public evidence against ACS v0.1.0.
- It is not an ACS conformance claim.
- DEMONSTRATED means the public repository directly implements the mapped requirement semantics.
- PARTIAL means conceptually or structurally related evidence exists, but not the ACS requirement itself.
- MISSING means no public evidence currently implements the ACS requirement.

## ACS-Core

### Hook Taxonomy: Wrapped MCP
- **ACS requirement:** Wrap MCP tool calls via `protocols/MCP/*` hooks.
- **ACS profile:** ACS-Core
- **Evidence:** `mikko-lab/kopilotti-webmcp` registers bounded tools in a shared visible workspace via `document.modelContext.registerTool()`. This is architectural evidence of bounded-tool concepts.
- **Status:** MISSING
- **Exact limitation:** No public implementation of the actual ACS wire hooks (like `toolCallRequest` or `toolCallResult`) exists. The WebMCP implementation does not emit ACS-compliant payloads over a Guardian transport.
- **Safe next step:** Implement a transport adapter to emit specific ACS `protocols/MCP/*` hook envelopes.

### Dispositions & Decision Honoring
- **ACS requirement:** The observed agent must honor Guardian decisions and support all five dispositions: ALLOW, DENY, MODIFY, ASK, DEFER.
- **ACS profile:** ACS-Core
- **Evidence:** `mikko-lab/refuse-dont-guess` demonstrates a deterministic policy that outputs `PASS`, `BLOCK`, or `ESCALATE`. `mikko-lab/kopilotti-webmcp` requires page-native human approval before policy execution. 
- **Status:** PARTIAL
- **Exact limitation:** PASS, BLOCK, ESCALATE, and human approval are only conceptual analogues. There is no implementation of the actual ACS ALLOW, DENY, ASK, MODIFY, and DEFER wire-format dispositions. Furthermore, the deterministic boundaries and page-native approval do not prove ACS Guardian decision honoring.
- **Safe next step:** Standardize the deterministic outputs strictly to the full set of ACS wire-format dispositions and enforce them via Guardian signaling.

### Baseline Signature (HMAC-SHA256)
- **ACS requirement:** Authenticate the channel using a baseline HMAC-SHA256 signature over the canonical envelope.
- **ACS profile:** ACS-Core
- **Evidence:** None of the public repositories demonstrate ACS request/response envelopes signed according to ACS Core.
- **Status:** MISSING
- **Exact limitation:** `mikko-lab/ddn-reference` issues cryptographically signed decision receipts (Ed25519) and `prompt-injection-gate` uses hash chains, but these do not satisfy the ACS envelope-signature requirements for in-transit channel authentication.
- **Safe next step:** Implement the standard HMAC-SHA256 envelope for request/response payloads in transit.

## ACS-Trace

### OTel / OCSF Event Emission
- **ACS requirement:** Emit OTel or OCSF events for every supported ACS step, including decisions.
- **ACS profile:** ACS-Trace
- **Evidence:** `mikko-lab/prompt-injection-gate` implements a custom JSONL audit log backend.
- **Status:** MISSING
- **Exact limitation:** There is no public implementation of OTel or OCSF event emission. Custom JSONL formats do not satisfy ACS-Trace.
- **Safe next step:** Replace the custom logger with an OpenTelemetry or OCSF conformant event emitter.

## ACS-Inspect / Inspect-Dynamic

### AgBOM Snapshot and Serialization
- **ACS requirement:** Emit `agbom/snapshot` before content-bearing hooks and serialize canonical AgBOM.
- **ACS profile:** ACS-Inspect
- **Evidence:** No public evidence identified in the allowed repositories.
- **Status:** MISSING
- **Exact limitation:** The reference implementations do not serialize or track agent components dynamically (no AgBOM).
- **Safe next step:** Introduce a baseline component registry to emit static AgBOMs at session start.

### Dynamic Component Mutation
- **ACS requirement:** Emit `agbom/changed` on every mid-session component mutation.
- **ACS profile:** ACS-Inspect-Dynamic
- **Evidence:** No public evidence identified in the allowed repositories.
- **Status:** MISSING
- **Exact limitation:** The reference implementations do not support hot-swapping models or tools mid-session.
- **Safe next step:** Out of scope for initial deployment.

## ACS-Provenance

### Field-Level Provenance
- **ACS requirement:** Attach a Provenance object to every data-bearing field in every hook payload.
- **ACS profile:** ACS-Provenance
- **Evidence:** `mikko-lab/prompt-injection-gate` applies a structural quarantine boundary for untrusted tool outputs.
- **Status:** MISSING
- **Exact limitation:** Structural quarantine boundaries, hash chains, and receipts are not field-level ACS provenance. There is no implementation of explicit ACS Provenance objects with `origin` and `provenance_id` attached to specific fields.
- **Safe next step:** Map the untrusted output boundaries into strictly serialized ACS provenance objects.

## ACS-Crypto

### Asymmetric and Post-Quantum Signatures
- **ACS requirement:** Support at least ML-DSA-65 (RECOMMENDED primary) or SLH-DSA-128s, and optional hybrid composites.
- **ACS profile:** ACS-Crypto
- **Evidence:** `mikko-lab/ddn-reference` issues `DecisionReceiptV1` containing Ed25519-signed attestations.
- **Status:** PARTIAL
- **Exact limitation:** Ed25519 is useful related evidence of asymmetric cryptography but does not satisfy the ACS-Crypto requirement for post-quantum ML-DSA-65 or SLH-DSA-128s support.
- **Safe next step:** Upgrade the signature scheme to an ML-DSA-65 hybrid composite.

## ACS-Audit

### Content Committing Request Hash
- **ACS requirement:** Populate `request_hash` on every ContextEntry to ensure the chain commits to request content.
- **ACS profile:** ACS-Audit
- **Evidence:** `mikko-lab/ddn-reference` canonicalizes inputs and binds them to specific policy hashes to generate a `DecisionReceiptV1`.
- **Status:** PARTIAL
- **Exact limitation:** DDN uses its own receipt and canonicalization/attestation model. It does not use the ACS `SessionContext` and does not put a `request_hash` on an ACS `ContextEntry` as the profile specifically requires.
- **Safe next step:** Persist decision receipts into a durable backend utilizing standard ACS ContextEntry models.

---

## Public architecture summary

The current public evidence approximately maps as:

Input/tool-output controls (`prompt-injection-gate` quarantine boundary)
→ bounded tool/action surface (`kopilotti-webmcp` registered tools)
→ deterministic decision / escalation (`refuse-dont-guess` PASS/ESCALATE/BLOCK)
→ external behavioral evaluation (structural boundaries)
→ verifiable evidence (`ddn-reference` threshold-signed receipts)

## Candidate demo slice

steps/toolCallRequest
→ deterministic Guardian
→ ALLOW / DENY / ASK
→ execution gate
→ steps/toolCallResult
→ minimal audit record

Explicitly defer:
- MODIFY
- DEFER
- full ACS-Core conformance
- ACS-Trace
- ACS-Inspect / AgBOM
- ACS-Provenance
- ACS-Crypto
- ACS-Audit
