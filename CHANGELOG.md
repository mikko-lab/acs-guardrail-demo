# Changelog

## Unreleased

### Added
- **Ancestor chains and descendant revocation (package 1b):** issuer-attested derivation in tenancy mode. See `docs/ancestor-chains.md`.
  - **Grants and provider.** A `CapabilityGrantV2` may carry a signed `parent: { capability_id, fingerprint }`. The provider may return `{ kind: "capability_chain", leaf, ancestors }` with the complete issuer-signed chain, parent first, root last. `MAX_CHAIN_LENGTH` is 8 grants, leaf included.
  - **Verification** (`CapabilityGrantVerifier.verifyChain()`). Envelope, depth, repeated ids and cycles, the leaf with its request binding, every ancestor's signature and validity (failures name the chain position), both link directions (capability_id, then fingerprint), the leaf's tenant for every member, and attenuation (tool subset, validity window inside the parent's). New codes `MALFORMED_CHAIN`, `CHAIN_TOO_DEEP`, `CHAIN_REPEATED_ID`, `CHAIN_LINK_MISMATCH`, `TENANT_CHAIN_MISMATCH` and `CHAIN_ATTENUATION`, with audit reasons `capability_malformed_chain`, `capability_chain_too_deep`, `capability_chain_repeated_id`, `capability_chain_link_mismatch`, `capability_tenant_chain_mismatch` and `capability_chain_attenuation`.
  - **Rejection and binding.** A wrong chain is rejected before any binding, the Guardian decision, a pending approval, a permit, an execution and the tool call. A verified chain is bound atomically: every member's id to its content and every member's session to the tenant. A conflicting chain binds nothing. A chain is never assembled from grants seen earlier.
  - **Start and approval binding.** The verified ancestor ids are frozen right after verification, before the first callback; audit sinks receive copies, so changing audit metadata never changes the authority. An execution is bound at start to its frozen ancestor chain (`ancestor_capability_ids` on snapshots, terminals and execution audit events), and no later fence re-resolves it. A pending approval keeps a chain snapshot. At approval the provider's chain must equal it member by member (`chain_snapshot_mismatch`), and it is then re-verified.
  - **Descendant revocation.** A capability revocation of an ancestor covers its descendants (reason `ancestor_revoked`) at the request check after verification, approval re-verification, the early start check, the start guard, the commit fence, both delivery checks and the cancellation fan-out. It also covers ancestors revoked before their first use. It never propagates to parents or siblings. Session revocation still covers only its own session.
  - **Evidence.** Tests: `tests/ancestor-chain.test.ts` (46 tests). Runtime-test mutants: `mutants/ancestor/manifest.json` lists 25 mutants (M20, M21, M27b, M27d, M27g, M34, M34a, M35, M35a, M35b, M36, M37, M38–M41, M42a, M42b, M42c, M43–M48), each with exact witness values, plus the valid-chain control witness. `npm run mutants:ancestor` runs them.
- **Shared mutant gate:** `scripts/mutants/run-mutant-gate.mjs --manifest <manifest>` replaces `run-tenant-mutants.mjs` and serves both packages.
  - It adds `control` witnesses, which must hold unchanged under a mutant, and recorded gaps taken from the manifest.
  - It copies only regular files into the gate's work trees.
  - A crash of the gate itself exits 2, never 1. The new gate regression R4-crash checks this.
  - See `docs/mutant-gate.md`.
- **Tenant scope (package 1a):** tenancy mode, enabled by `new CapabilityGrantVerifier(publicKey, keyId, clock, { tenancy: true })`.
  - **Grants.** Tenancy mode accepts only signed `CapabilityGrantV2` grants (`version: 2`, required `tenant_id`). Tenantless grants are rejected (`MISSING_TENANT`, audit reason `capability_missing_tenant`); there is no default tenant and no mixed mode.
  - **Trust and binding.** The tenant comes only from the verified grant. A request's own `params.tenant_id` must equal it (`tenant_mismatch`). The capability fingerprint covers `tenant_id`. A runtime session is bound to one tenant (`session_tenant_conflict`). An execution is bound to its tenant at start, and the commit fence, both delivery checks and the cancellation fan-out use that binding.
  - **Revocation.** `revoke({ scope: "tenant", tenant_id })` is enforced at every check point: the early request check (session binding), the request check after verification, approval re-verification, the early start check, the start guard, the commit fence (`tenant_revoked`), result processing and the hand-over. It also requests cancellation of the tenant's running executions; other tenants are unaffected.
  - **Reporting.** `getExecution()`, `terminals()` and the execution audit events carry the bound `tenant_id`, which OCSF export allowlists.
  - **Evidence.** Tests: `tests/tenant-scope.test.ts`. Runtime-test mutants: `mutants/tenant/manifest.json` names each mutant's witnesses, the exact control and mutant value of every witness label, the accepted caught errors and the evidence kind. `npm run mutants:tenant` runs them; it requires an identical test inventory, typecheck, build and a clean jest process, and treats unexpected values or errors as technical failures. `npm run mutants:tenant:regressions` checks the gate itself. See `docs/tenant-scope.md`.
- **Build check:** `npm run build` (`tsc --outDir dist`) is part of `npm run verify`; jest ignores `dist/`.
- **Cooperative containment (A2):** every tool call that passes the start fence becomes a managed execution (`exec-<n>`) bound to its request, session and original capability. Tools receive an `ExecutionContext` (`tool(args, ctx)`) with a runtime-owned `CancellationSignal`, `acknowledgeCancellation()`, a commit fence `commit(key, value)` over a runtime-managed state store (`executor.managedState`, read-only) and `track()` for registered work. `revoke()` requests cancellation of covered executions after recording the tombstone. `track()` accepts only native Promises, and settlement of registered work and of the tool function's native Promise is observed through the Promise's internal state with the intrinsic `Promise.prototype.then` and the intrinsic species (an own `constructor` is pinned to `Promise` for the duration of the call when needed), without running any code of the Promise object; the runtime handles the rejection of every Promise it observes. Exactly one terminal per execution (`completed` / `cancelled` / `failed`), observable through `getExecution()`, `whenTerminal()` and `terminals()`; `audit_recorded` reports whether its `execution_terminal` record call returned normally. New audit events `execution_cancellation_requested`, `execution_cancellation_acknowledged`, `tool_commit_requested`, `tool_commit_applied`, `tool_commit_blocked` and `execution_terminal` with OCSF metadata allowlists. See `docs/cooperative-containment.md`.
- **Revocation effective points:** start is enforced immediately before the tool function call (after the `tool_execution_started` audit record, via an optional `beforeInvoke` guard on `ExecutionGate.execute()`), and delivery at the fulfilment of the public `process()` / `resolveApproval()` promise, so revocations from synchronous callbacks or Promise transitions on the path are honoured.
- **Authority revocation (A1):** `GuardedExecutor.revoke({ scope: "capability", capability_id } | { scope: "session", session_id })` records an explicit, monotonic, idempotent revocation and returns a `RevocationReceiptV1`. Revoked authority is denied at the request, approval, start and delivery boundaries (`AuthorityRevokedError`, `authority_revocation_enforced`, `tool_result_withheld` with a revocation reason). New audit event types `authority_revoked` and `authority_revocation_enforced` with explicit OCSF metadata allowlists. See `docs/authority-revocation.md`.

### Fixed
- **Unobservable settlement is not a terminal (A2):** a tool function that returns a native Promise whose settlement cannot be observed (a non-configurable `constructor` or non-extensible Promise that cannot be pinned) still fails the call with `TypeError`, but no longer records a `failed` terminal or `execution_terminal`: the Promise may still be pending. The execution enters the new state `unobservable`; `ctx.commit()` is denied with the new reason `settlement_unobservable`, `ctx.track()` throws, `whenTerminal()` never resolves, and a later `revoke()` that covers it still requests cancellation. `tests/cooperative-containment.test.ts` › C22b and C29 (d) now expect this state instead of a `failed` terminal; C22c–C22f are new regressions.

### Changed
- **Ancestor chain compatibility (package 1b):**
  - **Grants with `parent`.** A version 1 grant with a `parent` field is now rejected (`MALFORMED_GRANT`), and a chain envelope is rejected outside tenancy mode (`MALFORMED_CHAIN`). In tenancy mode a version 2 grant with `parent` is accepted only with its verified chain; before, an issuer-signed `parent` field was ignored. Grants without `parent` behave as before, and the 582 earlier tests pass unchanged.
  - **API types.**
    - `RevocationReason` and `CommitBlockReason` gain `ancestor_revoked`.
    - `CheckedAuthority`, `ExecutionSnapshot` and `ExecutionTerminal` gain optional `ancestor_capability_ids`, present only for chained authorities.
    - `ManagedExecutionDeps` gains optional `ancestorIds`.
    - `capabilityFingerprint` moves to `capability-grant.ts` (re-exported from `authority-revocation.ts`).
  - **Revocation reason precedence.** Tenant, then session, then an ancestor (nearest parent first), then the capability itself.
  - **OCSF.** The allowlists of `capability_verified`, `authority_revocation_enforced` and the execution and commit events include `ancestor_capability_ids`.
  - **Mutant gate.**
    - The tenant patches and gate regressions are regenerated against the new source.
    - The tenant manifest gains `recorded_gaps` (the M33 gap, unchanged).
    - Its witnesses and exact values are unchanged.
- **Tenant scope compatibility (package 1a):**
  - **Legacy mode (default).** A version 1 grant that carries a `tenant_id` field is now rejected (`MALFORMED_GRANT`) instead of having the field silently ignored, and a version 2 grant is rejected. Version 1 grants without `tenant_id` behave exactly as before, and a request's `params.tenant_id` is still ignored. All 553 existing tests pass unchanged.
  - **API types.**
    - `CapabilityGrantVerifier.verify()` returns `CapabilityGrant` (`CapabilityGrantV1 | CapabilityGrantV2`).
    - `RevocationTarget` and `RevocationReason` gain the tenant variants, and `CommitBlockReason` gains `tenant_revoked`.
    - `ExecutionSnapshot` and `ExecutionTerminal` gain an optional `tenant_id`, present only in tenancy mode, so legacy snapshots are unchanged.
    - `ManagedExecutionDeps` gains an optional `tenantId`.
    - `AcsParams` declares the reserved, signed `tenant_id` field.
  - **Revocation reason precedence.** When several revocations apply, the broadest is reported: tenant, then session, then capability. Session-before-capability is unchanged.
- **Audit sequence (A2):** every managed execution that becomes terminal records `execution_terminal`, so the normal ALLOW and approval audit sequences contain one more event. `tests/audit.test.ts` › "NORMAL ALLOW exact event sequence with no duplicates" lists it (between `tool_execution_started` and `tool_execution_completed`); its other expectations are unchanged.
- **Tool signature:** `ToolImplementation` takes an optional second argument, the execution context; existing tools are unaffected. `ExecutionGate.execute()`'s `beforeInvoke` guard may return a tool invoker.
- **Approval re-checks authority:** `resolveApproval()` now re-checks the original pending request's authority before execution: runtime revocation, the original capability's current validity, and that the provider still resolves a valid capability for the same context. An approval whose original capability expired or whose provider withdrew the capability no longer executes.
- **Capability id binding:** a `capability_id` is bound to the content of the first verified grant seen with it; a different grant with the same id is rejected with `capability_rejected` reason `capability_id_conflict`.
- **Capability verification audit order:** `capability_verified` is recorded only after the revocation and id-binding checks pass.
- **Test fixture:** `tests/guarded-executor.test.ts` › EXPIRY › "expiry strict > semantics" now gives its capability a lifetime longer than the pending window, so that capability expiry no longer coincides with (and masks) the pending-timeout boundary it tests; its assertions are unchanged. The previous fixture expired the capability at exactly the pending timeout, which the approval re-check now rejects.
- **Audit event enumeration:** the OCSF allowlist completeness test lists the two A1 and the six A2 event types.

### Limitations
- Revocation does not stop a running tool. A2 cancellation is cooperative; the commit fence covers only `ctx.commit()` on the in-memory managed state; effects outside it, non-cooperating code and unregistered background work are not controlled.
- Revocation state is in memory for one executor instance: not persistent, not distributed, not shared between processes, and lost on restart.
- Capability (with issuer-attested descendants in tenancy mode), session and (tenancy mode) tenant scopes only; no agent scope, no holder-to-holder delegation, no regrant. Tenant scope is one issuer key and one executor for all tenants, not separate trust domains.
- The tenant field of the capability fingerprint has component evidence only (mutant M33); no production-path witness separates it from the kept safeguards (`docs/tenant-scope.md`).
- Ancestor chains: M40, M42a, M47 and M48 are check-point evidence only; M42a re-resolves only at the commit fence; ancestor expiry between request and approval has no isolated witness (attenuation masks it). Contract and supplement evidence for the ancestor column belongs to the later eval work (`docs/ancestor-chains.md`).

## [v0.4.0] - 2026-09-29

### Summary
- Tamper-evident SHA-256 audit chain.
- Trusted-head verification and a fail-closed integrity API.
- OCSF 1.8.0 export of verified audit evidence as Base Event / Detection Finding.
- Explicit metadata allowlist and deterministic JSONL output.
- Official OCSF Toolkit cross-validation of a representative exporter corpus.
- GitHub Actions verification on Node 22 and Node 24.

### Limitations
- The audit remains in memory.
- No immutable storage, non-repudiation or external anchoring.
- OCSF validation covers a representative corpus, not full OCSF validation or certification.
- The OCSF Server validator was not run.
- No SIEM integration.
- No full ACS conformance or certification claim.

### Added
- **Tamper-evident audit chain:** Audit events now carry a deterministic SHA-256 `event_hash` linked through `previous_hash`, with an explicit `GENESIS` convention.
- **Trusted head verification:** Added the integrity API `audit.verifyIntegrity(expectedHeadHash?)`, `AuditCollector.verifyIntegrity(events, expectedHeadHash?)`, and `audit.assertIntegrity(events?, expectedHeadHash?)` so callers can combine linked validation with a trusted expected head for suffix-truncation detection.
- **Fail-closed audit verification:** Added deterministic integrity results and `AuditIntegrityError` for callers that require verification to fail closed. Regression coverage includes payload mutation, deletion, reordering, hash tampering, trusted-head checks, and request-scoped reads.

### Trust model and limitations
- Linked verification detects inconsistent modification within the same stream.
- A trusted expected head detects suffix truncation and a different final event, even when the remaining prefix is otherwise structurally valid.
- Without a trusted expected head or external anchor, an attacker who rewrites the entire stream can recompute the chain and evade detection.
- The chain is in-memory and restart persistence is not provided. It does not provide immutable storage, non-repudiation, external anchoring, or a durable audit backend.

### Added: OCSF 1.8.0 audit export
- **OCSF 1.8.0 audit export:** Added `src/ocsf/`. `exportAuditToOcsf(events, { expectedHeadHash?, requireTrustedHead? })` verifies the ACS hash chain with `AuditCollector.verifyIntegrity`, maps each event to an OCSF 1.8.0 Base Event or, where `IncidentClassifier` derives an incident, a Detection Finding, and validates each record. `serializeOcsfJsonl` writes deterministic JSONL. Any failure throws a typed error and nothing partial is returned. ACS hashes are carried in `unmapped.acs` as provenance. Event UIDs derive from the ACS `event_hash`. Metadata passes only through an explicit per-event-type allowlist.
- **Vendored OCSF 1.8.0 subset:** `schemas/ocsf/1.8.0/` holds a subset of the official schema, compiled with `ocsf-lib`, plus the extraction script `scripts/ocsf/extract-subset.py`.

- **Official OCSF cross-validation:** `scripts/ocsf/setup-crossval-toolchain.sh` builds a pinned official toolchain (OCSF Toolkit v0.9.0, ocsf-schema v1.8.0, ocsf-schema-compiler 1.1.1). `scripts/ocsf/cross-validate.sh` validates a representative corpus generated by `exportAuditToOcsf`. Result: 19 events, 0 errors, 0 warnings at default levels.

### Fixed
- **OCSF Base Event `type_name`:** now `"Base Event: <ACS event type>"` instead of the generic `"Base Event: Other"`, which OCSF Toolkit flagged as `validation_attribute_enum_sibling_suspicious_other`. The local validator now rejects the generic caption as the sibling of enum id 99 (exporter policy, stricter than OCSF).

### OCSF export limitations
- Runtime validation is local structural validation against the vendored subset. Official OCSF Toolkit cross-validation covers a representative corpus only; the OCSF Server validator was not run.
- Without a trusted expected head, a truncated but structurally valid prefix exports successfully.
- The export is a derived view. It does not replace ACS evidence and does not provide SIEM integration, immutable storage or non-repudiation.

### Added: CI
- **GitHub Actions verification:** `.github/workflows/verify.yml` runs `npm ci` and `npm run verify` (typecheck and Jest) on a Node 22 and Node 24 matrix.
- The workflow runs on `push` and `pull_request` triggers.
- OCSF cross-validation is not part of CI; it remains a separate, local run through `scripts/ocsf/`.

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
