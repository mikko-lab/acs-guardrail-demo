# ACS audit evidence → OCSF 1.8.0 export

Code: `src/ocsf/` · Tests: `tests/ocsf-exporter.test.ts`, `tests/ocsf-mapper.test.ts`, `tests/ocsf-validator.test.ts` · Vendored schema subset: `schemas/ocsf/1.8.0/`

## What this is

A derived **OCSF 1.8.0** representation of the ACS in-memory audit stream, emitted as JSONL, for interoperability with tooling that reads OCSF. The exporter verifies the ACS hash chain first and exports nothing if verification fails.

```ts
import { exportAuditToOcsf, serializeOcsfJsonl } from "./src/ocsf";

const result = exportAuditToOcsf(audit.getEvents(), { expectedHeadHash: trustedHead });
const jsonl = serializeOcsfJsonl(result.events);
```

## What this is not

- Not a SIEM product, SIEM connector, or log-shipping integration.
- Not an immutable audit ledger or durable storage.
- Not a non-repudiation mechanism. No signatures are added.
- Not an OpenShell integration.
- Not a claim of universal runtime coverage. It exports only what `AuditCollector` recorded on the controlled runtime path.
- Not a replacement for the ACS source evidence. The ACS events and hash chain remain the evidence; OCSF is a view derived from them.
- Not complete OCSF schema validation (see [Validation](#validation)).

## Integrity model

```text
ACS AuditEvent[]  (source evidence, unchanged)
      │
      │  JSON snapshot (detached from the caller's objects)
      ▼
AuditCollector.verifyIntegrity(snapshot, expectedHeadHash?)
      │ PASS                          │ FAIL
      ▼                               ▼
OCSF mapping (per event)         OcsfExportIntegrityError, nothing exported
      │
      ▼
local OCSF 1.8.0 subset validation ── FAIL ─▶ OcsfValidationError, nothing exported
      │
      ▼
deterministic JSONL
```

- Verification uses the existing `AuditCollector.verifyIntegrity`. `src/audit.ts` was not changed.
- The exporter works on one JSON snapshot of the input. Verification and mapping read the same values. The caller's `AuditEvent` objects are never mutated.
- Every failure throws a typed error (`OcsfExportIntegrityError`, `OcsfTrustedHeadRequiredError`, `OcsfMappingError`, `OcsfValidationError`). No partial result is returned.
- ACS `previous_hash`, `event_hash`, `request_id`, `event_type`, `timestamp` and `metadata` are not recomputed or rewritten. The OCSF records are not new ACS chain events and do not extend the chain.
- ACS hashes in the export prove the chain of the **ACS canonical events**. They are not hashes of the OCSF records. A change to an OCSF line after export is not detectable from the ACS hashes it carries; detecting it requires re-exporting from verified ACS evidence and comparing.

### Structural vs trusted-head verification

| Mode | How | Detects | Does not detect |
|---|---|---|---|
| Structural (`integrity: "structural"`) | no `expectedHeadHash` | missing hashes, wrong genesis, broken links, mutated/reordered/removed events within the supplied stream | suffix truncation (a valid prefix passes), a fully recomputed chain |
| Trusted head (`integrity: "trusted_head"`) | `expectedHeadHash` from a separately trusted source | the above, plus suffix truncation and a different final head | anything that also controls the trusted head value |

- Without a trusted head, a **truncated but structurally valid prefix exports successfully**. This is tested and intentional: it is the limit of structural verification, and the result is labelled `integrity: "structural"`.
- An attacker who can rewrite the whole stream can recompute a valid chain; only a trusted head (or an external anchor) catches this.
- `requireTrustedHead: true` makes the exporter refuse to run without an `expectedHeadHash`.
- The trusted head is only as trustworthy as where the caller got it from. This repository provides no anchoring service. None of this makes the audit immutable storage.

## Event identity

`metadata.uid = "acs-audit-event:sha256:" + <ACS event_hash>`

- `request_id` is not unique: one request produces several audit events. It is exported as `metadata.correlation_uid` instead, which is what OCSF defines that attribute for.
- `event_hash` is SHA-256 over the ACS canonical event including `previous_hash`. It is stable across re-exports, collision-resistant, and distinct for identical content at different chain positions.
- No random UUIDs are generated.
- The prefix names the source so the value is not read as a hash of the OCSF record.
- Limitation: two different chains holding a byte-identical event at the same position with the same predecessor would produce the same uid. That requires an identical history up to that point.
- `metadata.correlation_uid` is omitted when the ACS `request_id` is the `"unknown"` sentinel. Using it would correlate unrelated events.

## Mapping

Common to every exported record:

| OCSF attribute | Value |
|---|---|
| `metadata.version` | `"1.8.0"` |
| `metadata.product` | `{ name: "acs-guardrail-demo", version: <package.json version> }` |
| `metadata.uid` | see [Event identity](#event-identity) |
| `metadata.correlation_uid` | ACS `request_id` (except `"unknown"`) |
| `metadata.event_code` | ACS `event_type` |
| `metadata.original_time` | ACS `timestamp`, unchanged |
| `metadata.sequence` | zero-based position in the verified ACS chain |
| `time` | ACS `timestamp` as epoch ms. This is the event time, not the export time. |
| `unmapped.acs` | ACS provenance (below) |

No `exported_at` or other export-time value is emitted.

### ACS event type → OCSF representation

| ACS event type | OCSF representation |
|---|---|
| `replay_rejected` | Detection Finding (2004), incident `replay_attempt` |
| `timestamp_rejected` | Detection Finding (2004), incident `request_freshness_violation` |
| `correlation_failed` | Detection Finding (2004), incident `correlation_failure` |
| `result_guardian_decision` with `decision = deny` | Detection Finding (2004), incident `result_policy_violation` |
| `capability_rejected` with reason `capability_authentication_failed` | Detection Finding (2004), incident `authority_authentication_failure` |
| `capability_rejected` with reason `capability_agent_mismatch` / `capability_session_mismatch` / `capability_scope_mismatch` | Detection Finding (2004), incident `authority_boundary_violation` |
| `approval_verification_failed` with reason `invalid_signature` | Detection Finding (2004), incident `authority_authentication_failure` |
| `approval_verification_failed` with reason `tool_binding_mismatch` / `wrong_approver_identity` | Detection Finding (2004), incident `authority_boundary_violation` |
| every other event, including `guardian_decision` (allow, ask **and deny**), `approval_requested`, `human_approval`, `human_rejection`, `approval_expired`, `tool_execution_blocked`, other `capability_rejected` / `approval_verification_failed` reasons | **Base Event (0)**, generic |

The Detection Finding rows are not a separate rule set. The exporter calls the existing `IncidentClassifier.fromAudit` and emits a Detection Finding only for an event the classifier derives an incident from. If the classifier changes, the mapping follows it. A Guardian `deny` is a policy decision working as intended, not a detection, and stays a Base Event.

Each ACS event produces exactly one OCSF record, in source order.

**Base Event (generic on purpose):** `class_uid 0`, `category_uid 0` ("Uncategorized"), `activity_id 99` ("Other") with `activity_name` = ACS event type, `type_uid 99`. `severity_id 0` ("Unknown"), because ACS audit events carry no severity and none is invented. `status_id` / `status` are set only for `tool_execution_completed`, from its recorded `status` (`success` → 1 Success, `error` → 2 Failure).

**Detection Finding:** `class_uid 2004`, `category_uid 2`, `activity_id 1` (Create), `type_uid 200401`. `severity_id` comes from the incident severity (low 2, medium 3, high 4, critical 5). `finding_info.uid` is the classifier's `incident_id`. `finding_info.title` and `types` come from the incident type. The incident's `disposition` and `requires_human_review` go in `unmapped.acs.incident`, not in OCSF `disposition_id`, because that attribute belongs to the `security_control` profile, which this export does not declare.

**Deliberately not produced:** API Activity, Authorization/Authentication classes, `actor`, `user`, `src_endpoint`, `dst_endpoint`, `device`, IP addresses, `tenant_uid`, API/service, cloud and other identity fields. ACS audit events carry no verified values for them. `agent_id` is an authenticated request claim in this demo, not verified workload identity, so it stays ACS provenance and is not promoted to `actor`.

### ACS provenance (`unmapped.acs`)

OCSF defines `unmapped` for source attributes that do not map to the event schema, which fits here. No custom OCSF extension is registered.

| Field | Meaning |
|---|---|
| `provenance_schema` | `acs-guardrail-demo/ocsf-provenance/v1` |
| `event_type`, `request_id`, `timestamp` | ACS source values, unchanged |
| `previous_hash`, `event_hash` | ACS chain values, unchanged |
| `hash_algorithm`, `hash_canonicalization` | `SHA-256`, `RFC 8785 JSON canonicalization` (the ACS hashing scheme) |
| `chain_index` | position in the verified ACS chain |
| `metadata` | allowlisted ACS metadata only |
| `omitted_metadata_key_count` | number of source metadata keys not exported |
| `incident` | only on Detection Findings: classifier reference, incident id/type/severity/disposition/review flag |

### Metadata allowlist

`AuditEvent.metadata` is **not** copied wholesale. The export target is a different trust boundary from the in-process collector. `OCSF_METADATA_ALLOWLIST` in `src/ocsf/mapper.ts` lists the exportable keys per event type:

- keys not on the list are dropped and only counted;
- allowlisted keys pass only as flat values (string, finite number, boolean, string array); nested objects are dropped even under an allowlisted key;
- `approver_id` (human approval/rejection) is excluded: it is an approver identity claim, and identity mapping to log systems is out of scope;
- `raw` (`timestamp_rejected`) is excluded: it is attacker-controlled input.

A new metadata key added to any runtime component will not appear in the export until someone adds it to the allowlist.

## JSONL

`serializeOcsfJsonl` writes one RFC 8785-canonical JSON object per line, each ending in `\n`. The same input produces byte-identical output. Newlines inside values are JSON-escaped, so a value cannot split or inject lines. The exporter does not log to the console.

## Validation

Every mapped record is validated before being returned. This is **local structural validation against a vendored subset of OCSF 1.8.0**. It is not the official OCSF validator.

- **Source:** the official `ocsf/ocsf-schema` repository at `v1.8.0` (commit `6fa6499a…`), compiled with the official `ocsf-lib` 0.10.4. The subset holds `base_event`, `detection_finding`, `metadata`, `product` and `finding_info`, plus all data types. See `schemas/ocsf/1.8.0/README.md`.
- **Checks:** class is Base Event or Detection Finding; only attributes defined for the class/object (additional attributes rejected); required attributes; primitive types, arrays, type regex/range; enum ids; object `at_least_one` / `just_one` constraints; `type_uid = class_uid*100 + activity_id`; `_name` captions for non-Other enum ids; `metadata.version = "1.8.0"`.
- **Stricter than OCSF:** profile attributes (`actor`, `device`, `disposition_id` …) and attributes whose object type is not vendored are rejected, even though OCSF allows them.
- **Not checked:** profiles, extensions, deprecations, observables, recommended attributes, and classes other than 0 and 2004.
- **Why not the official tooling:** the OCSF Server (schema.ocsf.io), which provides the JSON Schema export and the event validation API, was not reachable from the build environment. `ocsf-lib` compiles the schema but does not validate events. Running a Phoenix/Elixir OCSF Server as a test dependency would be a disproportionate build burden for this demo. The JSON Schema used at runtime is generated from the vendored subset by `src/ocsf/validator.ts`. That translation is local code, so its correctness is a claim of this repository, not of OCSF.
- **Open item:** the output has not been cross-checked against the OCSF Server's validator. Doing so is the recommended next step before calling the output validated by OCSF tooling.

## Known limitations and open questions

- The source audit is in memory and mutable. The export is only as good as the stream and trusted head handed to it.
- `severity_id 0` (Unknown) on Base Events is a deliberate choice; some consumers may prefer 1 (Informational). No ACS field supports either value.
- ACS timestamps with sub-millisecond precision lose it in `time` (epoch ms). The exact string is kept in `metadata.original_time` and `unmapped.acs.timestamp`.
- Detection Finding `finding_info.uid` inherits the `IncidentClassifier` id format, including its occurrence index. It stays stable across re-exports of the same stream and of longer streams with the same prefix.
- Incidents are aligned to events without changing `IncidentClassifier`. This relies on the classifier deciding each event independently. The exporter fails closed (`OcsfMappingError`) if the alignment ever breaks.
