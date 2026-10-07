import { AuditEventType } from "../acs-types";
import { IncidentEnvelopeV1, IncidentSeverity } from "../incident-evidence";
import packageJson from "../../package.json";
import {
  ACS_OCSF_EVENT_UID_PREFIX,
  ACS_OCSF_PROVENANCE_SCHEMA,
  AcsProvenance,
  AllowlistedMetadataValue,
  OCSF_SCHEMA_VERSION,
  OcsfBaseEvent,
  OcsfDetectionFinding,
  OcsfEvent,
  OcsfMappingError,
  OcsfMetadata,
  VerifiedAuditEvent,
} from "./types";

/**
 * Explicit per-event-type allowlist of ACS metadata keys that may cross into
 * the OCSF export. The export target is a different trust boundary from the
 * in-process audit collector, so nothing is copied by default. Keys not listed
 * here (including any key a future tool or caller adds) are dropped and only
 * counted in `omitted_metadata_key_count`.
 *
 * Deliberately excluded today:
 * - `approver_id` (human_approval / human_rejection): approver identity claim;
 *   identity mapping to a log system is out of scope for this export.
 * - `raw` (timestamp_rejected): attacker-controlled request input.
 */
export const OCSF_METADATA_ALLOWLIST: Readonly<Record<AuditEventType, readonly string[]>> = Object.freeze({
  tool_call_requested: ["session_id", "tool"],
  capability_verified: ["capability_id", "agent_id", "session_id", "tool"],
  capability_rejected: ["reason", "agent_id", "session_id", "tool"],
  guardian_decision: ["session_id", "decision", "reason_codes"],
  tool_execution_blocked: ["reason", "error"],
  approval_requested: ["session_id"],
  approval_verification_failed: ["reason", "session_id", "expected_tool"],
  approval_expired: ["session_id"],
  human_approval: ["approver_type", "session_id", "request_id"],
  human_rejection: ["approver_type", "session_id", "request_id"],
  tool_execution_started: [],
  tool_execution_completed: ["status"],
  tool_result_created: ["tool"],
  result_guardian_decision: ["decision", "reason_codes"],
  tool_result_withheld: ["tool"],
  tool_result_delivered: ["tool"],
  replay_rejected: ["session_id", "reason_code"],
  timestamp_rejected: ["session_id", "reason_code", "delta_ms", "skew_window_ms"],
  correlation_failed: ["session_id", "request_id_ref", "tool", "disposition", "reason"],
  authority_revoked: ["revocation_id", "scope", "session_id", "capability_id", "status", "effective_sequence", "effective_at", "pending_approvals", "in_flight_executions"],
  authority_revocation_enforced: ["stage", "boundary", "decision", "reason", "revocation_id", "session_id", "capability_id", "tool", "request_id_ref"],
  execution_cancellation_requested: ["execution_id", "session_id", "capability_id", "revocation_id", "listeners"],
  execution_cancellation_acknowledged: ["execution_id", "session_id", "capability_id"],
  tool_commit_requested: ["execution_id", "session_id", "capability_id", "key"],
  tool_commit_applied: ["execution_id", "session_id", "capability_id", "key", "commit_id", "sequence"],
  tool_commit_blocked: ["execution_id", "session_id", "capability_id", "key", "decision", "reason", "revocation_id"],
  execution_terminal: ["execution_id", "session_id", "capability_id", "outcome", "cancellation_requested", "cancellation_acknowledged", "listener_errors", "tracked_registered", "tracked_fulfilled", "tracked_rejected"],
});

/** ACS request_id sentinel used when the request identity is not known. */
const UNKNOWN_REQUEST_ID = "unknown";

/** RFC 3339 date-time, as used by the OCSF 1.8.0 `datetime_t` type. */
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

const SEVERITY_ID: Record<IncidentSeverity, { id: number; caption: string }> = {
  low: { id: 2, caption: "Low" },
  medium: { id: 3, caption: "Medium" },
  high: { id: 4, caption: "High" },
  critical: { id: 5, caption: "Critical" },
};

export const OCSF_PRODUCT = Object.freeze({
  name: packageJson.name,
  version: packageJson.version,
});

export function ocsfEventUid(eventHash: string): string {
  return `${ACS_OCSF_EVENT_UID_PREFIX}${eventHash}`;
}

/**
 * Maps one verified ACS audit event to its OCSF 1.8.0 representation.
 *
 * `incident` must be the `IncidentClassifier` result derived from this exact
 * event; only then is a Detection Finding produced. Everything else becomes a
 * Base Event. No actor, user, endpoint, device, tenant or API fields are
 * produced because the ACS audit event does not carry verified values for them.
 */
export function mapAuditEventToOcsf(
  event: VerifiedAuditEvent,
  chainIndex: number,
  incident?: IncidentEnvelopeV1
): OcsfEvent {
  const time = parseSourceTime(event.timestamp, chainIndex);
  const metadata = buildMetadata(event, chainIndex);
  const acs = buildProvenance(event, chainIndex);

  if (incident) {
    if (incident.source_event_type !== event.event_type || incident.request_id !== event.request_id) {
      throw new OcsfMappingError(chainIndex, "incident evidence does not belong to this event");
    }
    const severity = SEVERITY_ID[incident.severity];
    if (!severity) {
      throw new OcsfMappingError(chainIndex, `unsupported incident severity '${String(incident.severity)}'`);
    }
    acs.incident = {
      classifier: "IncidentClassifier",
      envelope_version: incident.version,
      incident_id: incident.incident_id,
      incident_type: incident.incident_type,
      severity: incident.severity,
      disposition: incident.disposition,
      requires_human_review: incident.requires_human_review,
    };
    const finding: OcsfDetectionFinding = {
      class_uid: 2004,
      class_name: "Detection Finding",
      category_uid: 2,
      category_name: "Findings",
      activity_id: 1,
      activity_name: "Create",
      type_uid: 200401,
      type_name: "Detection Finding: Create",
      severity_id: severity.id,
      severity: severity.caption,
      time,
      message: `ACS incident ${incident.incident_type} derived from audit event ${event.event_type}`,
      finding_info: {
        uid: incident.incident_id,
        title: `ACS incident: ${incident.incident_type}`,
        types: [incident.incident_type],
      },
      metadata,
      unmapped: { acs },
    };
    return finding;
  }

  const base: OcsfBaseEvent = {
    class_uid: 0,
    class_name: "Base Event",
    category_uid: 0,
    category_name: "Uncategorized",
    activity_id: 99,
    activity_name: event.event_type,
    type_uid: 99,
    // type_uid 99 is "Other": its sibling carries the source-specific value
    // (OCSF "class_name: activity_name"), not the generic caption.
    type_name: `Base Event: ${event.event_type}`,
    // ACS audit events carry no severity; do not invent one.
    severity_id: 0,
    severity: "Unknown",
    time,
    message: `ACS audit event ${event.event_type}`,
    metadata,
    unmapped: { acs },
  };

  // The only ACS event with an explicit, recorded success/failure outcome.
  if (event.event_type === "tool_execution_completed") {
    const status = event.metadata?.status;
    if (status === "success") {
      base.status_id = 1;
      base.status = "Success";
    } else if (status === "error") {
      base.status_id = 2;
      base.status = "Failure";
    }
  }

  return base;
}

function parseSourceTime(timestamp: string, index: number): number {
  if (typeof timestamp !== "string" || !RFC3339.test(timestamp)) {
    throw new OcsfMappingError(index, "source timestamp is not an RFC 3339 date-time");
  }
  const ms = Date.parse(timestamp);
  if (!Number.isFinite(ms)) {
    throw new OcsfMappingError(index, "source timestamp is not a valid date-time");
  }
  return ms;
}

function buildMetadata(event: VerifiedAuditEvent, chainIndex: number): OcsfMetadata {
  const metadata: OcsfMetadata = {
    version: OCSF_SCHEMA_VERSION,
    product: { name: OCSF_PRODUCT.name, version: OCSF_PRODUCT.version },
    uid: ocsfEventUid(event.event_hash),
    event_code: event.event_type,
    original_time: event.timestamp,
    sequence: chainIndex,
  };
  // "unknown" is a sentinel for missing request identity; using it as a
  // correlation id would falsely correlate unrelated events.
  if (typeof event.request_id === "string" && event.request_id !== "" && event.request_id !== UNKNOWN_REQUEST_ID) {
    metadata.correlation_uid = event.request_id;
  }
  return metadata;
}

function buildProvenance(event: VerifiedAuditEvent, chainIndex: number): AcsProvenance {
  const { allowed, omitted } = filterMetadata(event.event_type, event.metadata);
  const provenance: AcsProvenance = {
    provenance_schema: ACS_OCSF_PROVENANCE_SCHEMA,
    event_type: event.event_type,
    request_id: event.request_id,
    timestamp: event.timestamp,
    previous_hash: event.previous_hash,
    event_hash: event.event_hash,
    hash_algorithm: "SHA-256",
    hash_canonicalization: "RFC 8785 JSON canonicalization",
    chain_index: chainIndex,
    omitted_metadata_key_count: omitted,
  };
  if (allowed) {
    provenance.metadata = allowed;
  }
  return provenance;
}

function filterMetadata(
  eventType: AuditEventType,
  metadata: Readonly<Record<string, unknown>> | undefined
): { allowed?: Record<string, AllowlistedMetadataValue>; omitted: number } {
  if (!metadata || typeof metadata !== "object") {
    return { omitted: 0 };
  }
  const allowlist = Object.prototype.hasOwnProperty.call(OCSF_METADATA_ALLOWLIST, eventType)
    ? OCSF_METADATA_ALLOWLIST[eventType]
    : [];
  const keys = Object.keys(metadata);
  const allowed: Record<string, AllowlistedMetadataValue> = {};
  let omitted = 0;
  for (const key of keys.sort()) {
    const value = metadata[key];
    if (allowlist.includes(key) && isAllowlistedValue(value)) {
      allowed[key] = Array.isArray(value) ? [...value] : value;
    } else if (value !== undefined) {
      omitted++;
    }
  }
  return { allowed: Object.keys(allowed).length > 0 ? allowed : undefined, omitted };
}

/** Only flat scalars and string arrays; nested objects never cross the boundary. */
function isAllowlistedValue(value: unknown): value is AllowlistedMetadataValue {
  if (typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  return Array.isArray(value) && value.every(v => typeof v === "string");
}
