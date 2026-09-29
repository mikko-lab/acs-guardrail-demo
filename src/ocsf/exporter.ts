import { canonicalize } from "json-canonicalize";
import { AuditEvent } from "../acs-types";
import { AuditCollector } from "../audit";
import { IncidentClassifier, IncidentEnvelopeV1 } from "../incident-evidence";
import { mapAuditEventToOcsf } from "./mapper";
import {
  OCSF_SCHEMA_VERSION,
  OcsfEvent,
  OcsfExportIntegrityError,
  OcsfExportOptions,
  OcsfExportResult,
  OcsfMappingError,
  OcsfTrustedHeadRequiredError,
  OcsfValidationError,
  VerifiedAuditEvent,
} from "./types";
import { validateOcsfEvent } from "./validator";

/**
 * Converts a verified ACS audit stream into its derived OCSF 1.8.0
 * representation.
 *
 * Order of operations (fail closed at every step; nothing partial is returned):
 *   1. detach a JSON snapshot of the input (the caller's objects are never
 *      mutated, and later mutation cannot affect what was verified);
 *   2. AuditCollector.verifyIntegrity(snapshot, expectedHeadHash);
 *   3. map each verified event (Detection Finding only where IncidentClassifier
 *      derives an incident from that exact event, otherwise Base Event);
 *   4. validate each OCSF event against the vendored OCSF 1.8.0 subset.
 *
 * The ACS hash chain is not recomputed or altered; OCSF events are a derived
 * view, not new audit chain entries.
 */
export function exportAuditToOcsf(
  events: readonly AuditEvent[],
  options: OcsfExportOptions = {}
): OcsfExportResult {
  if (options.requireTrustedHead && options.expectedHeadHash === undefined) {
    throw new OcsfTrustedHeadRequiredError();
  }

  const snapshot = snapshotEvents(events);

  const integrity = AuditCollector.verifyIntegrity(snapshot, options.expectedHeadHash);
  if (!integrity.valid) {
    throw new OcsfExportIntegrityError(integrity);
  }
  const verified = snapshot as VerifiedAuditEvent[];

  const incidents = incidentsByEvent(verified);

  const out: OcsfEvent[] = [];
  for (const [index, event] of verified.entries()) {
    const ocsf = mapAuditEventToOcsf(event, index, incidents[index]);
    const issues = validateOcsfEvent(ocsf);
    if (issues.length > 0) {
      throw new OcsfValidationError(index, issues);
    }
    out.push(ocsf);
  }

  return {
    ocsf_version: OCSF_SCHEMA_VERSION,
    integrity: options.expectedHeadHash !== undefined ? "trusted_head" : "structural",
    source_event_count: verified.length,
    source_head_hash: verified.at(-1)?.event_hash ?? null,
    events: out,
  };
}

/**
 * Deterministic JSONL: one RFC 8785 canonical JSON OCSF event per line, each
 * line terminated by "\n". An empty list yields "". No export-time values are
 * added.
 */
export function serializeOcsfJsonl(events: readonly OcsfEvent[]): string {
  return events.map(event => canonicalize(event) + "\n").join("");
}

/** Convenience: verify, map, validate and serialize in one fail-closed call. */
export function exportAuditToOcsfJsonl(events: readonly AuditEvent[], options?: OcsfExportOptions): string {
  return serializeOcsfJsonl(exportAuditToOcsf(events, options).events);
}

function snapshotEvents(events: readonly AuditEvent[]): AuditEvent[] {
  if (!Array.isArray(events)) {
    throw new TypeError("events must be an array of ACS audit events");
  }
  // One JSON round-trip: detaches from caller objects and resolves any
  // accessor exactly once, so verification and mapping see the same values.
  return JSON.parse(JSON.stringify(events)) as AuditEvent[];
}

/**
 * Aligns IncidentClassifier output with source events without changing the
 * classifier. The classifier's per-event decision is independent of other
 * events (only occurrence_index depends on history), so classifying a single
 * event tells us whether the full-stream run emitted an incident for it; the
 * full-stream incidents are then consumed in order to keep stream-level ids.
 */
function incidentsByEvent(events: readonly VerifiedAuditEvent[]): Array<IncidentEnvelopeV1 | undefined> {
  const all = IncidentClassifier.fromAudit(events.map(e => ({ ...e })));
  const result: Array<IncidentEnvelopeV1 | undefined> = [];
  let cursor = 0;
  for (const [index, event] of events.entries()) {
    const single = IncidentClassifier.fromAudit([{ ...event }]);
    if (single.length === 0) {
      result.push(undefined);
      continue;
    }
    const incident = all[cursor++];
    if (
      !incident ||
      incident.incident_type !== single[0].incident_type ||
      incident.source_event_type !== event.event_type ||
      incident.request_id !== event.request_id ||
      incident.evidence_refs[0]?.source_fingerprint !== single[0].evidence_refs[0]?.source_fingerprint
    ) {
      throw new OcsfMappingError(index, "incident classification could not be aligned with the source event");
    }
    result.push(incident);
  }
  if (cursor !== all.length) {
    throw new OcsfMappingError(events.length - 1, "incident classification produced unaligned incidents");
  }
  return result;
}
