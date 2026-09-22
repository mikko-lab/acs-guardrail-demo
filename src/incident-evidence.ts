import { createHash } from "crypto";
import { AuditEvent, AuditEventType } from "./acs-types";

export type IncidentSeverity = "low" | "medium" | "high" | "critical";

export type IncidentType =
  | "replay_attempt"
  | "correlation_failure"
  | "result_policy_violation"
  | "request_freshness_violation";

export interface IncidentEvidenceRef {
  event_type: AuditEventType;
  request_id: string;
  session_id?: string;
  source_fingerprint: string;
  occurrence_index: number;
}

export interface IncidentEnvelopeV1 {
  version: "1";
  incident_id: string;
  detected_at: string;
  incident_type: IncidentType;
  severity: IncidentSeverity;
  disposition: string;
  requires_human_review: boolean;
  session_id?: string;
  request_id?: string;
  request_id_ref?: string;
  tool?: string;
  source_event_type: AuditEventType;
  reason?: string;
  evidence_refs: IncidentEvidenceRef[];
}

export class IncidentClassifier {
  /**
   * Evaluates an audit event stream and deterministically derives
   * a list of security and boundary-violation incidents.
   */
  static fromAudit(events: AuditEvent[]): IncidentEnvelopeV1[] {
    const incidents: IncidentEnvelopeV1[] = [];
    const occurrenceCounts = new Map<string, number>();

    for (const event of events) {
      if (!this.isValidTimestamp(event.timestamp)) {
        continue; // Missing or invalid timestamp -> no incident (determinstic behavior)
      }

      const fingerprint = this.computeFingerprint(event);
      const currentCount = (occurrenceCounts.get(fingerprint) || 0) + 1;
      occurrenceCounts.set(fingerprint, currentCount);

      const incident = this.evaluateEvent(event, fingerprint, currentCount);
      if (incident) {
        incidents.push(incident);
      }
    }

    return incidents;
  }

  private static isValidTimestamp(timestamp?: string): boolean {
    if (!timestamp) return false;
    const date = new Date(timestamp);
    return !isNaN(date.getTime());
  }

  private static computeFingerprint(event: AuditEvent): string {
    const sessionId = (event.metadata?.session_id as string) || "";
    const reqIdRef = (event.metadata?.request_id_ref as string) || "";
    const tool = (event.metadata?.tool as string) || "";
    const reason = (event.metadata?.reason as string) || (event.metadata?.reason_code as string) || "";
    const decision = (event.metadata?.decision as string) || "";

    // Structural deterministic serialization to prevent delimiter ambiguity attacks
    const serialized = JSON.stringify([
      event.event_type,
      event.timestamp,
      sessionId,
      event.request_id || "",
      reqIdRef,
      tool,
      reason,
      decision,
    ]);

    return createHash("sha256").update(serialized).digest("hex");
  }

  private static evaluateEvent(event: AuditEvent, fingerprint: string, occurrenceIndex: number): IncidentEnvelopeV1 | null {
    switch (event.event_type) {
      case "replay_rejected":
        return this.buildIncident(
          event,
          "replay_attempt",
          "high",
          "blocked",
          true,
          fingerprint,
          occurrenceIndex
        );

      case "timestamp_rejected":
        return this.buildIncident(
          event,
          "request_freshness_violation",
          "medium", // freshness issues might just be latency, high would be actual replay
          "blocked",
          false,
          fingerprint,
          occurrenceIndex
        );

      case "correlation_failed":
        // NOTE: The current instrumentation (correlation_failed) cannot reliably
        // distinguish a true cross-session boundary attack from a generic unresolved reference.
        // Therefore, we classify all as correlation_failure to prevent false positive attribution.
        // This is a known instrumentation gap.
        return this.buildIncident(
          event,
          "correlation_failure",
          "high",
          "blocked",
          true,
          fingerprint,
          occurrenceIndex
        );

      case "result_guardian_decision": {
        const metadata = event.metadata || {};
        // Use ACTUAL schema: metadata.decision
        if (metadata.decision === "deny") {
          return this.buildIncident(
            event,
            "result_policy_violation",
            "medium",
            "withheld",
            false,
            fingerprint,
            occurrenceIndex
          );
        }
        return null;
      }

      // Normal control actions and oversight outcomes are ignored.
      case "guardian_decision":
      case "human_rejection":
      case "approval_expired":
      default:
        return null;
    }
  }

  private static buildIncident(
    event: AuditEvent,
    incident_type: IncidentType,
    severity: IncidentSeverity,
    disposition: string,
    requires_human_review: boolean,
    fingerprint: string,
    occurrenceIndex: number
  ): IncidentEnvelopeV1 {
    const sessionId = (event.metadata?.session_id as string) || undefined;
    const tool = (event.metadata?.tool as string) || undefined;
    const reason = (event.metadata?.reason as string) || (event.metadata?.reason_code as string) || undefined;
    const reqIdRef = (event.metadata?.request_id_ref as string) || undefined;

    // Stable identity based on exact event data and occurrence
    const incidentId = `INC-${fingerprint}-${occurrenceIndex}`;

    return {
      version: "1",
      incident_id: incidentId,
      detected_at: event.timestamp, // Guaranteed to be valid string here
      incident_type,
      severity,
      disposition,
      requires_human_review,
      session_id: sessionId,
      request_id: event.request_id,
      request_id_ref: reqIdRef,
      tool,
      source_event_type: event.event_type,
      reason,
      evidence_refs: [
        {
          event_type: event.event_type,
          request_id: event.request_id,
          session_id: sessionId,
          source_fingerprint: fingerprint,
          occurrence_index: occurrenceIndex,
        },
      ],
    };
  }
}
