import { createHash } from "crypto";
import { AuditEvent, AuditEventType } from "./acs-types";

export type IncidentSeverity = "low" | "medium" | "high" | "critical";

export type IncidentType =
  | "replay_attempt"
  | "correlation_failure"
  | "result_policy_violation"
  | "request_freshness_violation"
  | "authority_authentication_failure"
  | "authority_boundary_violation";

export interface IncidentEvidenceRef {
  event_type: AuditEventType;
  request_id: string;
  session_id?: string;
  agent_id?: string;
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
  agent_id?: string;
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
    const agentId = (event.metadata?.agent_id as string) || "";
    const reqIdRef = (event.metadata?.request_id_ref as string) || "";
    const tool =
      (event.metadata?.tool as string) ||
      (event.metadata?.expected_tool as string) ||
      "";
    const reason = (event.metadata?.reason as string) || (event.metadata?.reason_code as string) || "";
    const decision = (event.metadata?.decision as string) || "";

    // Preserve the legacy fingerprint shape for pre-authority events.
    const fingerprintParts: unknown[] = [
      event.event_type,
      event.timestamp,
      sessionId,
      event.request_id || "",
      reqIdRef,
      tool,
      reason,
      decision,
    ];

    // Authority events extend identity with trusted agent context without
    // changing historical fingerprints for existing incident types.
    if (
      event.event_type === "capability_rejected" ||
      event.event_type === "approval_verification_failed"
    ) {
      fingerprintParts.push(agentId);
    }

    const serialized = JSON.stringify(fingerprintParts);

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

      case "capability_rejected": {
        const reason = event.metadata?.reason;

        if (reason === "capability_authentication_failed") {
          return this.buildIncident(
            event,
            "authority_authentication_failure",
            "high",
            "blocked",
            true,
            fingerprint,
            occurrenceIndex
          );
        }

        if (
          reason === "capability_agent_mismatch" ||
          reason === "capability_session_mismatch" ||
          reason === "capability_scope_mismatch"
        ) {
          return this.buildIncident(
            event,
            "authority_boundary_violation",
            "high",
            "blocked",
            true,
            fingerprint,
            occurrenceIndex
          );
        }

        // Missing capability, provider failures, freshness failures,
        // malformed grants and unsupported scopes are not automatically
        // security incidents.
        return null;
      }

      case "approval_verification_failed": {
        const reason = event.metadata?.reason;

        if (reason === "invalid_signature") {
          return this.buildIncident(
            event,
            "authority_authentication_failure",
            "high",
            "blocked",
            true,
            fingerprint,
            occurrenceIndex
          );
        }

        if (
          reason === "tool_binding_mismatch" ||
          reason === "wrong_approver_identity"
        ) {
          return this.buildIncident(
            event,
            "authority_boundary_violation",
            "high",
            "blocked",
            true,
            fingerprint,
            occurrenceIndex
          );
        }

        // session_mismatch and request_mismatch are verifier-level
        // invariants but are not currently reachable through the
        // GuardedExecutor runtime because pending lookup happens first.
        // Other approval failures are policy, lifecycle or malformed-input
        // outcomes rather than automatic security incidents.
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
    const agentId = (event.metadata?.agent_id as string) || undefined;
    const tool =
      (event.metadata?.tool as string) ||
      (event.metadata?.expected_tool as string) ||
      undefined;
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
      agent_id: agentId,
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
          agent_id: agentId,
          source_fingerprint: fingerprint,
          occurrence_index: occurrenceIndex,
        },
      ],
    };
  }
}
