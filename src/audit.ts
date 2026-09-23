import { createHash } from "node:crypto";
import { canonicalize } from "json-canonicalize";
import { AuditEvent, AuditEventType } from "./acs-types";

export const AUDIT_GENESIS_HASH = "GENESIS";

export type AuditIntegrityResult =
  | { valid: true }
  | {
      valid: false;
      index: number;
      reason:
        | "missing_hash"
        | "genesis_mismatch"
        | "previous_hash_mismatch"
        | "event_hash_mismatch";
    };

export class AuditIntegrityError extends Error {
  readonly result: Extract<AuditIntegrityResult, { valid: false }>;

  constructor(result: Extract<AuditIntegrityResult, { valid: false }>) {
    super(`Audit integrity verification failed at event ${result.index}: ${result.reason}`);
    this.name = "AuditIntegrityError";
    this.result = result;
  }
}

export class AuditCollector {
  private events: AuditEvent[] = [];

  record(request_id: string, event_type: AuditEventType, metadata?: Record<string, unknown>) {
    const eventWithoutHash: AuditEvent = {
      timestamp: new Date().toISOString(),
      request_id,
      event_type,
      metadata
    };
    const previous_hash = this.events.at(-1)?.event_hash ?? AUDIT_GENESIS_HASH;
    const event: AuditEvent = {
      ...eventWithoutHash,
      previous_hash,
      event_hash: AuditCollector.computeHash(eventWithoutHash, previous_hash)
    };
    this.events.push(event);
  }

  getEvents(): AuditEvent[] {
    return this.events.map(event => ({
      ...event,
      metadata: event.metadata === undefined
        ? undefined
        : JSON.parse(JSON.stringify(event.metadata)) as Record<string, unknown>
    }));
  }

  getEventsForRequest(request_id: string): AuditEvent[] {
    return this.events.filter(e => e.request_id === request_id);
  }

  clear() {
    this.events = [];
  }

  verifyIntegrity(): AuditIntegrityResult {
    return AuditCollector.verifyIntegrity(this.events);
  }

  assertIntegrity(events: readonly AuditEvent[] = this.events): void {
    const result = AuditCollector.verifyIntegrity(events);
    if (!result.valid) {
      throw new AuditIntegrityError(result);
    }
  }

  static verifyIntegrity(events: readonly AuditEvent[]): AuditIntegrityResult {
    let previous_hash = AUDIT_GENESIS_HASH;
    for (const [index, event] of events.entries()) {
      if (!event.previous_hash || !event.event_hash) {
        return { valid: false, index, reason: "missing_hash" };
      }
      if (event.previous_hash !== previous_hash) {
        return {
          valid: false,
          index,
          reason: index === 0 ? "genesis_mismatch" : "previous_hash_mismatch"
        };
      }
      const expectedHash = AuditCollector.computeHash(event, event.previous_hash);
      if (event.event_hash !== expectedHash) {
        return { valid: false, index, reason: "event_hash_mismatch" };
      }
      previous_hash = event.event_hash;
    }
    return { valid: true };
  }

  private static computeHash(event: AuditEvent, previous_hash: string): string {
    const content = {
      timestamp: event.timestamp,
      request_id: event.request_id,
      event_type: event.event_type,
      metadata: event.metadata,
      previous_hash
    };
    return createHash("sha256")
      .update(canonicalize(content))
      .digest("hex");
  }
}
