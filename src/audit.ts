import { AuditEvent, AuditEventType } from "./acs-types";

export class AuditCollector {
  private events: AuditEvent[] = [];

  record(request_id: string, event_type: AuditEventType, metadata?: Record<string, unknown>) {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      request_id,
      event_type,
      metadata
    };
    this.events.push(event);
  }

  getEvents(): AuditEvent[] {
    return [...this.events];
  }

  getEventsForRequest(request_id: string): AuditEvent[] {
    return this.events.filter(e => e.request_id === request_id);
  }

  clear() {
    this.events = [];
  }
}
