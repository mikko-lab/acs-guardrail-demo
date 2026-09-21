import type { AuditCollector } from "./audit";

export class CorrelationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CorrelationError";
  }
}

interface ExecutionCorrelationRecord {
  toolName: string;
}

/**
 * Context supplied by the GuardedExecutor when calling validateAndConsume
 * so that a failed correlation produces a correlation_failed audit event
 * before the CorrelationError propagates.
 *
 * Call-site contract (enforced by code review, not the type system):
 *   - Production runtime path: MUST always supply ctx.
 *     There is exactly one production call site: GuardedExecutor.processResultRequest.
 *     That method has both the AuditCollector and all required identifiers available;
 *     omitting ctx there would silently suppress evidence.
 *   - Unit tests that test the store in isolation (e.g. execution-correlation.test.ts
 *     M-05 suite, result-gate.test.ts) may omit ctx because they are testing the
 *     correlation logic itself, not the audit integration. These callers are
 *     intentionally omitting ctx and the behaviour is identical to the pre-WP-01
 *     implementation for those code paths.
 *
 * Fields:
 *   resultRequestId — The request_id of the current result request (AuditEvent.request_id).
 *                     This is NOT the same as requestIdRef; it is the new request's own ID.
 *   sessionId       — The session_id shared by all requests in this session.
 *   tool            — The tool name reported in the result envelope (may be a mismatch).
 *   audit           — The AuditCollector to write the event to.
 */
export interface CorrelationAuditContext {
  audit: AuditCollector;
  resultRequestId: string;
  sessionId: string;
  tool: string;
}

export class ExecutionCorrelationStore {
  // Stores string keys: `${sessionId}:${requestId}`
  private records = new Map<string, ExecutionCorrelationRecord>();

  public registerExecution(sessionId: string, requestId: string, toolName: string): void {
    this.records.set(`${sessionId}:${requestId}`, { toolName });
  }

  /**
   * Validate that requestIdRef refers to a registered execution and that the
   * tool name matches; consume the record on success.
   *
   * Security semantics (unchanged from v0.1.0):
   *   - An unknown or already-consumed reference always throws CorrelationError.
   *   - A tool-name mismatch always throws CorrelationError.
   *   - When ctx is provided, a correlation_failed event is recorded BEFORE the
   *     throw so that evidence is always created regardless of how the caller
   *     handles the exception.
   *   - A failure to record the audit event does NOT suppress the throw;
   *     evidence write errors are caught silently to preserve fail-closed
   *     semantics.
   *
   * On the optional ctx parameter:
   *   ctx is optional for backward compatibility with low-level unit tests
   *   that test the store in isolation and have no audit infrastructure. The
   *   one production call site (GuardedExecutor.processResultRequest) always
   *   supplies ctx. See CorrelationAuditContext for the full contract.
   *
   * Reason-code note:
   *   An already-consumed reference is indistinguishable from an unknown one
   *   at this layer because the record is deleted on successful consume.
   *   Both cases use reason "unresolved_request_id_ref". No artificial
   *   distinction is introduced (WP-01 accepted limitation).
   */
  public validateAndConsume(
    sessionId: string,
    requestIdRef: string,
    resultToolName: string,
    ctx?: CorrelationAuditContext,
  ): void {
    const key = `${sessionId}:${requestIdRef}`;
    const record = this.records.get(key);

    if (!record) {
      const err = new CorrelationError(
        `Unknown or already consumed request_id_ref: ${requestIdRef}`,
      );
      if (ctx) {
        try {
          ctx.audit.record(ctx.resultRequestId, "correlation_failed", {
            session_id: ctx.sessionId,
            request_id_ref: requestIdRef,
            tool: ctx.tool,
            disposition: "deny",
            reason: "unresolved_request_id_ref",
          });
        } catch {
          // Audit write failure must never open an execution path.
        }
      }
      throw err;
    }

    if (record.toolName !== resultToolName) {
      const err = new CorrelationError(
        `Tool name mismatch. Expected '${record.toolName}', got '${resultToolName}'`,
      );
      if (ctx) {
        try {
          ctx.audit.record(ctx.resultRequestId, "correlation_failed", {
            session_id: ctx.sessionId,
            request_id_ref: requestIdRef,
            tool: ctx.tool,
            disposition: "deny",
            reason: "tool_name_mismatch",
          });
        } catch {
          // Audit write failure must never open an execution path.
        }
      }
      throw err;
    }

    this.records.delete(key);
  }

  public clearSession(sessionId: string): void {
    for (const key of this.records.keys()) {
      if (key.startsWith(`${sessionId}:`)) {
        this.records.delete(key);
      }
    }
  }
}
