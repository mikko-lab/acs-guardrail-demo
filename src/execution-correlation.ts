export class CorrelationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CorrelationError";
  }
}

export class ExecutionCorrelationStore {
  // Stores string keys: `${sessionId}:${requestId}`
  private executed = new Set<string>();

  public markExecuted(sessionId: string, requestId: string): void {
    this.executed.add(`${sessionId}:${requestId}`);
  }

  public validateAndConsume(sessionId: string, requestIdRef: string): void {
    const key = `${sessionId}:${requestIdRef}`;
    if (!this.executed.has(key)) {
      throw new CorrelationError(`Unknown or already consumed request_id_ref: ${requestIdRef}`);
    }
    this.executed.delete(key);
  }

  public clearSession(sessionId: string): void {
    for (const key of this.executed) {
      if (key.startsWith(`${sessionId}:`)) {
        this.executed.delete(key);
      }
    }
  }
}

