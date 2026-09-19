export class CorrelationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CorrelationError";
  }
}

interface ExecutionCorrelationRecord {
  toolName: string;
}

export class ExecutionCorrelationStore {
  // Stores string keys: `${sessionId}:${requestId}`
  private records = new Map<string, ExecutionCorrelationRecord>();

  public registerExecution(sessionId: string, requestId: string, toolName: string): void {
    this.records.set(`${sessionId}:${requestId}`, { toolName });
  }

  public validateAndConsume(sessionId: string, requestIdRef: string, resultToolName: string): void {
    const key = `${sessionId}:${requestIdRef}`;
    const record = this.records.get(key);

    if (!record) {
      throw new CorrelationError(`Unknown or already consumed request_id_ref: ${requestIdRef}`);
    }

    if (record.toolName !== resultToolName) {
      throw new CorrelationError(`Tool name mismatch. Expected '${record.toolName}', got '${resultToolName}'`);
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
