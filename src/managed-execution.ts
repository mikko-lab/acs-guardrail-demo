/**
 * src/managed-execution.ts
 *
 * Cooperative containment for one managed tool execution (see docs/cooperative-containment.md).
 *
 * A managed execution gives its tool an ExecutionContext: a cancellation signal, a runtime-mediated commit
 * fence over the runtime-managed state store, and registration of background work. The runtime records one
 * terminal when the tool function and all registered work have settled.
 *
 * Only cooperating code and effects performed through ctx.commit() are controlled. Arbitrary tool code,
 * effects outside ctx.commit() and unregistered background work are not.
 */
import type { AuditCollector } from "./audit";

export class CancellationError extends Error {
  readonly code = "EXECUTION_CANCELLED";
  constructor(readonly execution_id: string, readonly revocation_id: string) {
    super(`Execution ${execution_id} cancelled: authority revoked (${revocation_id})`);
    this.name = "CancellationError";
  }
}

export type CommitBlockReason = "session_revoked" | "capability_revoked" | "execution_terminal" | "audit_unavailable";

export class CommitRejectedError extends Error {
  readonly code = "COMMIT_REJECTED";
  constructor(readonly execution_id: string, readonly key: string, readonly reason: CommitBlockReason) {
    super(`Commit of '${key}' rejected for execution ${execution_id}: ${reason}`);
    this.name = "CommitRejectedError";
  }
}

export interface CancellationSignal {
  readonly requested: boolean;
  readonly reason: CancellationError | undefined;
  /** Registers a listener; a listener registered after the request is called immediately. Returns an unsubscribe function. */
  onCancel(listener: (reason: CancellationError) => void): () => void;
  /** Throws this execution's CancellationError if cancellation was requested. */
  throwIfRequested(): void;
}

export interface CommitReceipt {
  commit_id: string;
  execution_id: string;
  key: string;
  sequence: number;
}

export interface ExecutionContext {
  readonly execution_id: string;
  readonly cancellation: CancellationSignal;
  /** Records receipt of the cancellation request. Returns true only for the first acknowledgement of a requested cancellation. */
  acknowledgeCancellation(): boolean;
  /** Runtime-mediated synchronous state change; throws CommitRejectedError if denied. */
  commit(key: string, value: unknown): CommitReceipt;
  /** Registers work that must settle before the execution is terminal. */
  track<T>(work: PromiseLike<T>): Promise<T>;
}

export type TerminalOutcome = "completed" | "cancelled" | "failed";

export interface ExecutionTerminal {
  execution_id: string;
  request_id: string;
  session_id: string;
  capability_id: string;
  outcome: TerminalOutcome;
  cancellation_requested: boolean;
  cancellation_acknowledged: boolean;
  listener_errors: number;
  tracked_registered: number;
  tracked_fulfilled: number;
  tracked_rejected: number;
}

export interface ExecutionSnapshot {
  execution_id: string;
  request_id: string;
  session_id: string;
  capability_id: string;
  state: "running" | "draining" | "terminal";
  cancellation_requested: boolean;
  cancellation_acknowledged: boolean;
  terminal?: ExecutionTerminal;
}

const MAX_KEY_LENGTH = 256;

/** Read-only view of the runtime-managed state. Values are returned as copies. */
export interface ReadonlyManagedState {
  get(key: string): unknown;
  has(key: string): boolean;
  keys(): string[];
  readonly version: number;
}

/**
 * Runtime-managed state: the only commit target of A2. It has exactly one writer, issued once to the
 * executor that owns it; everyone else gets the read-only view.
 */
export class ManagedStateStore implements ReadonlyManagedState {
  #data = new Map<string, string>();
  #version = 0;
  #writerIssued = false;

  issueWriter(): (key: string, json: string) => number {
    if (this.#writerIssued) throw new Error("ManagedStateStore writer already issued");
    this.#writerIssued = true;
    return (key, json) => {
      this.#data.set(key, json);
      return ++this.#version;
    };
  }
  get(key: string): unknown {
    const json = this.#data.get(key);
    return json === undefined ? undefined : JSON.parse(json);
  }
  has(key: string): boolean { return this.#data.has(key); }
  keys(): string[] { return [...this.#data.keys()].sort(); }
  get version(): number { return this.#version; }
  view(): ReadonlyManagedState {
    const store = this;
    return Object.freeze({
      get: (key: string) => store.get(key),
      has: (key: string) => store.has(key),
      keys: () => store.keys(),
      get version() { return store.version; },
    });
  }
}

export interface ManagedExecutionDeps {
  audit: AuditCollector;
  /** Current revocation state of the execution's authority; consulted at the commit binding check. */
  revoked(): { reason: "session_revoked" | "capability_revoked"; revocation_id: string } | undefined;
  write(key: string, json: string): number;
  nextCommitId(): string;
  onTerminal(terminal: ExecutionTerminal): void;
}

type ToolFn = (args: Record<string, unknown>, ctx?: ExecutionContext) => Promise<unknown>;

export class ManagedExecution {
  readonly context: ExecutionContext;
  #state: "running" | "draining" | "terminal" = "running";
  #mainSettled = false;
  #mainOutcome: TerminalOutcome = "completed";
  #cancellation: CancellationError | undefined;
  #acknowledged = false;
  #listeners = new Set<(reason: CancellationError) => void>();
  #listenerErrors = 0;
  #tracked = { registered: 0, fulfilled: 0, rejected: 0, pending: 0 };
  #terminal: ExecutionTerminal | undefined;
  readonly terminalPromise: Promise<ExecutionTerminal>;
  #resolveTerminal!: (t: ExecutionTerminal) => void;

  constructor(
    readonly id: string,
    readonly requestId: string,
    readonly sessionId: string,
    readonly capabilityId: string,
    private readonly deps: ManagedExecutionDeps
  ) {
    this.terminalPromise = new Promise(resolve => (this.#resolveTerminal = resolve));
    const self = this;
    const cancellation: CancellationSignal = Object.freeze({
      get requested() { return self.#cancellation !== undefined; },
      get reason() { return self.#cancellation; },
      onCancel: (listener: (reason: CancellationError) => void) => self.#onCancel(listener),
      throwIfRequested: () => { if (self.#cancellation) throw self.#cancellation; },
    });
    this.context = Object.freeze({
      execution_id: id,
      cancellation,
      acknowledgeCancellation: () => this.#acknowledge(),
      commit: (key: string, value: unknown) => this.#commit(key, value),
      track: <T>(work: PromiseLike<T>) => this.#track(work),
    });
  }

  get terminal(): boolean { return this.#state === "terminal"; }
  get cancellationRequested(): boolean { return this.#cancellation !== undefined; }

  snapshot(): ExecutionSnapshot {
    return {
      execution_id: this.id,
      request_id: this.requestId,
      session_id: this.sessionId,
      capability_id: this.capabilityId,
      state: this.#state,
      cancellation_requested: this.#cancellation !== undefined,
      cancellation_acknowledged: this.#acknowledged,
      ...(this.#terminal ? { terminal: { ...this.#terminal } } : {}),
    };
  }

  /** Calls the tool function with this execution's context and observes its settlement. */
  invoke(toolFn: ToolFn, args: Record<string, unknown>): Promise<unknown> {
    let pending: Promise<unknown>;
    try {
      pending = Promise.resolve(toolFn(args, this.context));
    } catch (e) {
      pending = Promise.reject(e);
    }
    pending.then(
      () => this.#settleMain("completed"),
      (e: unknown) => this.#settleMain(e === this.#cancellation && e !== undefined ? "cancelled" : "failed")
    );
    return pending;
  }

  /** Called by revoke() after the tombstone exists. Idempotent per execution. */
  requestCancellation(revocationId: string): void {
    if (this.#state === "terminal" || this.#cancellation) return;
    this.#cancellation = new CancellationError(this.id, revocationId);
    try {
      this.deps.audit.record(this.requestId, "execution_cancellation_requested", {
        ...this.#binding(),
        revocation_id: revocationId,
        listeners: this.#listeners.size,
      });
    } catch {
      // Evidence failure does not stop the cancellation request.
    }
    for (const listener of [...this.#listeners]) this.#callListener(listener);
  }

  #binding() {
    return { execution_id: this.id, session_id: this.sessionId, capability_id: this.capabilityId };
  }

  #onCancel(listener: (reason: CancellationError) => void): () => void {
    if (typeof listener !== "function") throw new TypeError("listener must be a function");
    if (this.#cancellation) {
      this.#callListener(listener);
      return () => undefined;
    }
    this.#listeners.add(listener);
    return () => { this.#listeners.delete(listener); };
  }

  #callListener(listener: (reason: CancellationError) => void): void {
    try {
      listener(this.#cancellation!);
    } catch {
      this.#listenerErrors++;
    }
  }

  #acknowledge(): boolean {
    if (!this.#cancellation || this.#acknowledged || this.#state === "terminal") return false;
    this.#acknowledged = true;
    try {
      this.deps.audit.record(this.requestId, "execution_cancellation_acknowledged", this.#binding());
    } catch {
      // The acknowledgement is recorded in the execution state regardless.
    }
    return true;
  }

  #blocked(key: string, reason: CommitBlockReason, revocationId?: string): never {
    try {
      this.deps.audit.record(this.requestId, "tool_commit_blocked", {
        ...this.#binding(),
        key,
        decision: "deny",
        reason,
        ...(revocationId !== undefined ? { revocation_id: revocationId } : {}),
      });
    } catch {
      // Evidence failure does not open the commit.
    }
    throw new CommitRejectedError(this.id, key, reason);
  }

  #commit(key: string, value: unknown): CommitReceipt {
    if (this.#state === "terminal") this.#blocked(String(key), "execution_terminal");
    if (typeof key !== "string" || key.length === 0 || key.length > MAX_KEY_LENGTH) {
      throw new TypeError(`commit key must be a non-empty string of at most ${MAX_KEY_LENGTH} characters`);
    }
    // Serialization may run caller code (toJSON); it happens before the binding check.
    const json = JSON.stringify(value);
    if (json === undefined) throw new TypeError("commit value must be JSON-serializable");
    try {
      this.deps.audit.record(this.requestId, "tool_commit_requested", { ...this.#binding(), key });
    } catch {
      this.#blocked(key, "audit_unavailable");
    }

    // Binding check: nothing runs between this check and the write. (Re-read through the getter: the callbacks
    // above may have changed the state.)
    if (this.terminal) this.#blocked(key, "execution_terminal");
    const revoked = this.deps.revoked();
    if (revoked) this.#blocked(key, revoked.reason, revoked.revocation_id);
    const sequence = this.deps.write(key, json);

    const commit_id = this.deps.nextCommitId();
    try {
      this.deps.audit.record(this.requestId, "tool_commit_applied", { ...this.#binding(), key, commit_id, sequence });
    } catch {
      // The write has happened and is not undone.
    }
    return { commit_id, execution_id: this.id, key, sequence };
  }

  #track<T>(work: PromiseLike<T>): Promise<T> {
    if (this.#state === "terminal") throw new Error(`Execution ${this.id} is terminal; work can no longer be registered`);
    if (!work || typeof (work as PromiseLike<T>).then !== "function") throw new TypeError("track() requires a promise");
    this.#tracked.registered++;
    this.#tracked.pending++;
    const tracked = Promise.resolve(work);
    tracked.then(
      () => { this.#tracked.fulfilled++; this.#settleTracked(); },
      () => { this.#tracked.rejected++; this.#settleTracked(); }
    );
    return tracked;
  }

  #settleMain(outcome: TerminalOutcome): void {
    if (this.#mainSettled) return;
    this.#mainSettled = true;
    this.#mainOutcome = outcome;
    this.#state = "draining";
    this.#maybeTerminal();
  }

  #settleTracked(): void {
    this.#tracked.pending--;
    this.#maybeTerminal();
  }

  #maybeTerminal(): void {
    if (this.#state === "terminal" || !this.#mainSettled || this.#tracked.pending > 0) return;
    this.#state = "terminal";
    const terminal: ExecutionTerminal = {
      execution_id: this.id,
      request_id: this.requestId,
      session_id: this.sessionId,
      capability_id: this.capabilityId,
      outcome: this.#mainOutcome,
      cancellation_requested: this.#cancellation !== undefined,
      cancellation_acknowledged: this.#acknowledged,
      listener_errors: this.#listenerErrors,
      tracked_registered: this.#tracked.registered,
      tracked_fulfilled: this.#tracked.fulfilled,
      tracked_rejected: this.#tracked.rejected,
    };
    this.#terminal = terminal;
    this.#listeners.clear();
    try {
      const { request_id: _request_id, ...metadata } = terminal;
      this.deps.audit.record(this.requestId, "execution_terminal", metadata);
    } catch {
      // The terminal state is recorded in the execution regardless.
    }
    this.deps.onTerminal(terminal);
    this.#resolveTerminal({ ...terminal });
  }
}
