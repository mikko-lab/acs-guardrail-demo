/**
 * src/managed-execution.ts
 *
 * Cooperative containment for one managed tool execution (see docs/cooperative-containment.md).
 *
 * A managed execution gives its tool an ExecutionContext: a cancellation signal, a runtime-mediated commit
 * fence over the runtime-managed state store, and registration of background work. The runtime records one
 * terminal when the tool function and all registered work have settled. An execution whose returned Promise
 * cannot be observed has no terminal: the call fails and the commit fence closes, but it stays a cancellation target.
 *
 * Only cooperating code and effects performed through ctx.commit() are controlled. Arbitrary tool code,
 * effects outside ctx.commit() and unregistered background work are not.
 */
import { types } from "node:util";
import type { AuditCollector } from "./audit";

// Captured at load: the runtime does not defend against later modification of the JavaScript environment itself.
const NativePromise = Promise;
const nativeThen = Promise.prototype.then;
const intrinsicSpeciesGetter = Object.getOwnPropertyDescriptor(Promise, Symbol.species)?.get;
const { defineProperty, getOwnPropertyDescriptor, getPrototypeOf, isExtensible } = Object;
const deleteProperty = Reflect.deleteProperty;

type Settlement = { ok: true; value: unknown } | { ok: false; error: unknown };

/** Whether the `constructor` the intrinsic `then` would read resolves to the intrinsic Promise. Reads descriptors only. */
function constructorIsIntrinsic(promise: Promise<unknown>): boolean {
  for (let o: object | null = promise; o !== null; o = getPrototypeOf(o)) {
    if (types.isProxy(o)) return false;
    const own = getOwnPropertyDescriptor(o, "constructor");
    if (own) return "value" in own && own.value === NativePromise;
  }
  return true; // No constructor at all: the intrinsic `then` uses the intrinsic Promise.
}

/**
 * Observes a native Promise (including subclasses) through its internal state without running any code of the
 * object. The intrinsic Promise.prototype.then registers the reactions on the Promise itself, so the object's own
 * `then` is never called, the reactions run only when the Promise really settles, and its rejection counts as
 * handled. The intrinsic `then` also creates a derived Promise with the species of `constructor`; to keep that
 * from running the object's code (an accessor, a subclass or custom species constructor, which could also reject
 * the derived Promise), the species must resolve to the intrinsic Promise. If the object's own `constructor` chain
 * does not, an own `constructor` data property equal to Promise is defined for the duration of the call and the
 * original state is restored right after; no code of the object runs in between. The derived Promise is then an
 * intrinsic Promise that fulfils with the reaction's result and never rejects (the reactions do not throw).
 *
 * Throws TypeError, registering nothing, when this is impossible: a non-extensible Promise or a non-configurable
 * own `constructor` whose chain does not resolve to Promise, or a modified Promise[Symbol.species].
 */
function observeNative(promise: Promise<unknown>, onSettled: (s: Settlement) => void): void {
  if (getOwnPropertyDescriptor(NativePromise, Symbol.species)?.get !== intrinsicSpeciesGetter) {
    throw new TypeError("Promise[Symbol.species] has been modified; settlement cannot be observed");
  }
  const onFulfilled = (value: unknown) => onSettled({ ok: true, value });
  const onRejected = (error: unknown) => onSettled({ ok: false, error });
  if (constructorIsIntrinsic(promise)) {
    nativeThen.call(promise, onFulfilled, onRejected);
    return;
  }
  const own = getOwnPropertyDescriptor(promise, "constructor");
  if (own ? !own.configurable : !isExtensible(promise)) {
    throw new TypeError("The Promise's constructor cannot be pinned; settlement cannot be observed without running its code");
  }
  defineProperty(promise, "constructor", { value: NativePromise, writable: true, enumerable: false, configurable: true });
  try {
    nativeThen.call(promise, onFulfilled, onRejected);
  } finally {
    if (own) defineProperty(promise, "constructor", own);
    else deleteProperty(promise, "constructor");
  }
}

export class CancellationError extends Error {
  readonly code = "EXECUTION_CANCELLED";
  constructor(readonly execution_id: string, readonly revocation_id: string) {
    super(`Execution ${execution_id} cancelled: authority revoked (${revocation_id})`);
    this.name = "CancellationError";
  }
}

export type CommitBlockReason =
  | "session_revoked"
  | "capability_revoked"
  | "execution_terminal"
  | "settlement_unobservable"
  | "audit_unavailable";

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
  /**
   * Registers work that must settle before the execution is terminal. Accepts only a native Promise whose
   * settlement the runtime can observe (otherwise TypeError, nothing registered) and returns the same Promise.
   * Throws once the execution is terminal or its settlement is unobservable.
   */
  track<T>(work: Promise<T>): Promise<T>;
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
  /**
   * Whether the execution_terminal record call returned normally. false means unconfirmed: the event may be absent or,
   * with a sink that writes and then throws, present. The terminal itself does not depend on it.
   */
  audit_recorded: boolean;
}

/**
 * running: the tool function has not settled. draining: it settled, registered work remains. unobservable: the tool
 * function returned a native Promise whose settlement cannot be observed; the call failed, commits and registration
 * are closed, no terminal is ever recorded, and the execution stays a cancellation target. terminal: settled.
 */
export type ExecutionState = "running" | "draining" | "unobservable" | "terminal";

export interface ExecutionSnapshot {
  execution_id: string;
  request_id: string;
  session_id: string;
  capability_id: string;
  state: ExecutionState;
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
  #state: ExecutionState = "running";
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
      track: <T>(work: Promise<T>) => this.#track(work),
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

  /**
   * Calls the tool function with this execution's context and observes its settlement. The returned promise is
   * runtime-owned and settles only after the execution has recorded how the tool function ended.
   */
  invoke(toolFn: ToolFn, args: Record<string, unknown>): Promise<unknown> {
    return this.#run(toolFn, args);
  }

  async #run(toolFn: ToolFn, args: Record<string, unknown>): Promise<unknown> {
    let returned: unknown;
    try {
      returned = toolFn(args, this.context);
    } catch (e) {
      this.#settleMain(this.#outcomeOf(e));
      throw e;
    }
    if (!types.isPromise(returned)) {
      // A synchronous value is settled at once; a non-native thenable reports its own settlement (trust boundary).
      try {
        const value = await returned;
        this.#settleMain("completed");
        return value;
      } catch (e) {
        this.#settleMain(this.#outcomeOf(e));
        throw e;
      }
    }
    let settlement: Settlement;
    try {
      settlement = await new Promise<Settlement>(resolve => observeNative(returned as Promise<unknown>, resolve));
    } catch (e) {
      // The Promise cannot be observed without running its code: the call fails, but the work behind it may still be
      // pending, so this is not evidence that the execution ended. No terminal; the execution stays cancellable.
      this.#markUnobservable();
      throw new TypeError("Tool returned a native Promise whose settlement cannot be observed", { cause: e });
    }
    if (settlement.ok) {
      this.#settleMain("completed");
      return settlement.value;
    }
    this.#settleMain(this.#outcomeOf(settlement.error));
    throw settlement.error;
  }

  #outcomeOf(error: unknown): TerminalOutcome {
    return error === this.#cancellation && error !== undefined ? "cancelled" : "failed";
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

  /** The fence reason for an execution that may no longer commit, apart from revocation. */
  #closedReason(): CommitBlockReason | undefined {
    if (this.#state === "terminal") return "execution_terminal";
    if (this.#state === "unobservable") return "settlement_unobservable";
    return undefined;
  }

  #commit(key: string, value: unknown): CommitReceipt {
    const closed = this.#closedReason();
    if (closed) this.#blocked(String(key), closed);
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

    // Binding check: nothing runs between this check and the write. (Re-read: the callbacks above may have
    // changed the state.)
    const closedNow = this.#closedReason();
    if (closedNow) this.#blocked(key, closedNow);
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

  #track<T>(work: Promise<T>): Promise<T> {
    if (this.#state === "terminal") throw new Error(`Execution ${this.id} is terminal; work can no longer be registered`);
    if (this.#state === "unobservable") throw new Error(`Execution ${this.id} has an unobservable settlement; work can no longer be registered`);
    if (!types.isPromise(work)) throw new TypeError("track() requires a native Promise");
    // Counted only after the reactions are registered; the reactions cannot run before this method returns.
    try {
      observeNative(work, settlement => {
        if (settlement.ok) this.#tracked.fulfilled++;
        else this.#tracked.rejected++;
        this.#settleTracked();
      });
    } catch (e) {
      throw new TypeError("track() requires a native Promise whose settlement can be observed", { cause: e });
    }
    this.#tracked.registered++;
    this.#tracked.pending++;
    return work;
  }

  #settleMain(outcome: TerminalOutcome): void {
    if (this.#mainSettled) return;
    this.#mainSettled = true;
    this.#mainOutcome = outcome;
    this.#state = "draining";
    this.#maybeTerminal();
  }

  /** The tool function's settlement cannot be observed. Never terminal: #mainSettled stays false. */
  #markUnobservable(): void {
    this.#state = "unobservable";
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
      audit_recorded: false,
    };
    this.#terminal = terminal;
    this.#listeners.clear();
    try {
      const { request_id: _request_id, audit_recorded: _audit_recorded, ...metadata } = terminal;
      this.deps.audit.record(this.requestId, "execution_terminal", metadata);
      terminal.audit_recorded = true;
    } catch {
      // The terminal is recorded in the execution and the executor's terminal log regardless.
    }
    this.deps.onTerminal(terminal);
    this.#resolveTerminal({ ...terminal });
  }
}
