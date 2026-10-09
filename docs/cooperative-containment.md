# Cooperative containment (A2)

A2 builds on [authority revocation (A1)](authority-revocation.md). A1 decides whether an authority may still request, be approved, start and be delivered. A2 adds a contract through which a **cooperating** tool receives a cancellation signal, performs its controlled side effects through a runtime-mediated commit fence, and lets the runtime record when its managed work has ended.

The guarantees are limited to managed executions of one `GuardedExecutor` instance and to effects performed through the runtime's commit interface. Arbitrary tool code, effects performed outside `ctx.commit()`, and unregistered background work are not controlled; the runtime never claims to have stopped them.

## Separate concepts

| Concept | Meaning | Evidence |
|---|---|---|
| Revocation | A1's monotonic tombstone for a capability or session. It takes effect inside `revoke()` before any cancellation callback runs. | `authority_revoked`; `RevocationReceiptV1` |
| Cancellation request | A targeted `revoke()` asks every managed, not yet terminal execution bound to the revoked authority to stop. | `execution_cancellation_requested` |
| Cancellation acknowledgement | The tool states that it received the request. It does not mean the tool stopped. | `execution_cancellation_acknowledged` |
| Commit decision | The runtime decides whether one runtime-mediated effect may happen. | `tool_commit_requested`, then `tool_commit_applied` or `tool_commit_blocked` |
| Commit effect | The change of the runtime-managed state itself (`executor.managedState`). | The state, not the audit stream |
| Terminal | The runtime **observed** that the managed tool function and all of its registered work have settled. At most one per execution; none for an execution whose settlement is unobservable. | The execution record (`executor.getExecution()`, `executor.whenTerminal()`, `executor.terminals()`); `execution_terminal` when the audit sink records it |
| Unobservable settlement | The tool function returned a native Promise the runtime cannot observe. The call fails, but this is not evidence that the execution ended. | `state: "unobservable"` in the execution record; `tool_execution_completed` with `status: "error"`; no `execution_terminal` |
| Delivery | A1's binding check at the fulfilment of the public `process()` / `resolveApproval()` promise. Unchanged. | A1 delivery evidence |

## Execution identity

Every real tool invocation gets its own `execution_id` (`exec-<n>`, unique per executor instance), created at A1's start effective point, after the binding start check and immediately before the tool function is called. An execution is bound to the request's `request_id`, its `session_id` and the original `capability_id` the request (or the pending approval) was authorized under. A start that A1 denies creates no execution, so it never has a terminal. Two executions of the same request id (for example after `clearSession`) are two executions.

## Execution context

A tool function is called as `tool(args, ctx)`. Existing tools that ignore `ctx` keep working, but then nothing they do is controlled by A2.

```ts
interface ExecutionContext {
  readonly execution_id: string;
  readonly cancellation: CancellationSignal;
  acknowledgeCancellation(): boolean;
  commit(key: string, value: unknown): CommitReceipt;
  track<T>(work: Promise<T>): Promise<T>;
}
interface CancellationSignal {
  readonly requested: boolean;
  readonly reason: CancellationError | undefined;
  onCancel(listener: (reason: CancellationError) => void): () => void;
  throwIfRequested(): void;
}
```

The signal is the runtime's own type, not a DOM `AbortSignal`: listener exceptions are caught by the runtime one listener at a time instead of surfacing as uncaught process errors.

## Revocation and cancellation order

A targeted `revoke()`:

1. records the tombstone (A1); from here on every runtime check of the authority denies it;
2. records `authority_revoked` and builds the receipt (A1, unchanged shape);
3. for each managed execution bound to the authority that is not terminal and has no cancellation request yet (including an execution whose settlement is unobservable): marks the request, records `execution_cancellation_requested`, then calls that execution's listeners.

Each listener runs inside its own `try`/`catch`. A throwing listener is counted (`listener_errors` on the terminal) and the remaining listeners and executions are still processed. A listener may re-enter the runtime: a `ctx.commit()` from a listener is denied because the tombstone already exists; a repeated `revoke()` of the same target is an idempotent duplicate that does not signal again; a `revoke()` of another target cancels that target's executions. Nothing a listener does can undo the revocation. A listener registered after the request is called immediately (inside the same protection). A duplicate `revoke()` never signals an execution a second time.

## Commit fence

`ctx.commit(key, value)` applies one change to the runtime-managed state store. **Its effective point is the store write itself.** In order:

1. the execution must not be terminal and its settlement must not be unobservable;
2. the key is validated and the value is serialized to JSON (this may run caller code such as `toJSON`);
3. `tool_commit_requested` is recorded (this may run audit callbacks);
4. **binding check**: the execution is still neither terminal nor unobservable, and neither its session nor its capability is revoked;
5. the store write;
6. `tool_commit_applied` is recorded.

Nothing runs between the binding check (4) and the write (5), so a revocation from any callback in steps 1–3 is seen by the check. A denied commit throws `CommitRejectedError` (`reason`: `session_revoked`, `capability_revoked`, `execution_terminal`, `settlement_unobservable` or `audit_unavailable`; a closed execution reports `execution_terminal` or `settlement_unobservable` before any revocation), records `tool_commit_blocked`, and leaves the store unchanged. A commit that was applied before a revocation stays applied; it is a historical fact and is never rolled back.

**Audit failure.** If `tool_commit_requested` cannot be recorded, the commit fails closed (`audit_unavailable`) and nothing is written. If `tool_commit_blocked` cannot be recorded, the commit is still denied. If `tool_commit_applied` cannot be recorded, the write has already happened and is not undone.

The guarantee covers only this synchronous, runtime-managed state change. It does not extend to network requests, external transactions, file systems or any effect a tool performs without `ctx.commit()`. Being allowed to start (A1's permit) is not evidence of a commit; only the state change is.

## Registered work and terminal

`ctx.track(work)` registers a promise as part of the execution and returns the same promise. Registration is possible until the execution is terminal or its settlement is unobservable; afterwards `track()` throws.

**Observing settlement.** The runtime observes a native Promise (any object with the native Promise brand, including a Promise subclass) through its internal state, **without running any code of the object**. It calls the intrinsic `Promise.prototype.then`, captured at load, on the Promise: the reactions are registered on the Promise itself, so the object's own `then` is never called, the reactions run only when the Promise really settles, and the Promise's rejection counts as handled.

The intrinsic `then` also creates a derived Promise with the species of the Promise's `constructor`. A species constructor, an accessor `constructor` or a subclass constructor is code of the object: it can have side effects, settle Promises it holds, and reject the derived Promise. The runtime therefore makes the species resolve to the intrinsic Promise before calling `then`:

1. It reads the `constructor` the intrinsic `then` would see from property descriptors only (no getter runs, Proxies are not traversed). If it is the intrinsic `Promise`, or there is none, the call proceeds as is.
2. Otherwise it defines an own `constructor` data property equal to `Promise` for the duration of the call and restores the original state (the original own descriptor, or no own property) immediately afterwards. No code of the object runs in between.

The derived Promise is then an intrinsic Promise that fulfils with the runtime reaction's result; the reactions do not throw, so it never rejects. When neither step is possible (a non-extensible Promise, or a non-configurable own `constructor`, whose `constructor` is not the intrinsic `Promise`), or when `Promise[Symbol.species]` itself has been modified, the Promise is **unobservable**: nothing is registered and no code of the object runs.

- `track(work)` accepts a native Promise and returns the same Promise. It counts the work only after the runtime's reactions are registered. A non-Promise (including a non-native thenable) or an unobservable Promise is refused with `TypeError` and nothing is registered, so a refused registration leaves no pending entry behind.
- The tool function's return value is observed the same way when it is a native Promise; its own `then` is ignored and its rejection is handled by the runtime (the outcome is `failed`, or `cancelled` per the rule below). An unobservable returned Promise is handled as described under [Unobservable settlement](#unobservable-settlement). A synchronous value counts as settled at once.
- A non-native thenable returned by the tool function is the trust boundary: its settlement is whatever it reports. The runtime cannot compare that report with work the tool hides behind it, exactly as for detached work.

The runtime does not defend against modification of the JavaScript environment itself (for example replacing `Promise.prototype.then` before the runtime module loads, or `Promise.prototype.constructor`).

The execution is **terminal** when the runtime has observed that the tool function's promise has settled **and** every registered promise has settled. The runtime then marks the execution terminal, appends the terminal record to the executor's terminal log, attempts to record one `execution_terminal` audit event and resolves `executor.whenTerminal(execution_id)`; it never does any of this a second time. The terminal's `outcome` describes how the tool function itself ended:

| Outcome | Rule |
|---|---|
| `completed` | The tool function fulfilled. This includes a tool that ignored or merely acknowledged a cancellation request and finished anyway (`cancellation_requested: true`). |
| `cancelled` | A cancellation was requested for this execution, and the tool function rejected with **this execution's** `CancellationError` (from `ctx.cancellation.throwIfRequested()` or `ctx.cancellation.reason`). |
| `failed` | The tool function threw or rejected with anything else, including another execution's `CancellationError`. |

A cancellation request alone never makes an outcome `cancelled`. Registered-work results are reported separately (`tracked_registered`, `tracked_fulfilled`, `tracked_rejected`) and do not change the outcome. The terminal also reports `cancellation_requested`, `cancellation_acknowledged`, `listener_errors` and `audit_recorded`.

**Terminal and audit failure.** The terminal is the execution's own state; it never depends on the audit sink, and the local record (`getExecution()`, `whenTerminal()`, `terminals()`) is authoritative. `audit_recorded: true` means the `execution_terminal` record call returned normally. `audit_recorded: false` means that call threw: the recording is unconfirmed. The event may be absent (a sink that fails before writing) or present (a sink that writes and then throws); whether it is in the stream can only be established by reading the stream. The record is not retried.

Terminal is independent of delivery: `process()` / `resolveApproval()` return when the result has been processed, which may be before registered work has settled; the terminal is recorded later. The existing `tool_execution_completed` event still means only that the tool function settled; it is not a terminal. For a tool without registered work the terminal is observed when the tool function's promise settles, so `execution_terminal` precedes `tool_execution_completed` in the audit stream.

### Unobservable settlement

When the tool function returns a native Promise whose settlement is unobservable (see above), the runtime separates the failure of its own observation from evidence about the execution:

- **The call fails.** `invoke()` rejects with `TypeError` ("Tool returned a native Promise whose settlement cannot be observed", the observation error as `cause`); the request ends as any failed tool call (`tool_execution_completed` with `status: "error"`, `tool_execution_blocked`, a failure result). No code of the Promise object runs.
- **No terminal.** The Promise may still be pending, so its work may still be running. The execution's state becomes `unobservable`; the runtime records no terminal, appends nothing to `terminals()`, records no `execution_terminal`, and `whenTerminal()` never resolves. This holds also when the Promise settles later or was already settled: the runtime cannot observe either, and an unobserved settlement is not terminal evidence. An outcome `failed` is therefore never reported for this case.
- **Commit fence and registration close.** From then on `ctx.commit()` is denied with `settlement_unobservable` (recorded as `tool_commit_blocked`) and `ctx.track()` throws. Commits applied earlier stay applied.
- **Still a cancellation target.** The execution is not terminal, so a later `revoke()` that covers it requests cancellation as for a running execution (`execution_cancellation_requested`, listeners called once, `ctx.acknowledgeCancellation()` available). The cancellation request is not a terminal either.

The runtime cannot mark such a Promise's own rejection handled; if it later rejects, the unhandled rejection belongs to the tool, as for any Promise a tool leaves unhandled, and the integrator decides how the process treats it.

**Detached work.** Work a tool starts without `ctx.track()` is invisible to the runtime. A terminal does not prove that such work has ended. Its runtime-mediated commits after the terminal are denied (`execution_terminal`); its other effects are not controlled.

## Delivery

A1's delivery fence is unchanged and remains binding. A cancelled or still-running execution's result is withheld if its authority is revoked before the public promise is fulfilled.

## Inspection

- `executor.managedState`: read-only view of the managed state store (`get`, `has`, `keys`, `version`); values are returned as copies.
- `executor.getExecution(execution_id)`: snapshot with identity bindings, `state` (`running`, `draining` when only registered work remains, `unobservable` when the tool function's settlement cannot be observed, `terminal`), cancellation flags and the terminal record (only when terminal).
- `executor.whenTerminal(execution_id)`: resolves with the terminal record (including `audit_recorded`); never resolves for an execution whose settlement is unobservable.
- `executor.terminals()`: every terminal record of the executor, in the order the executions became terminal (copies).

## Audit events

| Event | Metadata |
|---|---|
| `execution_cancellation_requested` | `execution_id`, `session_id`, `capability_id`, `revocation_id`, `listeners` |
| `execution_cancellation_acknowledged` | `execution_id`, `session_id`, `capability_id` |
| `tool_commit_requested` | `execution_id`, `session_id`, `capability_id`, `key` |
| `tool_commit_applied` | `execution_id`, `session_id`, `capability_id`, `key`, `commit_id`, `sequence` |
| `tool_commit_blocked` | `execution_id`, `session_id`, `capability_id`, `key`, `decision: "deny"`, `reason` (`session_revoked`, `capability_revoked`, `execution_terminal`, `settlement_unobservable`, `audit_unavailable`), `revocation_id` when revoked |
| `execution_terminal` | `execution_id`, `session_id`, `capability_id`, `outcome`, `cancellation_requested`, `cancellation_acknowledged`, `listener_errors`, `tracked_registered`, `tracked_fulfilled`, `tracked_rejected` |

All are recorded with the execution's `request_id`. The runtime attempts `execution_terminal` for every managed execution that becomes terminal, including executions of tools that ignore `ctx`; an execution whose settlement is unobservable has none; the normal ALLOW and approval audit sequences therefore contain one more event than before A2. A failed `execution_terminal` record call is reported by the local terminal's `audit_recorded: false` (unconfirmed, not necessarily absent); `audit_recorded` itself is not part of the audit metadata. Commit values are never written to the audit log. The audit stream is the runtime's own report: tests observe commits through the managed state and tool behaviour through harness-owned doubles. All six events export to OCSF as generic Base Events and are not incidents.

## State and limits

Execution records, the managed state and cancellation state live in the memory of one executor instance; they are not persistent, distributed or shared, and are lost on restart. Not provided: stopping non-cooperating code, fencing effects outside `ctx.commit()`, asynchronous or external commit targets, observing work behind non-native thenables or behind an unobservable native Promise (non-extensible or with a non-configurable `constructor` that is not `Promise`), a terminal for an execution that returned such a Promise, handling that Promise's rejection, protection against modification of the JavaScript environment, a DOM `AbortSignal`, tenant, agent or ancestor scopes, a network endpoint or UI, and conformance to the `agent-control-evals` revocation-0.3.0 contract.
