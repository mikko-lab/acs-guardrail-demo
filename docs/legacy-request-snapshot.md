# Legacy mode: the verified request is the request that runs

**Status:** fix for legacy mode, the default executor without `{ lifecycle: "permit" }`. It is present since `a9deab6` and on `main` up to `855a9b9`.

## The defect

In legacy mode `process()` validated, verified and executed the caller's own request object. Signature, replay and capability checks read that object. Callbacks run after those checks:
- the capability provider;
- the audit sink (`capability_verified`, `guardian_decision`);
- the Guardian, which is handed the request object itself.

Any of them could rewrite the object if it held a reference to it. Holding a reference is enough: the caller keeps one, and a callback may share it. The executor then went on with the rewritten values, which had never been verified:

| Rewritten after the checks | Guardian ALLOW path (`read_record`) | Guardian ASK path (`update_record`), then `resolveApproval()` |
|---|---|---|
| tool | `read_record` → `update_record`: the request becomes pending for a tool the signer never asked for. `update_record` → `read_record` runs `read_record` directly, without approval. | The pending action and the approval context name the rewritten tool. |
| arguments | The tool runs with unsigned arguments. | The pending action holds the rewritten arguments. Its signature check at approval fails after the human approved, so the signed request never runs. |
| session | The execution runs under, and is recorded for, another session. | The pending action is stored under another session. An approval for the signed request finds nothing. |
| request id | The execution, its audit records and its correlation use an unsigned request id. | The pending action is stored under another request id. An approval for the signed request finds nothing. |

Reproduction: `tests/legacy-request-snapshot.test.ts`.
- At `855a9b9`, 24 of its 28 tests fail.
- The 4 that pass are controls: a rewrite after `process()` returned is already harmless, because the pending action was a copy.

## The fix

`process()` takes one JSON copy of the request at entry and deep-freezes it, before schema validation, in legacy mode as in permit mode (`ownedRequestSnapshot`, docs/approval-permit-lifecycle.md §3.2). From then on, only that copy is read or run:
- signature, replay and capability checks;
- the Guardian decision;
- the audit records;
- the pending action;
- the execution permit;
- the tool call.

The caller's object is never read again.

- **A rewrite of the caller's object has no effect.** The tool, its arguments, the session and the request id that run are those that were verified.
- **The Guardian is handed the frozen copy.** A write attempt throws (`TypeError` in strict code), and `process()` is rejected before anything runs or is pending.
- **The pending action holds the same frozen copy.** `resolveApproval()` verifies the human grant against the request that was verified and approved, and it runs exactly that request. It still re-verifies the signature and re-checks the authority (approval fence), as before.

## Behaviour changes

- A request that is not a JSON value (a cycle, a `BigInt`) is rejected at entry with `Validation Error: request must be a JSON value`. Such a request could not be signed or schema-validated before either.
- A callback that writes to the request it is handed now makes `process()` fail. Before, the write silently changed the operation.
- The argument values a tool receives in legacy mode are the frozen snapshot's. The top-level arguments object is a fresh copy, as before. A tool that writes into a nested argument value throws and ends as a tool failure (`tool_execution_failed`).
- Nothing else changes in legacy mode: the decisions, audit events, receipts and results for unmodified requests stay the same.

## Evidence

`tests/legacy-request-snapshot.test.ts`. Tool calls are observed through the tool doubles' own counters and arguments, never through the audit.
- **LS1 (Guardian ALLOW):**
  - **Rewrite of the caller's object** (in the capability provider or the `capability_verified` audit sink), for each of tool, arguments, session and request id: `read_record` runs exactly once, with the signed arguments, session and request id.
  - **Guardian rewrite:** `process()` is rejected and nothing runs.
- **LS2 (Guardian ASK, then `resolveApproval()`):**
  - **Rewrite of the caller's object**, at the same sites and for the same fields: the signed `update_record` is pending under its signed session and request id. Approving it runs it exactly once, with the signed arguments.
  - **Guardian rewrite:** `process()` is rejected, nothing is pending, and an approval finds nothing.
  - **Controls:** a rewrite after `process()` returned pending changes nothing (already so at `855a9b9`).
