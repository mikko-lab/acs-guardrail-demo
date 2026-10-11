# Runtime-test mutant gate

One gate, `scripts/mutants/run-mutant-gate.mjs`, checks the runtime-test mutants of every package against its own manifest. It implements the rules of §7.8 of the approved [coverage expansion plan](https://github.com/mikko-lab/agent-control-evals/blob/main/docs/revocation/coverage-expansion-plan.md) of `agent-control-evals`.

| Package | Manifest | Command | Mutants |
|---|---|---|---|
| Tenant scope (1a) | [`mutants/tenant/manifest.json`](../mutants/tenant/manifest.json) | `npm run mutants:tenant` | [tenant-scope.md](tenant-scope.md#mutant-gate) |
| Ancestor chains (1b) | [`mutants/ancestor/manifest.json`](../mutants/ancestor/manifest.json) | `npm run mutants:ancestor` | [ancestor-chains.md](ancestor-chains.md#mutant-gate) |
| Approval–permit lifecycle (G3/G4) | [`mutants/lifecycle/manifest.json`](../mutants/lifecycle/manifest.json) | `npm run mutants:lifecycle` | [approval-permit-lifecycle.md](approval-permit-lifecycle.md#mutant-gate) |

```
node scripts/mutants/run-mutant-gate.mjs --manifest <manifest.json> [--out <dir>] [--only <mutant id>]
```

The report is written to `out/mutants-<package>/report.json` unless `--out` names another directory.

## Manifest

Every mutant is named in a manifest before any run. The manifest's SHA-256 is fixed in the `.sha256` file next to it and is checked first. For each mutant the manifest gives:
- its patch, bound by SHA-256;
- its evidence kind;
- its witness tests (file, describe and title);
- for every witness label, the exact value the unmodified runtime and the mutant must produce;
- the exact errors each witness may catch in each run;
- the kept safeguards that could also reject the witness input, and why the witness still separates control from mutant.

A witness may also have `role: "control"`. Its labels keep their values under the mutant (control value = mutant value). The ancestor manifest uses one for the valid-chain control, so every ancestor mutant must leave a valid chain working.

The manifest also lists the package's recorded coverage gaps, which the report repeats.

**Witness log.** `tests/witness.ts` logs every witness check (label, actual, expected, with undefined encoded as `{"$undefined":true}`) and every error a witness caught through `outcome()` to the file named by `WITNESS_LOG`. It logs whether or not the check passed. The gate compares these observations with the manifest, so a label alone is never enough.

## Rules

**Control.** The unpatched tree must pass all of the following:
- `npm run typecheck` and `npm run build` (`tsc --outDir dist`; `dist/src/guarded-executor.js` must exist);
- jest exiting 0, with no signal and no timeout, every test passing;
- every witness logging exactly its manifest control values and exactly its accepted control errors.

**Technical soundness of a mutant.** All of the following must hold:
- the patch applies;
- typecheck and build pass;
- jest exits 0 or 1, with no signal and no timeout, and writes its JSON result (jest runs as the gate's direct child process, without `npx` or a shell in between, so a timeout or a signal reaches jest itself and is reported as such; an exit status above 128 is reported as the signal it encodes);
- no suite execution error;
- the **test inventory is identical to the control's**: the same number of tests and the same test ids (file, describe path and title).

**Detection.** All of the following must hold:
- jest exits 1;
- every named witness fails with `WitnessAssertionError`;
- every label logs exactly its manifest mutant value;
- the failed labels are exactly those whose mutant value differs from the control value;
- the errors the witness caught are exactly the accepted mutant errors;
- every `control` witness still passes, with exactly its values and accepted errors.

**Whole run (strict manifests).** A manifest with `"whole_run": "strict"` (the lifecycle manifest) adds a whole-run rule. Every test that is not a named witness must pass and must log exactly the witness-log entries (check values and caught errors) it logs in the control run. The only exception is the mutant's `collateral` list, which pins such tests by test id with their exact status. A pinned observation must occur exactly as pinned. Anything else is an unexpected failure and a technical failure (exit 2), whatever the witnesses show: a witness's failure never redeems an otherwise unexpected run. Manifests without `whole_run` (tenant, ancestor and their regressions) keep the earlier rule, under which failures of tests that are not witnesses are diagnostics.

**Unexpected failures.** A label value that is neither the control nor the mutant value, or a caught error the manifest does not accept, is an unexpected failure. It is reported with its details (value, error name and message) as a technical failure and is never check-point evidence. A `control` witness that changes under the mutant is a technical failure too: the mutant breaks more than its named safeguard.

**Never a detection; these are technical failures (exit 2):**
- a patch that does not apply;
- a typecheck or build error;
- a load error;
- a changed test inventory;
- a jest exit status other than 0 or 1, a signal or a timeout;
- a failure that is not a `WitnessAssertionError`;
- an unexpected value or error;
- a `control` witness that changes under the mutant;
- a failing control;
- a crash of the gate itself (any exception inside the gate exits 2, never 1).

Exit status: 0 when every mutant is detected, 1 when a mutant is not detected, 2 on any technical failure.

**Evidence kinds:**
- **`check_point`:** a check label changes from its control value to its mutant value; the value is a stage, boundary, reason or call count.
- **`containment_effect`:** an effect label changes in runtime state: tool calls, managed state, returned content or the cancellation signal.
- **`both`:** both of the above in the same run.
- **`component_check_point`:** a component test's check label changes; this is never production-path evidence.
- **`lifecycle_effect`:** a lifecycle label changes: the approval or permit state, or the number of lineages, in runtime state (lineage snapshots).
- **`check_and_lifecycle`:** both a check label and a lifecycle label change in the same run.

Lifecycle state is runtime state but not a contained effect: the report lists it as `lifecycle_evidence` and never in `containment_evidence`. `check_point_evidence_production_path` lists `both`, `check_point` and `check_and_lifecycle`.

A changed rejection code alone is never containment. Safeguards that mask a check point are kept, and no safeguard is removed or weakened to give another check a containment witness. The report lists check-point and containment evidence separately.

Failures of tests that are not named witnesses are recorded in the report as diagnostics (`other_failures`) and never count.

## Gate regressions

`npm run mutants:tenant:regressions` (`scripts/mutants/gate-regressions.mjs`) runs the gate on four fixed, hash-checked manifests in `mutants/tenant/regressions/`. It requires each case's exit status and the reason the gate reports:

| Case | Input | Required gate result |
|---|---|---|
| R1-inventory | the M27e patch plus deletion of an unrelated test (628 → 627 tests) | technical failure, exit 2 (test inventory differs) |
| R2-syntax | an unexpected `SyntaxError` on the request path; the M27e witness stage becomes undefined | technical failure, exit 2 (unexpected value and unaccepted caught error) |
| R3-m27e | the real M27e mutant | detected at stage `start` (control `request`), exit 0 |
| R4-crash | a manifest whose patch path is a directory, so reading it throws inside the gate | internal error, exit 2 (a crash is never exit 1) |

## Lifecycle gate regressions

`npm run mutants:lifecycle:regressions` (`scripts/mutants/lifecycle-gate-regressions.mjs`) runs the gate on ten fixed, hash-checked manifests in `mutants/lifecycle/regressions/`, all under the strict whole-run rule:

| Case | Input | Required gate result |
|---|---|---|
| RL1-detected | the real M53 mutant | detected, exit 0 |
| RL2-inventory | M53 plus deletion of an unrelated test | technical failure, exit 2 (test inventory differs) |
| RL3-value | the L4c witness logs `permit_not_issued`, neither its control nor its mutant value | technical failure, exit 2 |
| RL4-error | M57 plus a changed `AuthorityRevokedError` message: the L2b witnesses catch an unaccepted error | technical failure, exit 2 |
| RL5-other-failure | M53 plus a failing assertion in an unrelated test | technical failure, exit 2 (unexpected failure outside the named witnesses) |
| RL6-crash | a patch path that is a directory | internal error, exit 2 |
| RL7-timeout | M53 plus a jest global teardown that never ends (gate run with `--jest-timeout-ms 240000`) | technical failure, exit 2 (jest timed out) |
| RL8-signal | M53 plus a jest configuration that kills its own process with SIGKILL | technical failure, exit 2 (killed by signal) |
| RL9-unchanged | a production-code change that changes no behaviour (a comment) | not detected, exit 1 |
| RL10-kinds | M67 (`check_and_lifecycle`) and M71 (`component_check_point`) | detected, exit 0; the report's `containment_evidence` is empty, `lifecycle_evidence` is `["M67"]` and `component_check_point` is `["M71"]` |

## Determinism

`npm run mutants:lifecycle:determinism` (`scripts/mutants/witness-determinism.mjs`) runs the lifecycle test files three times on the unmodified tree with the witness log and requires every run to pass with a witness log (every check value and caught error, per test) identical to the first run's.
