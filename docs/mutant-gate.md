# Runtime-test mutant gate

One gate, `scripts/mutants/run-mutant-gate.mjs`, checks the runtime-test mutants of every package against its own manifest. It implements the rules of §7.8 of the approved [coverage expansion plan](https://github.com/mikko-lab/agent-control-evals/blob/main/docs/revocation/coverage-expansion-plan.md) of `agent-control-evals`.

| Package | Manifest | Command | Mutants |
|---|---|---|---|
| Tenant scope (1a) | [`mutants/tenant/manifest.json`](../mutants/tenant/manifest.json) | `npm run mutants:tenant` | [tenant-scope.md](tenant-scope.md#mutant-gate) |
| Ancestor chains (1b) | [`mutants/ancestor/manifest.json`](../mutants/ancestor/manifest.json) | `npm run mutants:ancestor` | [ancestor-chains.md](ancestor-chains.md#mutant-gate) |
| Approval–permit lifecycle (G3/G4) | [`mutants/lifecycle/manifest.json`](../mutants/lifecycle/manifest.json) | `npm run mutants:lifecycle` | [approval-permit-lifecycle.md](approval-permit-lifecycle.md#8-mutant-gate) |

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

**Witness log.** `tests/witness.ts` logs every witness check (label, actual, expected, with undefined encoded as `{"$undefined":true}`) and every error a test caught through its outcome helpers (`outcome()`, `settle()`, `attempt()`) to the file named by `WITNESS_LOG`. It logs whether or not the check passed. The gate compares these observations with the manifest, so a label alone is never enough.

**Binding.** Every entry names its test file and the test it was written in. The helper binds an entry to a test only between its own `beforeEach` and `afterEach` hooks. An entry written outside them, for example in a `beforeAll`, has no test. The gate binds every entry to exactly one test of the inventory, by file and test name, and does not ignore an entry it cannot bind. Each of the following is a technical failure (exit 2), in the control and in every mutant run, under every manifest:
- an entry written outside any test;
- an entry whose file and test name match no test;
- two tests of one file with the same name, since an entry could then not be bound to one test.

Tests of different files may share a name; their entries stay apart.

## Rules

**Control.** The unpatched tree must pass all of the following:
- `npm run typecheck` and `npm run build` (`tsc --outDir dist`; `dist/src/guarded-executor.js` must exist);
- jest exiting 0, with no signal and no timeout, every test passing;
- every witness-log entry bound to one test (see Binding);
- every witness logging exactly its manifest labels, each once, with the manifest control value as the test's own expectation, exactly its control values and exactly its accepted control errors.

**`--only`.** `--only <id>` must name a mutant of the manifest. An unknown id is rejected before any run (exit 2), and a run of no mutant is never a success.

**Technical soundness of a mutant.** All of the following must hold:
- the patch applies and takes effect:
  - `git apply` runs as if outside any repository (`GIT_CEILING_DIRECTORIES` above the copy, `GIT_DIR` and `GIT_WORK_TREE` cleared), so a work directory inside a git work tree, for example a `TMPDIR` there, cannot make it skip paths and still exit 0;
  - every file the patch names must change;
  - the reverse patch must apply to the result;
- every witness-log entry is bound to one test;
- typecheck and build pass;
- jest exits 0 or 1, with no signal and no timeout, and writes its JSON result (jest runs as the gate's direct child process, without `npx` or a shell in between, so a timeout or a signal reaches jest itself and is reported as such; an exit status above 128 is reported as the signal it encodes);
- no suite execution error;
- the **test inventory is identical to the control's**: the same number of tests and the same test ids (file, describe path and title).

**Detection.** All of the following must hold:
- jest exits 1;
- every named witness fails with exactly one failure: the `WitnessAssertionError` that its `witness()` call throws for exactly the logged checks that failed. The gate rebuilds that message from the witness log and compares it with jest's failure message (normalised as for collateral, below). Any other or additional failure of the same test, for example an `afterEach` hook's error after the assertion, is a technical failure, never hidden behind the expected assertion. A witness that passes although a logged check failed is a technical failure too;
- every named witness logs exactly its manifest labels, each once, with the manifest control value as the test's own expectation;
- every label logs exactly its manifest mutant value;
- the failed labels are exactly those whose mutant value differs from the control value;
- the errors the witness caught are exactly the accepted mutant errors;
- a witness that logs exactly its control values (the mutant changed nothing it observes) must catch exactly its accepted control errors, and the mutant is then not detected (exit 1);
- every `control` witness still passes, with exactly its labels, values and accepted errors.

**Whole run (strict manifests).** A manifest with `"whole_run": "strict"` (the lifecycle manifest) adds a whole-run rule. Every test that is not a named witness must pass and must log exactly the witness-log entries (check values and caught errors) it logs in the control run. The only exception is the mutant's `collateral` list. It pins each such test by test id with:
- its exact status;
- its exact witness-log observations (check values and caught errors);
- when it fails, its exact assertion failure: jest's failure messages with only colour codes and V8 stack-trace frame lines (`at fn (file:line:col)` and the like) removed, since frames name the gate's temporary work directory. The error class, the message and the whole assertion content stay in the comparison; a message line that only starts with "at" is kept.

A collateral test that fails differently (another assertion, a `SyntaxError`, a crash) is unexpected. Under the strict rule every caught error, of witnesses and collateral alike, is compared with its accepted text exactly (`Name: message`). No prefix is accepted, no suffix is ignored, and no field is normalised. Anything else is an unexpected failure and a technical failure (exit 2), whatever the witnesses show: a witness's failure never redeems an otherwise unexpected run. A missing witness log, in the control or the mutant run, is a technical failure too. Under every manifest, a named witness that logs no observation at all is a technical failure. Manifests without `whole_run` (tenant, ancestor and their regressions) keep the earlier rule, under which failures of tests that are not witnesses are diagnostics. **Gate debt:** the tenant and ancestor manifests have not been moved to the strict rule. Two consequences follow:
- their passing runs do not show that the rest of the suite stayed unaffected under their mutants;
- their accepted errors are still compared by prefix.

Their green results are not evidence for the strict rule.

**Unexpected failures.** A label value that is neither the control nor the mutant value, or a caught error the manifest does not accept, is an unexpected failure. It is reported with its details (value, error name and message) as a technical failure and is never check-point evidence. A `control` witness that changes under the mutant is a technical failure too: the mutant breaks more than its named safeguard.

**Never a detection; these are technical failures (exit 2):**
- an unknown `--only` id, or a run of no mutant;
- a patch that does not apply or does not take effect;
- a witness-log entry that cannot be bound to exactly one test;
- a named witness that fails with more or other than its exact `WitnessAssertionError`, logs a label the manifest does not name, or logs a named label other than once;
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
- **`availability_effect`:** an availability label changes: an allowed action is denied or not executed (a follow-up start denied, fewer tool calls).
- **`check_and_availability`:** both a check label and an availability label change in the same run.

Lifecycle state is runtime state but not a contained effect: the report lists it as `lifecycle_evidence` and never in `containment_evidence`. An availability effect is the opposite of containment (something allowed did not happen): the report lists it as `availability_evidence`, never in `containment_evidence`. `check_point_evidence_production_path` lists `both`, `check_point`, `check_and_lifecycle` and `check_and_availability`.

**Beyond the claimed kind.** The kind is the evidence claimed for the mutant. For every entry the report lists the parts whose labels change (`changed_parts`). Any part outside the claimed kind goes to `beyond_kind_parts` and to the summary's `observed_beyond_kind`, with the manifest's note where it gives one. It is never counted in the evidence lists.

**Counts and variants.** A variant (`variant_of`) has its main entry's patch, so its run is identical to the main entry's, and it reads another witness of that run. It is not an independent failure mechanism. The report's `counts` give, separately:
- manifest entries;
- distinct patches;
- mechanisms (entries that are not variants);
- variants;
- named witness tests;
- control witness tests.

**Claim limits.** Where an entry's claim is narrower than its kind suggests, the manifest says so in `claim_limits` and the report repeats it. Examples: M58 shows snapshot continuity only, and lifecycle-only entries infer, not show, that a later fence still denies.

A changed rejection code alone is never containment. Safeguards that mask a check point are kept, and no safeguard is removed or weakened to give another check a containment witness. The report lists check-point and containment evidence separately.

The report lists the failed tests that are not named witnesses (`other_failures`). Under a manifest without the strict whole-run rule they are diagnostics and never count. Under the strict rule each one must be pinned collateral, otherwise the run is a technical failure (see Whole run).

## Gate regressions

`npm run mutants:tenant:regressions` (`scripts/mutants/gate-regressions.mjs`) runs the gate on four fixed, hash-checked manifests in `mutants/tenant/regressions/`. It requires each case's exit status and the reason the gate reports:

| Case | Input | Required gate result |
|---|---|---|
| R1-inventory | the M27e patch plus deletion of an unrelated test (628 → 627 tests) | technical failure, exit 2 (test inventory differs) |
| R2-syntax | an unexpected `SyntaxError` on the request path; the M27e witness stage becomes undefined | technical failure, exit 2 (unexpected value and unaccepted caught error) |
| R3-m27e | the real M27e mutant | detected at stage `start` (control `request`), exit 0 |
| R4-crash | a manifest whose patch path is a directory, so reading it throws inside the gate | internal error, exit 2 (a crash is never exit 1) |

## Lifecycle gate regressions

`npm run mutants:lifecycle:regressions` (`scripts/mutants/lifecycle-gate-regressions.mjs`) runs the gate on twenty-four fixed, hash-checked manifests in `mutants/lifecycle/regressions/`, all under the strict whole-run rule. Case ids on the command line run only those cases. Two cases (RL20, RL21) run the gate from a scratch copy of the tree with the manifest's hash-bound `fixture_patch` applied, so the control and every mutant run see the fixture. RL22 runs it with `TMPDIR` inside the git work tree.

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
| RL10-kinds | M58 (`both`), its variant M58-i, M65 (`check_and_availability`), M67 (`check_and_lifecycle`) and M71 (`component_check_point`) | detected, exit 0. The report must show: `containment_evidence` `["M58"]`, `lifecycle_evidence` `["M67"]`, `availability_evidence` `["M65"]`, `component_check_point` `["M71"]`; counts of 5 entries, 4 distinct patches, 4 mechanisms and 1 variant (`{"M58": ["M58-i"]}`); M58, M65 and M67 under `observed_beyond_kind` |
| RL11-no-log | M53 plus a witness helper that writes no witness log | technical failure, exit 2 (witness log missing) |
| RL12-no-witness | M53 plus an L4c witness that never logs, while the witness log itself exists | technical failure, exit 2 (a named witness logged no observations) |
| RL13-collateral-syntax | M58 plus the pinned collateral test L5-session failing with an unexpected `SyntaxError` instead of its assertion | technical failure, exit 2 (the collateral differs from its pin) |
| RL14-collateral-assertion | M64 plus the pinned collateral test L11-unobservable failing with a `SyntaxError` exactly where its pinned assertion fails (same status and observations) | technical failure, exit 2 (assertion failure differs) |
| RL15-error-suffix | M57 plus a suffix outside the manifest appended to the error messages the L2b witnesses catch (only there; the rest of the run is unchanged) | technical failure, exit 2 (caught errors compared exactly) |
| RL16-m58, RL17-m57 | the real M58 and M57 mutants, the unmodified counterparts of RL13 and RL15 | detected, exit 0 |
| RL18-witness-aftereach | M53 plus an `afterEach` hook that fails in the L4c witness after its expected `WitnessAssertionError` | technical failure, exit 2 (the witness failed with more than its `WitnessAssertionError`) |
| RL19-unbound-beforeall | M53 plus a witness-log entry (a caught `SyntaxError`) written in a file-level `beforeAll`, outside any test | technical failure, exit 2 (entry outside any test) |
| RL20-same-name-files | the real M53, with a fixture test in another file whose describe and title equal the L4c witness's and which logs the L4c labels with their control values | detected, exit 0 (entries are bound by file) |
| RL21-ambiguous-name | the real M53, with a fixture test in the same file whose describe and title equal `[LC-L3]`'s | technical failure, exit 2 (ambiguous witness-log binding) |
| RL22-tmpdir-worktree | the real M53, run with `TMPDIR` inside this git work tree | detected, exit 0 (the patch takes effect; `git apply` is isolated from the enclosing work tree) |
| RL23-patch-context | an M53 patch whose context does not occur in the source | technical failure, exit 2 (patch does not apply) |
| RL24-unknown-only | the M53 manifest with `--only` naming an id it does not have | technical failure, exit 2, before any run |

RL10 and RL18–RL22 and RL24 fail with the driver of `ef0c9a8`. RL23 holds there too: a patch whose context does not match was already a technical failure. Driver of `ef0c9a8`:
- RL10 is rejected, because the availability kind is unknown;
- RL18, RL19, RL21 and RL24 give exit 0;
- RL20 gives exit 2: the same-named test's entries were merged into the witness's;
- RL22 gives exit 1: the patch was silently not applied.

The patch-effect check (every named file changes, the reverse patch applies) also guards the case where the isolation itself failed. That case cannot be produced without disabling the isolation, so no regression covers it.

## Determinism

`npm run mutants:lifecycle:determinism` (`scripts/mutants/witness-determinism.mjs`) runs the lifecycle test files three times on the unmodified tree with the witness log. It requires every run to pass, every witness-log entry to be bound to a test file and test, and the witness log (every check value and caught error, per test) to be identical to the first run's.

## Where the expected values come from

The lifecycle manifest's expected values were taken from a precheck run of every patch and pinned, with the manifest's SHA-256, before the final run. A detection therefore shows that the final run reproduced the pinned precheck observations exactly. That is reproducibility evidence. Whether an observation shows the plan row's safety property is stated per entry (`claim_limits`, recorded gaps) and rests in addition on independent review.

## Known limitations

The review of `ef0c9a8` (A5–A9) found these limitations. They are recorded here and in the lifecycle manifest's `gate_limitations`, which the report repeats; this round does not implement them.
- **A5:** a collateral pin binds the assertion text, not the assertion's position. A collateral test that fails at another `expect` with the same normalised message is accepted. The current collateral messages are unambiguous.
- **A6:** the strict whole-run rule sees caught errors only where a test logs them. A non-witness test with a loose assertion, for example `rejects.toThrow()` without a matcher, passes with any unexpected error. "The rest of the suite stayed unaffected" is therefore only as strong as those assertions.
- **A7:** the witness log encodes values losslessly only for plain JSON values:
  - `Error`, `Map` and `Date` objects and non-enumerable fields encode as `{}`;
  - `NaN` and `Infinity` encode as `null`;
  - `-0` encodes as `0`.

  A loss can give not detected or a technical failure, never a detection. The current labels are plain values.
- **A8:** kind and part are the manifest's claims. The gate checks that the claimed parts change. It does not check that a `check_point` witness is a production-path test, nor the direction of an effect beyond its part; availability has been a separate part since manifest version 4. Patches are not restricted to `src/`, although every lifecycle patch touches `src/` only.
- **A9:** the `.sha256` file proves the manifest's integrity, not its registration before the run. The expected values come from a precheck run (see above), so a detection is reproducibility evidence. The gate does not check `source_head` and `plan`.
