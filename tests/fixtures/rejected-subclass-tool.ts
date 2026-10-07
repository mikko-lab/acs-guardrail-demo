/**
 * Child-process fixture for C28b and C29b. The process must exit normally (no unhandled rejection) after the
 * execution reaches its terminal. No timers and no unhandled-rejection handlers: Node's default behaviour decides
 * the exit code.
 *
 * - rejected-subclass: the tool returns an already rejected Promise subclass (expected terminal: failed).
 * - rejecting-species: the tool returns a fulfilled native Promise whose `constructor` is a species that rejects
 *   every Promise it constructs after running the executor (expected terminal: completed).
 */
import { setup, makeRequest } from "../evals/eval-setup";
import { tools } from "../../src/tools";

class SubPromise<T> extends Promise<T> {}

class RejectingSpecies<T> extends Promise<T> {
  constructor(executor: (resolve: (value: T | PromiseLike<T>) => void, reject: (reason?: unknown) => void) => void) {
    let rejectSelf!: (reason?: unknown) => void;
    super((resolve, reject) => { rejectSelf = reject; executor(resolve, reject); });
    rejectSelf(new Error("DERIVED_SPECIES_REJECTION"));
  }
}

function toolResult(scenario: string): Promise<unknown> {
  if (scenario === "rejected-subclass") return SubPromise.reject(new Error("SUBCLASS_REJECTION_MARKER"));
  if (scenario === "rejecting-species") {
    const p = Promise.resolve({ status: "ok" });
    Object.defineProperty(p, "constructor", { value: RejectingSpecies, writable: true, configurable: true });
    return p;
  }
  throw new Error(`unknown scenario ${scenario}`);
}

async function main(): Promise<void> {
  const scenario = process.argv[2];
  const ctx = setup(Date.now());
  let executionId = "";
  tools.read_record = (_args, c) => { executionId = c!.execution_id; return toolResult(scenario); };
  const result = await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: scenario, requestId: `${scenario}-a` }, ctx.clock));
  const terminal = await ctx.executor.whenTerminal(executionId);
  process.stdout.write(JSON.stringify({ outcome: terminal.outcome, delivered: result !== undefined }) + "\n");
}

void main();
