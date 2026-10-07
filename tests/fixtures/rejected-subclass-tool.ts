/**
 * Child-process fixture for C28b: a tool returns an already rejected Promise subclass. The process must exit
 * normally (no unhandled rejection) after the execution reaches its 'failed' terminal. No timers, no handlers
 * for unhandled rejections: Node's default behaviour decides the exit code.
 */
import { setup, makeRequest } from "../evals/eval-setup";
import { tools } from "../../src/tools";

class SubPromise<T> extends Promise<T> {}

async function main(): Promise<void> {
  const ctx = setup(Date.now());
  let executionId = "";
  tools.read_record = (_args, c) => { executionId = c!.execution_id; return SubPromise.reject(new Error("SUBCLASS_REJECTION_MARKER")); };
  const result = await ctx.executor.process(makeRequest({ tool: "read_record", sessionId: "c28b", requestId: "c28b-a" }, ctx.clock));
  const terminal = await ctx.executor.whenTerminal(executionId);
  process.stdout.write(JSON.stringify({ outcome: terminal.outcome, delivered: result !== undefined }) + "\n");
}

void main();
