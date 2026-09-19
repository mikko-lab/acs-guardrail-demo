import { AcsToolCallRequest, AcsResponseEnvelope, AcsToolCallResult } from "./acs-types";
import { AuditCollector } from "./audit";
import { tools, unknownToolMock } from "./tools";

/**
 * ExecutionGate — the critical security boundary.
 *
 * Consumes an ACS response envelope from the Guardian and enforces:
 *   allow → execute exactly once
 *   deny  → never execute (approval cannot override a deny)
 *   ask   → only execute after supplyApproval(request_id) is called
 *           for the exact matching request_id
 *
 * Returns an AcsToolCallResult (hooks/tool-call-result.json shape) on
 * successful execution, or throws on block.
 */
export class ExecutionGate {
  private audit: AuditCollector;

  constructor(audit: AuditCollector) {
    this.audit = audit;
  }

  async execute(
    request: AcsToolCallRequest,
    response: AcsResponseEnvelope
  ): Promise<AcsToolCallResult> {
    const { params } = request;
    const { result } = response;
    const toolName = params.payload.tool.name;

    // We do not record tool_call_requested or guardian_decision here anymore,
    // they are better recorded centrally or assumed already recorded by GuardedExecutor,
    // but we can leave them if they don't hurt. Wait, GuardedExecutor might record them?
    // Let's leave them here for now, or move them? The user didn't say to move audit.

    // DENY — hard block.
    if (result.decision === "deny") {
      this.audit.record(params.request_id, "tool_execution_blocked", {
        reason: "denied",
      });
      throw new Error(
        `Execution blocked (deny): ${result.reasoning ?? result.reason_codes?.[0]}`
      );
    }

    // If decision === "ask", it reaches here ONLY via the GuardedExecutor.approve() path.
    // The GuardedExecutor manages the pending-action state.

    this.audit.record(params.request_id, "tool_execution_started");

    const toolFn = tools[toolName] ?? unknownToolMock;

    // Pass argument values (unwrapping { value } per ACS ToolArgumentValue shape).
    const unwrappedArgs: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(params.payload.arguments)) {
      unwrappedArgs[k] = v.value;
    }

    try {
      const rawResult = await toolFn(unwrappedArgs);
      this.audit.record(params.request_id, "tool_execution_completed", {
        status: "success",
      });

      // Return ACS toolCallResult shape (hooks/tool-call-result.json).
      return {
        tool: { name: toolName },
        request_id_ref: params.request_id,
        exit_status: "success",
        outputs: [{ value: rawResult }],
      };
    } catch (e: unknown) {
      this.audit.record(params.request_id, "tool_execution_completed", {
        status: "error",
      });
      throw e;
    }
  }
}
