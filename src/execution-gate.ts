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
  private approvals: Set<string> = new Set();

  constructor(audit: AuditCollector) {
    this.audit = audit;
  }

  /**
   * Supply human approval for a specific request_id.
   * Approval is bound to the exact request_id; it cannot authorize any other request.
   */
  supplyApproval(request_id: string): void {
    this.approvals.add(request_id);
    this.audit.record(request_id, "human_approval");
  }

  async execute(
    request: AcsToolCallRequest,
    response: AcsResponseEnvelope
  ): Promise<AcsToolCallResult> {
    const { params } = request;
    const { result } = response;
    const toolName = params.payload.tool.name;

    this.audit.record(params.request_id, "tool_call_requested", {
      tool: toolName,
    });
    this.audit.record(params.request_id, "guardian_decision", {
      decision: result.decision,
      reason_codes: result.reason_codes,
    });

    // DENY — hard block; approval cannot override.
    if (result.decision === "deny") {
      this.audit.record(params.request_id, "tool_execution_blocked", {
        reason: "denied",
      });
      throw new Error(
        `Execution blocked (deny): ${result.reasoning ?? result.reason_codes?.[0]}`
      );
    }

    // ASK — block until external approval is supplied for this exact request_id.
    if (result.decision === "ask") {
      if (!this.approvals.has(params.request_id)) {
        this.audit.record(params.request_id, "tool_execution_blocked", {
          reason: "pending_approval",
        });
        throw new Error(
          `Execution blocked: Pending human approval for request ${params.request_id}`
        );
      }
    }

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
