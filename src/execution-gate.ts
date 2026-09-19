import { AcsToolCallRequest, AcsToolCallResult } from "./acs-types";
import { tools, unknownToolMock } from "./tools";
import { AuditCollector } from "./audit";

export interface ExecutionPermit {
  readonly sessionId: string;
  readonly requestId: string;
  readonly toolName: string;
}

/**
 * ExecutionGate — the critical security boundary.
 *
 * Consumes an internal ExecutionPermit to execute tools.
 * It strictly requires a valid permit to run any tool.
 */
export class ExecutionGate {
  private audit: AuditCollector;
  #authority: symbol;
  #activePermits = new WeakSet<ExecutionPermit>();

  constructor(audit: AuditCollector, authority: symbol) {
    this.audit = audit;
    this.#authority = authority;
  }

  mintPermit(authority: symbol, sessionId: string, requestId: string, toolName: string): ExecutionPermit {
    if (authority !== this.#authority) {
      throw new Error("Unauthorized permit minting");
    }
    const permit = { sessionId, requestId, toolName };
    this.#activePermits.add(permit);
    return permit;
  }

  async execute(
    request: AcsToolCallRequest,
    permit: ExecutionPermit
  ): Promise<AcsToolCallResult> {
    const { params } = request;
    const toolName = params.payload.tool.name;

    if (!permit || !this.#activePermits.has(permit)) {
      throw new Error("Execution blocked: valid execution permit required");
    }

    // Permit is consumed IMMEDIATELY before tool invocation
    this.#activePermits.delete(permit);

    // Validate bindings
    if (permit.sessionId !== params.metadata.session_id) {
      throw new Error("Execution blocked: permit session mismatch");
    }
    if (permit.requestId !== params.request_id) {
      throw new Error("Execution blocked: permit request mismatch");
    }
    if (permit.toolName !== toolName) {
      throw new Error("Execution blocked: permit tool mismatch");
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
