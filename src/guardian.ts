import {
  AcsToolCallRequest,
  AcsResponseEnvelope,
  GuardianDecision,
} from "./acs-types";

/**
 * Deterministic Guardian.
 *
 * Returns an ACS response-envelope (jsonrpc/id/result) where result is an
 * AcsResult with the correct field names from response-envelope.json:
 *   - decision       (NOT "disposition")
 *   - reasoning      (human-readable, REQUIRED on deny and ask)
 *   - reason_codes   (string[], machine-readable)
 *   - ask_details    (REQUIRED when decision === "ask")
 */
export class Guardian {
  evaluate(request: AcsToolCallRequest): AcsResponseEnvelope {
    const { params } = request;
    const toolName = params.payload.tool.name;

    let result: GuardianDecision;

    if (toolName === "read_record") {
      result = {
        type: "final",
        acs_version: "0.1.0",
        request_id: params.request_id,
        decision: "allow",
        reasoning: "Tool is explicitly marked as safe for read-only access.",
        reason_codes: ["DEMO_READ_ONLY_ALLOWED"],
      };
    } else if (toolName === "update_record") {
      result = {
        type: "final",
        acs_version: "0.1.0",
        request_id: params.request_id,
        decision: "ask",
        reasoning:
          "Modifying records causes a side effect and requires explicit human approval before execution.",
        reason_codes: ["DEMO_SIDE_EFFECT_APPROVAL_REQUIRED"],
        ask_details: {
          approver: {
            type: "human",
            id: "demo-operator",
          },
          question:
            "The observed agent has requested update_record. Do you approve this side-effecting operation?",
          timeout_seconds: 300,
          timeout_disposition: "deny",
        },
      };
    } else {
      result = {
        type: "final",
        acs_version: "0.1.0",
        request_id: params.request_id,
        decision: "deny",
        reasoning:
          "The requested tool is not in the allowed policy. Unknown tools are never permitted.",
        reason_codes: ["DEMO_UNKNOWN_TOOL"],
      };
    }

    return {
      jsonrpc: "2.0",
      id: request.id,
      result,
    };
  }
}
