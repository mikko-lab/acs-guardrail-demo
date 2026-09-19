// -------------------------------------------------------------------
// ACS v0.1.0 shape-aligned types for the Phase 1 demo.
//
// SCOPE NOTE: This file models the selected ACS shapes:
//   - request-envelope.json  (params-nested structure)
//   - hooks/tool-call-request.json  (ToolArgumentValue)
//   - response-envelope.json  (AcsResult with decision/reasoning/reason_codes)
//   - ask-details.json
//   - hooks/tool-call-result.json
//
// Fields intentionally omitted at this phase:
//   nonce, signature, chain_hash, provenance, tenant_id,
//   modifications, defer_details, policy_references, policy_data.
// -------------------------------------------------------------------

// ── Request ──────────────────────────────────────────────────────────

/** Minimal ACS Metadata (request-envelope.json #/$defs/Metadata). */
export interface AcsMetadata {
  agent_id: string;
  session_id: string;
}

/**
 * ACS ToolArgumentValue (hooks/tool-call-request.json #/arguments/additionalProperties).
 * Each argument is an object with at minimum a `value` property.
 * `provenance` is omitted in this phase (ACS-Provenance not implemented).
 */
export interface AcsToolArgumentValue {
  value: unknown;
}

/** hooks/tool-call-request.json payload shape. */
export interface AcsToolCallRequestPayload {
  tool: { name: string };
  arguments: Record<string, AcsToolArgumentValue>;
}

/**
 * ACS params block (request-envelope.json #/$defs/AcsParams).
 * acs_version uses semver without a leading "v" (pattern: ^\d+\.\d+\.\d+$).
 */
export interface AcsParams {
  acs_version: string;
  request_id: string;
  timestamp: string;
  metadata: AcsMetadata;
  payload: AcsToolCallRequestPayload;
}

/**
 * ACS Request Envelope (request-envelope.json).
 * ACS fields (acs_version, request_id, …) live inside `params`, not at the root.
 */
export interface AcsToolCallRequest {
  jsonrpc: "2.0";
  method: "steps/toolCallRequest";
  id: string | number;
  params: AcsParams;
}

// ── Response ─────────────────────────────────────────────────────────

export type GuardianDecisionValue = "allow" | "deny" | "ask";

/**
 * ACS ask-details.json shape.
 * Required when decision === "ask".
 */
export interface AcsAskDetails {
  approver: {
    type: "human" | "agent" | "service";
    id: string;
  };
  question: string;
  timeout_seconds: number;
  timeout_disposition: "allow" | "deny";
}

/**
 * ACS AcsResult (response-envelope.json #/$defs/AcsResult).
 *
 * Key field names (taken directly from the schema):
 *   - `decision`     — the verdict field (NOT "disposition")
 *   - `reasoning`    — human-renderable explanation (REQUIRED on deny/ask)
 *   - `reason_codes` — machine-readable string[] (free vocabulary in v0.1)
 *   - `ask_details`  — required when decision === "ask"
 */
export interface GuardianDecision {
  type: "final";
  acs_version: string;
  request_id: string;
  decision: GuardianDecisionValue;
  reasoning?: string;
  reason_codes?: string[];
  ask_details?: AcsAskDetails;
}

/**
 * ACS Response Envelope (response-envelope.json).
 */
export interface AcsResponseEnvelope {
  jsonrpc: "2.0";
  id: string | number;
  result: GuardianDecision;
}

// ── Result ────────────────────────────────────────────────────────────

/**
 * ACS ToolCallResult payload (hooks/tool-call-result.json).
 * exit_status enum: "success" | "failure" | "timeout" | "blocked"
 */
export interface AcsToolCallResult {
  tool: { name: string };
  request_id_ref: string;
  exit_status: "success" | "failure" | "timeout" | "blocked";
  outputs: Array<{ value: unknown }>;
}

// ── Audit (internal, not an ACS-Audit claim) ─────────────────────────

export type AuditEventType =
  | "tool_call_requested"
  | "guardian_decision"
  | "human_approval"
  | "tool_execution_started"
  | "tool_execution_completed"
  | "tool_execution_blocked";

export interface AuditEvent {
  timestamp: string;
  request_id: string;
  event_type: AuditEventType;
  metadata?: Record<string, unknown>;
}
