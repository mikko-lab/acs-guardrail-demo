import { AcsToolCallRequest, AcsToolCallRequestPayload } from "./acs-types";
import { Guardian } from "./guardian";
import { ExecutionGate } from "./execution-gate";
import { AuditCollector } from "./audit";

async function runDemo(): Promise<void> {
  const audit = new AuditCollector();
  const guardian = new Guardian();
  const gate = new ExecutionGate(audit);

  // --- Construct a request using the ACS params-nested shape ---
  const request: AcsToolCallRequest = {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: "call-demo-1",
    params: {
      acs_version: "0.1.0",
      request_id: "req-demo-1",
      timestamp: new Date().toISOString(),
      metadata: {
        agent_id: "demo-agent",
        session_id: "session-demo-001",
      },
      payload: {
        tool: { name: "update_record" },
        // Arguments use the ACS ToolArgumentValue shape: { value: ... }
        arguments: {
          id: { value: "record_42" },
        },
      } satisfies AcsToolCallRequestPayload,
    },
  };

  const response = guardian.evaluate(request);
  console.log(`Guardian decision: ${response.result.decision}`);

  // --- First attempt: no approval supplied → should block ---
  try {
    await gate.execute(request, response);
  } catch (e: unknown) {
    console.log(`Blocked (expected): ${(e as Error).message}`);
  }

  // --- Supply approval for this exact request_id ---
  gate.supplyApproval(request.params.request_id);
  const toolResult = await gate.execute(request, response);
  console.log(`Tool result:`, toolResult);
  console.log(`\nAudit log:\n`, JSON.stringify(audit.getEvents(), null, 2));
}

if (require.main === module) {
  runDemo().catch(console.error);
}
