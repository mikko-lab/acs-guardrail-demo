import { SchemaValidator } from "./schema-validator";
import { AcsToolCallRequest, AcsToolCallRequestPayload } from "./acs-types";
import { ReplayGuard } from "./replay-guard";
import { Guardian } from "./guardian";
import { ExecutionGate } from "./execution-gate";
import { AuditCollector } from "./audit";
import { GuardedExecutor } from "./guarded-executor";
import { SignatureService } from "./signature-service";
import { ExecutionCorrelationStore } from "./execution-correlation";

async function runDemo(): Promise<void> {
  const sessionId = "session-demo-001";
  const audit = new AuditCollector();
  const schemaValidator = new SchemaValidator();
  const signatureService = new SignatureService("demo-root-secret-for-testing", "key-1");
  const replayGuard = new ReplayGuard({ audit });
  const guardian = new Guardian();
    // Wire the enforcement stack through GuardedExecutor — the mandatory
  // orchestration boundary that prevents replay-guard from being skipped.
  const executor = new GuardedExecutor(
    schemaValidator,
    signatureService,
    replayGuard,
    guardian,
    audit,
    new ExecutionCorrelationStore()
  );

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
        session_id: sessionId,
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

  // --- First attempt: yields a pending status without executing ---
  console.log("Sending request...");
  const processResult = await executor.process(request);
  if (processResult.status === "pending") {
    console.log(`Paused: Pending human approval for request ${request.params.request_id}`);
  } else {
    console.log(`Executed immediately:`, processResult.result);
  }

  // --- Supply approval for this exact session_id + request_id ---
  console.log("Supplying human approval...");
  const toolResult = await executor.approve(sessionId, request.params.request_id);
  console.log(`Tool result:`, toolResult);

  // --- Demonstrate replay rejection: same request in same session ---
  try {
    await executor.process(request);
  } catch (e: unknown) {
    console.log(`Replay blocked (expected): ${(e as Error).message}`);
  }

  console.log(`\nAudit log:\n`, JSON.stringify(audit.getEvents(), null, 2));

  // --- Clean up session state ---
  executor.clearSession(sessionId);
}

if (require.main === module) {
  runDemo().catch(console.error);
}
