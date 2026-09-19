import { SchemaValidator } from "../src/schema-validator";
import { AcsToolCallRequest, AcsToolCallRequestPayload } from "../src/acs-types";
import { ReplayGuard } from "../src/replay-guard";
import { Guardian } from "../src/guardian";
import { ExecutionGate } from "../src/execution-gate";
import { AuditCollector } from "../src/audit";
import { GuardedExecutor } from "../src/guarded-executor";
import { SignatureService } from "../src/signature-service";
import { ExecutionCorrelationStore } from "../src/execution-correlation";
import { ApprovalGrantVerifier } from "../src/approval-verifier";
import { TestSigner } from "../tests/test-signer";
import crypto from "crypto";

async function runDemo(): Promise<void> {
  const sessionId = "session-demo-001";
  const audit = new AuditCollector();
  const schemaValidator = new SchemaValidator();
  const signatureService = new SignatureService("demo-root-secret-for-testing", "key-1");
  const replayGuard = new ReplayGuard({ audit });
  const guardian = new Guardian();

  // Local approval authority setup
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const approverKeyId = "demo-approver-key-1";
  const approvalVerifier = new ApprovalGrantVerifier(publicKey, approverKeyId);
  const demoSigner = new TestSigner(privateKey, approverKeyId);
    // Wire the enforcement stack through GuardedExecutor — the mandatory
  // orchestration boundary that prevents replay-guard from being skipped.
  const executor = new GuardedExecutor(
    schemaValidator,
    signatureService,
    replayGuard,
    guardian,
    audit,
    new ExecutionCorrelationStore(),
    approvalVerifier
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
  const grantBase = {
    version: 1 as const,
    decision: "approve" as const,
    session_id: sessionId,
    request_id: request.params.request_id,
    approver: { type: "human" as const, id: "demo-user" },
    issued_at: new Date().toISOString()
  };
  const grant = demoSigner.sign(grantBase);
  const toolResult = await executor.resolveApproval(grant);
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
