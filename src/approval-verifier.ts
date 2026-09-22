import crypto from "crypto";
import { canonicalize } from "json-canonicalize";


export type ApprovalErrorCode = 
  | "MALFORMED_GRANT"
  | "V1_REJECTED"
  | "INVALID_SIGNATURE"
  | "WRONG_APPROVER_IDENTITY"
  | "TOOL_BINDING_MISMATCH"
  | "SESSION_MISMATCH"
  | "REQUEST_MISMATCH";

export class ApprovalVerificationError extends Error {
  constructor(public readonly code: ApprovalErrorCode, message: string) {
    super(message);
    this.name = "ApprovalVerificationError";
  }
}

export interface ApprovalGrantV1 {
  version: 1;
  decision: "approve" | "reject";
  session_id: string;
  request_id: string;
  approver: {
    type: "human"; // Restricted to human
    id: string;
  };
  issued_at: string;
  signature: {
    algorithm: "Ed25519";
    key_id: string;
    value: string;
  };
}

export interface ApprovalGrantV2 {
  version: 2;
  decision: "approve" | "reject";
  session_id: string;
  request_id: string;
  tool: string; // EXPLICIT TOOL BINDING
  approver: {
    type: "human";
    id: string;
  };
  issued_at: string;
  signature: {
    algorithm: "Ed25519";
    key_id: string;
    value: string;
  };
}

export type AnyApprovalGrant = ApprovalGrantV1 | ApprovalGrantV2;

const ISO_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

export interface ApprovalContext {
  expectedSessionId: string;
  expectedRequestId: string;
  expectedTool: string;
  expectedApproverType: "human";
  expectedApproverId: string;
}

export class ApprovalGrantVerifier {
  constructor(
    private readonly publicKey: crypto.KeyObject,
    private readonly expectedKeyId: string
  ) {
    if (publicKey.type !== "public") {
      throw new Error("ApprovalGrantVerifier requires a public key, not a private key");
    }
  }

  // Backwards compatibility for existing code. Only verifies schema and signature.
  // Note: V1 is not tool-bound. This does NOT verify tool binding.
  verify(input: unknown): ApprovalGrantV1 {
    this.assertVersion(input, 1);
    const grant = this.verifySchemaAndSignature(input);
    return grant as ApprovalGrantV1;
  }

  // Verifies V2 explicitly with tool binding invariant.
  verifyV2(input: unknown, ctx: ApprovalContext): ApprovalGrantV2 {
    this.assertVersion(input, 2);
    const grant = this.verifySchemaAndSignature(input);

    const v2 = grant as ApprovalGrantV2;
    if (v2.session_id !== ctx.expectedSessionId) {
      throw new ApprovalVerificationError("SESSION_MISMATCH", "Invariant Violation: session_id does not match");
    }
    if (v2.request_id !== ctx.expectedRequestId) {
      throw new ApprovalVerificationError("REQUEST_MISMATCH", "Invariant Violation: request_id does not match");
    }
    if (v2.tool !== ctx.expectedTool) {
      throw new ApprovalVerificationError("TOOL_BINDING_MISMATCH", "Invariant Violation: tool does not match expected tool");
    }
    if (
      v2.approver.type !== ctx.expectedApproverType ||
      v2.approver.id !== ctx.expectedApproverId
    ) {
      throw new ApprovalVerificationError(
        "WRONG_APPROVER_IDENTITY",
        "Invariant Violation: approver does not match expected approver"
      );
    }

    return v2;
  }

  private assertVersion(input: unknown, expectedVersion: number) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: input must be a JSON object");
    }
    const grant = input as Record<string, unknown>;
    if (grant.version !== expectedVersion) {
      throw new ApprovalVerificationError(expectedVersion === 2 ? "V1_REJECTED" : "MALFORMED_GRANT", `Validation Error: version must be ${expectedVersion}`);
    }
  }

  private verifySchemaAndSignature(input: unknown): AnyApprovalGrant {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: input must be a JSON object");
    }
    
    const grant = input as Record<string, unknown>;
    
    if (grant.decision !== "approve" && grant.decision !== "reject") {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: decision must be 'approve' or 'reject'");
    }
    if (typeof grant.session_id !== "string" || grant.session_id.length === 0) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: session_id must be a non-empty string");
    }
    if (typeof grant.request_id !== "string" || grant.request_id.length === 0) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: request_id must be a non-empty string");
    }

    if (grant.version === 2) {
      if (typeof grant.tool !== "string" || grant.tool.length === 0) {
        throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: V2 requires a non-empty tool string");
      }
    }

    if (!grant.approver || typeof grant.approver !== "object" || Array.isArray(grant.approver)) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: approver must be an object");
    }
    const approver = grant.approver as Record<string, unknown>;
    if (approver.type !== "human") {
      throw new ApprovalVerificationError("WRONG_APPROVER_IDENTITY", "Validation Error: approver.type must be 'human'");
    }
    if (typeof approver.id !== "string" || approver.id.length === 0) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: approver.id must be a non-empty string");
    }

    if (typeof grant.issued_at !== "string" || !ISO_REGEX.test(grant.issued_at) || isNaN(Date.parse(grant.issued_at))) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: issued_at must be a valid ISO-8601 timestamp");
    }

    if (!grant.signature || typeof grant.signature !== "object" || Array.isArray(grant.signature)) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature must be an object");
    }
    const signature = grant.signature as Record<string, unknown>;
    if (signature.algorithm !== "Ed25519") {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature.algorithm must be 'Ed25519'");
    }
    if (signature.key_id !== this.expectedKeyId) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature.key_id mismatch");
    }
    if (typeof signature.value !== "string" || signature.value.length === 0 || signature.value.length % 4 !== 0 || !BASE64_REGEX.test(signature.value)) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature.value must be valid base64 format");
    }
    const dec = Buffer.from(signature.value, "base64");
    if (dec.length !== 64) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature must be exactly 64 bytes");
    }
    if (dec.toString("base64") !== signature.value) {
      throw new ApprovalVerificationError("MALFORMED_GRANT", "Validation Error: signature.value must be canonical base64");
    }

    // Return a deeply cloned snapshot to prevent caller mutation after verification
    const verifiedSnapshot = JSON.parse(JSON.stringify(grant)) as AnyApprovalGrant;

    // Cryptographic verification
    const cloneForSig = JSON.parse(JSON.stringify(verifiedSnapshot));
    delete cloneForSig.signature;

    const dataBuffer = Buffer.from(canonicalize(cloneForSig));
    const sigBuffer = Buffer.from(verifiedSnapshot.signature.value, "base64");

    let isVerified = false;
    try {
      isVerified = crypto.verify(null, dataBuffer, this.publicKey, sigBuffer);
    } catch {
      throw new ApprovalVerificationError("INVALID_SIGNATURE", "Validation Error: crypto verification failed");
    }

    if (!isVerified) {
      throw new ApprovalVerificationError("INVALID_SIGNATURE", "Validation Error: Invalid signature");
    }

    return verifiedSnapshot;
  }
}
