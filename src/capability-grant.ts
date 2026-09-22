import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { Clock } from "./replay-guard"; // reusing the existing clock interface

export interface CapabilityGrantV1 {
  version: 1;
  capability_id: string;
  agent_id: string;
  session_id: string;
  allowed_tools: string[];
  issued_at: string;
  expires_at: string;
  signature: {
    algorithm: "Ed25519";
    key_id: string;
    value: string;
  };
}

export interface CapabilityContext {
  expectedAgentId: string;
  expectedSessionId: string;
  requestedTool: string;
}

const ISO_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

export class CapabilityGrantVerifier {
  constructor(
    private readonly publicKey: crypto.KeyObject,
    private readonly expectedKeyId: string,
    private readonly clock: Clock
  ) {
    if (publicKey.type !== "public") {
      throw new Error("CapabilityGrantVerifier requires a public key, not a private key");
    }
  }

  verify(input: unknown, ctx: CapabilityContext): CapabilityGrantV1 {
    // 1. Basic Structural/Schema Validation
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new Error("Validation Error: input must be a JSON object");
    }
    
    const grant = input as Record<string, unknown>;

    if (grant.version !== 1) {
      throw new Error("Validation Error: version must be 1");
    }
    if (typeof grant.capability_id !== "string" || grant.capability_id.length === 0) {
      throw new Error("Validation Error: capability_id must be a non-empty string");
    }
    if (typeof grant.agent_id !== "string" || grant.agent_id.length === 0) {
      throw new Error("Validation Error: agent_id must be a non-empty string");
    }
    if (typeof grant.session_id !== "string" || grant.session_id.length === 0) {
      throw new Error("Validation Error: session_id must be a non-empty string");
    }
    if (!Array.isArray(grant.allowed_tools) || grant.allowed_tools.length === 0) {
      throw new Error("Validation Error: allowed_tools must be a non-empty array");
    }
    // We only check array structural types here, semantics (wildcard) is checked after authentication.
    for (const tool of grant.allowed_tools) {
      if (typeof tool !== "string" || tool.length === 0) {
        throw new Error("Validation Error: allowed_tools must contain non-empty strings");
      }
    }

    if (typeof grant.issued_at !== "string" || !ISO_REGEX.test(grant.issued_at) || isNaN(Date.parse(grant.issued_at))) {
      throw new Error("Validation Error: issued_at must be a valid ISO-8601 timestamp format");
    }
    if (typeof grant.expires_at !== "string" || !ISO_REGEX.test(grant.expires_at) || isNaN(Date.parse(grant.expires_at))) {
      throw new Error("Validation Error: expires_at must be a valid ISO-8601 timestamp format");
    }

    if (!grant.signature || typeof grant.signature !== "object" || Array.isArray(grant.signature)) {
      throw new Error("Validation Error: signature must be an object");
    }
    const signature = grant.signature as Record<string, unknown>;
    if (signature.algorithm !== "Ed25519") {
      throw new Error("Validation Error: signature.algorithm must be 'Ed25519'");
    }
    if (signature.key_id !== this.expectedKeyId) {
      throw new Error("Validation Error: signature.key_id mismatch");
    }
    if (typeof signature.value !== "string" || signature.value.length === 0 || signature.value.length % 4 !== 0 || !BASE64_REGEX.test(signature.value)) {
      throw new Error("Validation Error: signature.value must be valid base64 format");
    }
    const dec = Buffer.from(signature.value, "base64");
    if (dec.length !== 64) {
      throw new Error("Validation Error: signature must be exactly 64 bytes");
    }
    if (dec.toString("base64") !== signature.value) {
      throw new Error("Validation Error: signature.value must be canonical base64");
    }

    // 2. Authentication: Signature Verification
    const verifiedSnapshot = JSON.parse(JSON.stringify(grant)) as CapabilityGrantV1;

    const cloneForSig = JSON.parse(JSON.stringify(verifiedSnapshot));
    delete cloneForSig.signature;

    const dataBuffer = Buffer.from(canonicalize(cloneForSig));
    const sigBuffer = Buffer.from(verifiedSnapshot.signature.value, "base64");

    let isVerified = false;
    try {
      isVerified = crypto.verify(null, dataBuffer, this.publicKey, sigBuffer);
    } catch {
      throw new Error("Validation Error: crypto verification failed");
    }

    if (!isVerified) {
      throw new Error("Validation Error: Invalid signature");
    }

    // 3. Semantic Validation (Temporal & Wildcard)
    for (const tool of verifiedSnapshot.allowed_tools) {
      if (tool === "*" || tool.includes("*")) {
        throw new Error("Validation Error: allowed_tools must contain exact matches (no wildcards)");
      }
    }

    const issuedAt = new Date(verifiedSnapshot.issued_at).getTime();
    const expiresAt = new Date(verifiedSnapshot.expires_at).getTime();
    const now = this.clock.nowMs();

    if (expiresAt <= issuedAt) {
      throw new Error("Validation Error: expires_at must be strictly after issued_at");
    }
    if (now < issuedAt) {
      throw new Error("Validation Error: capability is not yet valid");
    }
    if (now >= expiresAt) {
      throw new Error("Validation Error: capability has expired");
    }

    // 4. Authoritative Invariants Context Enforcement
    if (verifiedSnapshot.agent_id !== ctx.expectedAgentId) {
      throw new Error("Invariant Violation: agent_id does not match");
    }
    if (verifiedSnapshot.session_id !== ctx.expectedSessionId) {
      throw new Error("Invariant Violation: session_id does not match");
    }
    
    // Tool Scope Binding
    if (!verifiedSnapshot.allowed_tools.includes(ctx.requestedTool)) {
      throw new Error(`Invariant Violation: requested tool '${ctx.requestedTool}' is not in allowed_tools`);
    }

    return verifiedSnapshot;
  }
}
