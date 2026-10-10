import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { Clock } from "./replay-guard"; // reusing the existing clock interface


export type CapabilityErrorCode = 
  | "MALFORMED_GRANT"
  | "INVALID_SIGNATURE"
  | "UNSUPPORTED_SCOPE"
  | "EXPIRED"
  | "NOT_YET_VALID"
  | "AGENT_MISMATCH"
  | "SESSION_MISMATCH"
  | "TOOL_SCOPE_MISMATCH"
  | "MISSING_TENANT";

export class CapabilityVerificationError extends Error {
  constructor(public readonly code: CapabilityErrorCode, message: string) {
    super(message);
    this.name = "CapabilityVerificationError";
  }
}

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

/**
 * Tenant-bound grant (tenancy mode). `tenant_id` is covered by the issuer signature and by the capability
 * fingerprint, and it is the only trusted source of an authority's tenant.
 */
export interface CapabilityGrantV2 extends Omit<CapabilityGrantV1, "version"> {
  version: 2;
  tenant_id: string;
}

export type CapabilityGrant = CapabilityGrantV1 | CapabilityGrantV2;

/** The tenant a verified grant is bound to; undefined for a version 1 (tenantless) grant. */
export const tenantOf = (grant: CapabilityGrant): string | undefined => (grant.version === 2 ? grant.tenant_id : undefined);

export interface CapabilityVerifierOptions {
  /**
   * Tenancy mode. When true, only version 2 grants with a tenant_id are accepted and a tenantless grant is
   * rejected (MISSING_TENANT); there is no default tenant. When false (default), only version 1 grants are
   * accepted. One verifier never accepts both versions.
   */
  tenancy?: boolean;
}

const MAX_TENANT_ID_LENGTH = 256;

export interface CapabilityContext {
  expectedAgentId: string;
  expectedSessionId: string;
  requestedTool: string;
}

const ISO_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

export class CapabilityGrantVerifier {
  /** Whether this verifier (and the executor using it) runs in tenancy mode. */
  readonly tenancy: boolean;

  constructor(
    private readonly publicKey: crypto.KeyObject,
    private readonly expectedKeyId: string,
    private readonly clock: Clock,
    options: CapabilityVerifierOptions = {}
  ) {
    this.tenancy = options.tenancy === true;
    if (publicKey.type !== "public") {
      throw new Error("CapabilityGrantVerifier requires a public key, not a private key");
    }
  }

  verify(input: unknown, ctx: CapabilityContext): CapabilityGrant {
    // 1. Basic Structural/Schema Validation
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: input must be a JSON object");
    }
    
    const grant = input as Record<string, unknown>;

    if (this.tenancy) {
      if (grant.version !== 2 || grant.tenant_id === undefined) {
        throw new CapabilityVerificationError("MISSING_TENANT", "Validation Error: tenancy mode requires a version 2 grant with tenant_id");
      }
      if (typeof grant.tenant_id !== "string" || grant.tenant_id.length === 0 || grant.tenant_id.length > MAX_TENANT_ID_LENGTH) {
        throw new CapabilityVerificationError("MALFORMED_GRANT", `Validation Error: tenant_id must be a non-empty string of at most ${MAX_TENANT_ID_LENGTH} characters`);
      }
    } else {
      if (grant.version !== 1) {
        throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: version must be 1");
      }
      if ("tenant_id" in grant) {
        throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: tenant_id is only valid in a version 2 grant (tenancy mode)");
      }
    }
    if (typeof grant.capability_id !== "string" || grant.capability_id.length === 0) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: capability_id must be a non-empty string");
    }
    if (typeof grant.agent_id !== "string" || grant.agent_id.length === 0) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: agent_id must be a non-empty string");
    }
    if (typeof grant.session_id !== "string" || grant.session_id.length === 0) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: session_id must be a non-empty string");
    }
    if (!Array.isArray(grant.allowed_tools) || grant.allowed_tools.length === 0) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: allowed_tools must be a non-empty array");
    }
    // We only check array structural types here, semantics (wildcard) is checked after authentication.
    for (const tool of grant.allowed_tools) {
      if (typeof tool !== "string" || tool.length === 0) {
        throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: allowed_tools must contain non-empty strings");
      }
    }

    if (typeof grant.issued_at !== "string" || !ISO_REGEX.test(grant.issued_at) || isNaN(Date.parse(grant.issued_at))) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: issued_at must be a valid ISO-8601 timestamp format");
    }
    if (typeof grant.expires_at !== "string" || !ISO_REGEX.test(grant.expires_at) || isNaN(Date.parse(grant.expires_at))) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: expires_at must be a valid ISO-8601 timestamp format");
    }

    if (!grant.signature || typeof grant.signature !== "object" || Array.isArray(grant.signature)) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature must be an object");
    }
    const signature = grant.signature as Record<string, unknown>;
    if (signature.algorithm !== "Ed25519") {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature.algorithm must be 'Ed25519'");
    }
    if (signature.key_id !== this.expectedKeyId) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature.key_id mismatch");
    }
    if (typeof signature.value !== "string" || signature.value.length === 0 || signature.value.length % 4 !== 0 || !BASE64_REGEX.test(signature.value)) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature.value must be valid base64 format");
    }
    const dec = Buffer.from(signature.value, "base64");
    if (dec.length !== 64) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature must be exactly 64 bytes");
    }
    if (dec.toString("base64") !== signature.value) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: signature.value must be canonical base64");
    }

    // 2. Authentication: Signature Verification
    const verifiedSnapshot = JSON.parse(JSON.stringify(grant)) as CapabilityGrant;

    const cloneForSig = JSON.parse(JSON.stringify(verifiedSnapshot));
    delete cloneForSig.signature;

    const dataBuffer = Buffer.from(canonicalize(cloneForSig));
    const sigBuffer = Buffer.from(verifiedSnapshot.signature.value, "base64");

    let isVerified = false;
    try {
      isVerified = crypto.verify(null, dataBuffer, this.publicKey, sigBuffer);
    } catch {
      throw new CapabilityVerificationError("INVALID_SIGNATURE", "Validation Error: crypto verification failed");
    }

    if (!isVerified) {
      throw new CapabilityVerificationError("INVALID_SIGNATURE", "Validation Error: Invalid signature");
    }

    // 3. Semantic Validation (Temporal & Wildcard)
    for (const tool of verifiedSnapshot.allowed_tools) {
      if (tool === "*" || tool.includes("*")) {
        throw new CapabilityVerificationError("UNSUPPORTED_SCOPE", "Validation Error: allowed_tools must contain exact matches (no wildcards)");
      }
    }

    const issuedAt = new Date(verifiedSnapshot.issued_at).getTime();
    const expiresAt = new Date(verifiedSnapshot.expires_at).getTime();
    const now = this.clock.nowMs();

    if (expiresAt <= issuedAt) {
      throw new CapabilityVerificationError("MALFORMED_GRANT", "Validation Error: expires_at must be strictly after issued_at");
    }
    if (now < issuedAt) {
      throw new CapabilityVerificationError("NOT_YET_VALID", "Validation Error: capability is not yet valid");
    }
    if (now >= expiresAt) {
      throw new CapabilityVerificationError("EXPIRED", "Validation Error: capability has expired");
    }

    // 4. Authoritative Invariants Context Enforcement
    if (verifiedSnapshot.agent_id !== ctx.expectedAgentId) {
      throw new CapabilityVerificationError("AGENT_MISMATCH", "Invariant Violation: agent_id does not match");
    }
    if (verifiedSnapshot.session_id !== ctx.expectedSessionId) {
      throw new CapabilityVerificationError("SESSION_MISMATCH", "Invariant Violation: session_id does not match");
    }
    
    // Tool Scope Binding
    if (!verifiedSnapshot.allowed_tools.includes(ctx.requestedTool)) {
      throw new CapabilityVerificationError("TOOL_SCOPE_MISMATCH", `Invariant Violation: requested tool '${ctx.requestedTool}' is not in allowed_tools`);
    }

    return verifiedSnapshot;
  }
}
