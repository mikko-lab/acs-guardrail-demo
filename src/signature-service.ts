import * as crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { AcsToolCallRequest, AcsResponseEnvelope, AcsSignature } from "./acs-types";

export class SignatureInvalidError extends Error {
  public code = -32004;
  constructor(message: string) {
    super(message);
    this.name = "SignatureInvalidError";
  }
}

export class SignatureService {
  constructor(private readonly rootSecret: string, private readonly keyId: string) {}

  private deriveKey(sessionId: string): Buffer {
    // HKDF-SHA256, empty salt, info = UTF-8 session_id, 32 bytes
    return Buffer.from(crypto.hkdfSync(
      "sha256",
      this.rootSecret,
      "",
      sessionId,
      32
    ));
  }

  private computeMac(key: Buffer, canonicalInput: string): string {
    return crypto
      .createHmac("sha256", key)
      .update(canonicalInput, "utf8")
      .digest("base64");
  }

  private getCanonicalInput(envelope: any, removeSignatureFrom: "params" | "result"): string {
    // Clone to remove signature
    const clone = JSON.parse(JSON.stringify(envelope));

    if (removeSignatureFrom === "params" && clone.params) {
      delete clone.params.signature;
    } else if (removeSignatureFrom === "result" && clone.result) {
      delete clone.result.signature;
    }

    const canonicalInput = canonicalize(clone);
    if (!canonicalInput) {
      throw new Error("Failed to canonicalize envelope");
    }
    return canonicalInput;
  }


  private decodeCanonicalHmacSha256Signature(value: string): Buffer {
    if (!value || typeof value !== "string") {
      throw new SignatureInvalidError("Signature value must be a non-empty string");
    }

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      throw new SignatureInvalidError("Signature value must be standard base64");
    }

    const decoded = Buffer.from(value, "base64");

    if (decoded.length !== 32) {
      throw new SignatureInvalidError("Invalid signature length");
    }

    if (decoded.toString("base64") !== value) {
      throw new SignatureInvalidError("Non-canonical base64 signature");
    }

    return decoded;
  }

  public signRequest(request: AcsToolCallRequest): AcsToolCallRequest {
    const sessionId = request.params.metadata.session_id;
    const key = this.deriveKey(sessionId);
    const canonicalInput = this.getCanonicalInput(request, "params");

    const signature: AcsSignature = {
      algorithm: "HMAC-SHA256",
      value: this.computeMac(key, canonicalInput),
      key_id: this.keyId
    };

    return {
      ...request,
      params: {
        ...request.params,
        signature
      }
    };
  }

  public verifyRequest(request: AcsToolCallRequest): void {
    const signature = request.params.signature;
    if (!signature) {
      throw new SignatureInvalidError("Missing signature in request envelope");
    }
    if (signature.algorithm !== "HMAC-SHA256") {
      throw new SignatureInvalidError(`Unsupported signature algorithm: ${signature.algorithm}`);
    }
    if (signature.key_id !== this.keyId) {
      throw new SignatureInvalidError(`Unknown key_id: ${signature.key_id}`);
    }

    const sessionId = request.params.metadata.session_id;
    const key = this.deriveKey(sessionId);
    const canonicalInput = this.getCanonicalInput(request, "params");
    const expectedMac = this.computeMac(key, canonicalInput);

    const expectedBuffer = Buffer.from(expectedMac, "base64");
    const actualBuffer = this.decodeCanonicalHmacSha256Signature(signature.value);

    if (!crypto.timingSafeEqual(expectedBuffer, actualBuffer)) {
      throw new SignatureInvalidError("Invalid signature value for request");
    }
  }

  public signResponse(response: AcsResponseEnvelope, sessionId: string): AcsResponseEnvelope {
    const key = this.deriveKey(sessionId);
    const canonicalInput = this.getCanonicalInput(response, "result");

    const signature: AcsSignature = {
      algorithm: "HMAC-SHA256",
      value: this.computeMac(key, canonicalInput),
      key_id: this.keyId
    };

    return {
      ...response,
      result: {
        ...response.result,
        signature
      }
    };
  }

  public verifyResponse(response: AcsResponseEnvelope, sessionId: string): void {
    const signature = response.result.signature;
    if (!signature) {
      throw new SignatureInvalidError("Missing signature in response envelope");
    }
    if (signature.algorithm !== "HMAC-SHA256") {
      throw new SignatureInvalidError(`Unsupported signature algorithm: ${signature.algorithm}`);
    }
    if (signature.key_id !== this.keyId) {
      throw new SignatureInvalidError(`Unknown key_id: ${signature.key_id}`);
    }

    const key = this.deriveKey(sessionId);
    const canonicalInput = this.getCanonicalInput(response, "result");
    const expectedMac = this.computeMac(key, canonicalInput);

    const expectedBuffer = Buffer.from(expectedMac, "base64");
    const actualBuffer = this.decodeCanonicalHmacSha256Signature(signature.value);

    if (!crypto.timingSafeEqual(expectedBuffer, actualBuffer)) {
      throw new SignatureInvalidError("Invalid signature value for response");
    }
  }
}
