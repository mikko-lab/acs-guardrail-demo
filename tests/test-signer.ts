import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { ApprovalGrantV1, ApprovalGrantV2 } from "../src/approval-verifier";

type UnsignedApprovalGrant =
  | Omit<ApprovalGrantV1, "signature">
  | Omit<ApprovalGrantV2, "signature">;

type ApprovalSignature = ApprovalGrantV1["signature"];

export class TestSigner {
  constructor(
    private readonly privateKey: crypto.KeyObject,
    private readonly keyId: string
  ) {}

  sign<T extends UnsignedApprovalGrant>(
    grantBase: T
  ): T & { signature: ApprovalSignature } {
    const dataBuffer = Buffer.from(canonicalize(grantBase));
    const signatureValue = crypto
      .sign(null, dataBuffer, this.privateKey)
      .toString("base64");

    return {
      ...grantBase,
      signature: {
        algorithm: "Ed25519",
        key_id: this.keyId,
        value: signatureValue
      }
    };
  }
}
