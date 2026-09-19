import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { ApprovalGrantV1 } from "../src/approval-verifier";

export class TestSigner {
  constructor(
    private readonly privateKey: crypto.KeyObject,
    private readonly keyId: string
  ) {}

  sign(grantBase: Omit<ApprovalGrantV1, "signature">): ApprovalGrantV1 {
    const dataBuffer = Buffer.from(canonicalize(grantBase));
    const signatureValue = crypto.sign(null, dataBuffer, this.privateKey).toString("base64");

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
