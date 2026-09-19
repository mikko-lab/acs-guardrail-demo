import Ajv, { ErrorObject } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import * as requestEnvelopeSchema from "../schemas/request-envelope.json";
import * as responseEnvelopeSchema from "../schemas/response-envelope.json";
import * as toolCallRequestSchema from "../schemas/hooks/tool-call-request.json";
import * as toolCallResultSchema from "../schemas/hooks/tool-call-result.json";
import * as askDetailsSchema from "../schemas/ask-details.json";
import * as deferDetailsSchema from "../schemas/defer-details.json";
import * as modificationsSchema from "../schemas/modifications.json";
import * as handshakeSchema from "../schemas/handshake.json";
import * as provenanceSchema from "../schemas/provenance.json";
import { AcsToolCallRequest, AcsResponseEnvelope } from "./acs-types";

export class SchemaValidationError extends Error {
  constructor(public errors: ErrorObject[], message: string) {
    super(message);
    this.name = "SchemaValidationError";
  }
}

export class AddressableSchemaError extends Error {
  constructor(public acsResponse: AcsResponseEnvelope, message: string) {
    super(message);
    this.name = "AddressableSchemaError";
  }
}

export class JsonRpcProtocolError extends Error {
  public code = -32600;
  constructor(message: string) {
    super(message);
    this.name = "JsonRpcProtocolError";
  }
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class SchemaValidator {
  private ajv: Ajv;

  constructor() {
    this.ajv = new Ajv({ 
      allErrors: true, 
      strict: false // required to load multiple draft 2020-12 schemas easily without strict mode complaints
    });
    addFormats(this.ajv);

    // Add all schemas to Ajv so they can resolve cross-references ($ref)
    this.ajv.addSchema(requestEnvelopeSchema, "request-envelope.json");
    this.ajv.addSchema(responseEnvelopeSchema, "response-envelope.json");
    this.ajv.addSchema(toolCallRequestSchema, "hooks/tool-call-request.json");
    this.ajv.addSchema(toolCallResultSchema, "hooks/tool-call-result.json");
    this.ajv.addSchema(askDetailsSchema, "ask-details.json");
    this.ajv.addSchema(deferDetailsSchema, "defer-details.json");
    this.ajv.addSchema(modificationsSchema, "modifications.json");
    this.ajv.addSchema(handshakeSchema, "handshake.json");
    this.ajv.addSchema(provenanceSchema, "provenance.json");
  }

  /**
   * Validates an unknown input as an AcsToolCallRequest.
   * Checks JSON-RPC protocol limits, then checks ACS envelope and payload schemas.
   * Throws JsonRpcProtocolError, AddressableSchemaError, or SchemaValidationError.
   */
  validateRequest(input: unknown): AcsToolCallRequest {
    // 1. JSON-RPC Protocol validation (-32600 boundary)
    if (!input || typeof input !== "object") {
      throw new JsonRpcProtocolError("Invalid Request: Input is not a non-null object");
    }
    const obj = input as Record<string, unknown>;

    if (obj.jsonrpc !== "2.0") {
      throw new JsonRpcProtocolError("Invalid Request: jsonrpc must be exactly '2.0'");
    }
    if (typeof obj.method !== "string") {
      throw new JsonRpcProtocolError("Invalid Request: method must be a string");
    }
    if (typeof obj.id !== "string" && typeof obj.id !== "number") {
      throw new JsonRpcProtocolError("Invalid Request: id must be a string or number");
    }
    if (!obj.params || typeof obj.params !== "object") {
      throw new JsonRpcProtocolError("Invalid Request: params must be a non-null object");
    }

    // 2. ACS Schema validation (Fail closed)
    const isEnvelopeValid = this.ajv.validate("request-envelope.json", input);
    
    const req = input as AcsToolCallRequest;
    let isPayloadValid = true;
    
    if (isEnvelopeValid && req.method === "steps/toolCallRequest") {
      isPayloadValid = this.ajv.validate("hooks/tool-call-request.json", req.params.payload);
    }

    if (!isEnvelopeValid || !isPayloadValid) {
      const errors = this.ajv.errors || [];
      const errorMsg = "Schema validation failed: " + this.ajv.errorsText(errors);

      // 3. Strict UUID requirement for addressable DENY
      const params = obj.params as Record<string, unknown>;
      let validRequestId: string | undefined;

      if (typeof params.request_id === "string" && UUID_REGEX.test(params.request_id)) {
        validRequestId = params.request_id;
      }

      if (validRequestId) {
        // Addressable -> produce explicit DENY response
        const acsResponse: AcsResponseEnvelope = {
          jsonrpc: "2.0",
          id: obj.id as string | number,
          result: {
            type: "final",
            acs_version: "0.1.0",
            request_id: validRequestId,
            decision: "deny",
            reasoning: errorMsg,
            reason_codes: ["schema_validation_failed"]
          }
        };
        
        // 4. Validate the generated response
        this.validateResponse(acsResponse);
        
        throw new AddressableSchemaError(acsResponse, errorMsg);
      } else {
        // Unaddressable (e.g. malformed or missing request_id)
        throw new SchemaValidationError(errors, errorMsg);
      }
    }

    return req;
  }

  /**
   * Validates a response envelope internally produced by Guardian or our schema validator.
   */
  validateResponse(response: unknown): AcsResponseEnvelope {
    const isValid = this.ajv.validate("response-envelope.json", response);
    if (!isValid) {
      throw new SchemaValidationError(this.ajv.errors || [], "Guardian produced an invalid response envelope: " + this.ajv.errorsText(this.ajv.errors));
    }
    return response as AcsResponseEnvelope;
  }
}

