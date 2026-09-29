import { AuditEventType, AuditEvent } from "../acs-types";
import { AuditIntegrityResult } from "../audit";
import { IncidentSeverity, IncidentType } from "../incident-evidence";

/**
 * The single OCSF schema version this exporter targets. Every exported event
 * carries it in `metadata.version`, and the local validator is built from a
 * vendored subset of this exact version.
 */
export const OCSF_SCHEMA_VERSION = "1.8.0" as const;

/** Identifier of the ACS provenance block carried in `unmapped.acs`. */
export const ACS_OCSF_PROVENANCE_SCHEMA = "acs-guardrail-demo/ocsf-provenance/v1" as const;

/** Prefix of the deterministic OCSF `metadata.uid` derived from the ACS `event_hash`. */
export const ACS_OCSF_EVENT_UID_PREFIX = "acs-audit-event:sha256:" as const;

export interface OcsfProduct {
  name: string;
  version: string;
}

export interface OcsfMetadata {
  version: typeof OCSF_SCHEMA_VERSION;
  product: OcsfProduct;
  /** Deterministic export event UID, derived from the ACS `event_hash`. */
  uid: string;
  /** ACS `request_id`; omitted for the ACS "unknown" request sentinel. */
  correlation_uid?: string;
  /** ACS `event_type`. */
  event_code: string;
  /** ACS source timestamp string, byte-for-byte. */
  original_time: string;
  /** Zero-based position of the source event in the verified ACS chain. */
  sequence: number;
}

/**
 * Reference back to the ACS source evidence. The hashes here are ACS hashes
 * over the ACS canonical event; they are NOT hashes of the OCSF representation.
 */
export interface AcsProvenance {
  provenance_schema: typeof ACS_OCSF_PROVENANCE_SCHEMA;
  event_type: AuditEventType;
  request_id: string;
  timestamp: string;
  previous_hash: string;
  event_hash: string;
  hash_algorithm: "SHA-256";
  hash_canonicalization: "RFC 8785 JSON canonicalization";
  chain_index: number;
  /** Allowlisted source metadata only. Absent when nothing passed the allowlist. */
  metadata?: Record<string, AllowlistedMetadataValue>;
  /** Number of source metadata keys that were not exported. */
  omitted_metadata_key_count: number;
  /** Present only on Detection Findings, taken from `IncidentClassifier`. */
  incident?: AcsIncidentReference;
}

export type AllowlistedMetadataValue = string | number | boolean | string[];

export interface AcsIncidentReference {
  classifier: "IncidentClassifier";
  envelope_version: "1";
  incident_id: string;
  incident_type: IncidentType;
  severity: IncidentSeverity;
  disposition: string;
  requires_human_review: boolean;
}

interface OcsfEventCommon {
  category_name: string;
  class_name: string;
  activity_name: string;
  type_name: string;
  severity_id: number;
  severity: string;
  time: number;
  message: string;
  metadata: OcsfMetadata;
  unmapped: { acs: AcsProvenance };
}

/** OCSF 1.8.0 Base Event (class_uid 0) representation of an ACS audit event. */
export interface OcsfBaseEvent extends OcsfEventCommon {
  class_uid: 0;
  category_uid: 0;
  activity_id: 99;
  type_uid: 99;
  status_id?: number;
  status?: string;
}

/** OCSF 1.8.0 Detection Finding (class_uid 2004) for a classified ACS incident. */
export interface OcsfDetectionFinding extends OcsfEventCommon {
  class_uid: 2004;
  category_uid: 2;
  activity_id: 1;
  type_uid: 200401;
  finding_info: {
    uid: string;
    title: string;
    types: string[];
  };
}

export type OcsfEvent = OcsfBaseEvent | OcsfDetectionFinding;

export interface OcsfExportOptions {
  /** Separately trusted ACS head hash. Enables truncation / head-replacement detection. */
  expectedHeadHash?: string;
  /** Refuse to export unless `expectedHeadHash` is supplied. Default false. */
  requireTrustedHead?: boolean;
}

export interface OcsfExportResult {
  ocsf_version: typeof OCSF_SCHEMA_VERSION;
  /**
   * "structural": only the supplied chain was checked; a structurally valid
   * prefix of a longer stream passes. "trusted_head": the final `event_hash`
   * also matched the caller-supplied trusted head.
   */
  integrity: "structural" | "trusted_head";
  source_event_count: number;
  /** Head `event_hash` of the verified ACS stream, or null for an empty stream. */
  source_head_hash: string | null;
  events: OcsfEvent[];
}

export class OcsfExportIntegrityError extends Error {
  readonly result: Extract<AuditIntegrityResult, { valid: false }>;

  constructor(result: Extract<AuditIntegrityResult, { valid: false }>) {
    super(`OCSF export refused: ACS audit integrity verification failed at event ${result.index}: ${result.reason}`);
    this.name = "OcsfExportIntegrityError";
    this.result = result;
  }
}

export class OcsfTrustedHeadRequiredError extends Error {
  constructor() {
    super("OCSF export refused: requireTrustedHead is set but no expectedHeadHash was supplied");
    this.name = "OcsfTrustedHeadRequiredError";
  }
}

export class OcsfMappingError extends Error {
  constructor(readonly index: number, readonly reason: string) {
    super(`OCSF export refused: ACS event ${index} cannot be mapped: ${reason}`);
    this.name = "OcsfMappingError";
  }
}

export interface OcsfValidationIssue {
  path: string;
  message: string;
}

export class OcsfValidationError extends Error {
  constructor(readonly index: number, readonly issues: OcsfValidationIssue[]) {
    super(
      `OCSF export refused: event ${index} failed local OCSF ${OCSF_SCHEMA_VERSION} subset validation: ` +
        issues.map(i => `${i.path || "/"} ${i.message}`).join("; ")
    );
    this.name = "OcsfValidationError";
  }
}

/** Frozen, verified source events handed to the mapper. */
export type VerifiedAuditEvent = Readonly<AuditEvent> & {
  readonly previous_hash: string;
  readonly event_hash: string;
};
