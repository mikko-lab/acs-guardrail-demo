import subset from "../schemas/ocsf/1.8.0/ocsf-1.8.0-subset.json";
import { AuditCollector } from "../src/audit";
import {
  exportAuditToOcsf,
  OCSF_SCHEMA_VERSION,
  OCSF_VALIDATED_CLASS_UIDS,
  OcsfEvent,
  validateOcsfEvent,
} from "../src/ocsf";

function sample(): { base: Record<string, any>; finding: Record<string, any> } {
  const audit = new AuditCollector();
  audit.record("req-1", "guardian_decision", { decision: "allow" });
  audit.record("req-2", "replay_rejected", { session_id: "s", reason_code: "REPLAY_DETECTED" });
  const [base, finding] = exportAuditToOcsf(audit.getEvents()).events.map(e => JSON.parse(JSON.stringify(e)));
  return { base, finding };
}

function messages(event: unknown): string {
  return validateOcsfEvent(event).map(i => `${i.path} ${i.message}`).join("\n");
}

describe("OCSF 1.8.0 vendored-subset validation", () => {
  it("is pinned to OCSF 1.8.0 from the official schema repository", () => {
    expect(OCSF_SCHEMA_VERSION).toBe("1.8.0");
    expect(subset.ocsf_version).toBe("1.8.0");
    expect(subset.source.tag).toBe("v1.8.0");
    expect(subset.source.repository).toBe("https://github.com/ocsf/ocsf-schema");
    expect(OCSF_VALIDATED_CLASS_UIDS).toEqual([0, 2004]);
  });

  it("vendored class definitions match the OCSF 1.8.0 required attributes", () => {
    const required = (cls: keyof typeof subset.classes) =>
      Object.entries(subset.classes[cls].attributes as Record<string, { requirement: string; profile?: string }>)
        .filter(([, a]) => a.requirement === "required" && !a.profile)
        .map(([n]) => n)
        .sort();
    expect(required("base_event")).toEqual(["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"]);
    expect(required("detection_finding")).toEqual([
      "activity_id", "category_uid", "class_uid", "finding_info", "metadata", "severity_id", "time", "type_uid",
    ]);
    expect(subset.classes.detection_finding.uid).toBe(2004);
    expect(subset.classes.base_event.uid).toBe(0);
  });

  it("accepts exported Base Event and Detection Finding", () => {
    const { base, finding } = sample();
    expect(validateOcsfEvent(base)).toEqual([]);
    expect(validateOcsfEvent(finding)).toEqual([]);
  });

  it("rejects a missing required attribute", () => {
    const { base, finding } = sample();
    delete base.time;
    delete finding.finding_info.uid;
    expect(messages(base)).toMatch(/required property 'time'/);
    expect(messages(finding)).toMatch(/finding_info.*required property 'uid'/);
  });

  it("rejects attributes that are not defined for the class", () => {
    const { base } = sample();
    base.acs_event_hash = "x";
    expect(messages(base)).toMatch(/'acs_event_hash' not allowed/);
  });

  it("rejects profile attributes (no profiles enabled), e.g. actor/device/disposition_id", () => {
    for (const [k, v] of [["actor", { user: { name: "x" } }], ["device", { hostname: "h" }], ["disposition_id", 2]] as const) {
      const { finding } = sample();
      finding[k] = v;
      expect(messages(finding)).toMatch(new RegExp(`'${k}' not allowed`));
    }
  });

  it("rejects valid OCSF attributes whose object type is not vendored", () => {
    const { base } = sample();
    base.enrichments = [{ name: "n", value: "v", data: {} }];
    expect(validateOcsfEvent(base).length).toBeGreaterThan(0);
  });

  it("rejects wrong primitive types and out-of-enum ids", () => {
    const { base, finding } = sample();
    base.time = "2026-01-01T00:00:00Z";
    finding.severity_id = 7;
    expect(messages(base)).toMatch(/\/time must be integer/);
    expect(messages(finding)).toMatch(/\/severity_id must be equal to one of the allowed values/);
  });

  it("rejects inconsistent type_uid and enum sibling captions", () => {
    const { finding } = sample();
    finding.type_uid = 200402;
    finding.severity = "Low";
    const m = messages(finding);
    expect(m).toMatch(/type_uid must equal class_uid \* 100 \+ activity_id/);
    expect(m).toMatch(/\/type_name must be 'Detection Finding: Update'/);
    expect(m).toMatch(/\/severity must be 'High'/);
  });

  it("exporter policy: rejects the generic caption as sibling of enum id 99 (type_name 'Base Event: Other')", () => {
    // OCSF Toolkit only warns here (validation_attribute_enum_sibling_suspicious_other);
    // the event is not invalid OCSF in general, but this exporter must not emit it.
    const { base } = sample();
    base.type_name = "Base Event: Other";
    const issues = validateOcsfEvent(base);
    expect(issues).toHaveLength(1);
    expect(issues[0].path).toBe("/type_name");
    expect(issues[0].message).toMatch(/generic caption 'Base Event: Other'/);
    expect(issues[0].message).toMatch(/validation_attribute_enum_sibling_suspicious_other/);
  });

  it("exporter policy: rejects activity_name 'Other' for activity_id 99", () => {
    const { base } = sample();
    base.activity_name = "Other";
    expect(messages(base)).toMatch(/\/activity_name must carry a source-specific value for activity_id 99/);
  });

  it("accepts a source-specific sibling for enum id 99", () => {
    const { base } = sample();
    expect(base.type_uid).toBe(99);
    expect(base.type_name).toBe("Base Event: guardian_decision");
    expect(base.activity_name).toBe("guardian_decision");
    expect(validateOcsfEvent(base)).toEqual([]);
  });

  it("rejects a wrong OCSF metadata.version", () => {
    const { base } = sample();
    base.metadata.version = "1.7.0";
    expect(messages(base)).toMatch(/metadata\/version must be '1.8.0'/);
  });

  it("rejects unknown metadata attributes and enforces product at_least_one(name, uid)", () => {
    const { base } = sample();
    base.metadata.acs_hash = "x";
    delete base.metadata.product.name;
    const m = messages(base);
    expect(m).toMatch(/'acs_hash' not allowed/);
    expect(m).toMatch(/metadata\/product must match a schema in anyOf/);
  });

  it("rejects classes that are not vendored (e.g. API Activity 6003)", () => {
    const { base } = sample();
    base.class_uid = 6003;
    expect(messages(base)).toMatch(/not a vendored OCSF 1.8.0 class/);
    expect(messages(null)).toMatch(/must be an object/);
  });

  it("every exported event validates (validation is part of the export pipeline)", () => {
    const audit = new AuditCollector();
    audit.record("req-1", "tool_execution_completed", { status: "error" });
    audit.record("req-1", "correlation_failed", { session_id: "s", request_id_ref: "r", tool: "t", disposition: "deny", reason: "tool_name_mismatch" });
    const out: OcsfEvent[] = exportAuditToOcsf(audit.getEvents()).events;
    out.forEach(e => expect(validateOcsfEvent(e)).toEqual([]));
  });
});
