import Ajv, { ErrorObject, ValidateFunction } from "ajv/dist/2020";
import subset from "../../schemas/ocsf/1.8.0/ocsf-1.8.0-subset.json";
import { OCSF_SCHEMA_VERSION, OcsfValidationIssue } from "./types";

/**
 * Local structural validation against a vendored subset of the compiled
 * OCSF 1.8.0 schema (see schemas/ocsf/1.8.0/README.md).
 *
 * This is NOT the official OCSF validator and NOT the OCSF Server's JSON
 * Schema export. The vendored subset is extracted verbatim from the official
 * schema compiled by the official ocsf-lib compiler; the translation of that
 * subset into JSON Schema below is local code. What it checks:
 *
 * - the event is a vendored class (Base Event 0 or Detection Finding 2004);
 * - every attribute is defined for that class/object in OCSF 1.8.0, with
 *   additional attributes rejected;
 * - required attributes are present;
 * - primitive types, arrays, type regexes/ranges and enum ids;
 * - object constraints (at_least_one / just_one) of vendored objects;
 * - type_uid = class_uid * 100 + activity_id;
 * - enum sibling captions for ids other than 99 (Other);
 * - exporter policy, stricter than OCSF: an integral enum id 99 whose sibling
 *   equals the generic schema caption of 99 (e.g. type_name "Base Event: Other")
 *   is rejected. OCSF Toolkit reports this only as the warning
 *   validation_attribute_enum_sibling_suspicious_other; such an event is not
 *   invalid OCSF in general, but this exporter must not produce it;
 * - metadata.version is 1.8.0.
 *
 * What it deliberately does not do:
 * - profile attributes are rejected (no profiles are declared or vendored);
 * - attributes whose object type is not vendored are rejected even though
 *   they are valid OCSF;
 * - no deprecation, observable or recommended-attribute checks.
 */

interface SubsetAttribute {
  type: string;
  requirement: string;
  is_array: boolean;
  profile?: string;
  enum?: Record<string, string>;
}

interface SubsetRecord {
  caption: string;
  uid?: number;
  constraints?: { at_least_one?: string[]; just_one?: string[] } | null;
  attributes: Record<string, SubsetAttribute>;
}

interface SubsetType {
  type?: string;
  regex?: string;
  max_len?: number;
  range?: [number, number];
  values?: unknown[];
}

interface Subset {
  ocsf_version: string;
  types: Record<string, SubsetType>;
  classes: Record<string, SubsetRecord>;
  objects: Record<string, SubsetRecord>;
}

const SCHEMA = subset as unknown as Subset;

if (SCHEMA.ocsf_version !== OCSF_SCHEMA_VERSION) {
  throw new Error(`Vendored OCSF subset is ${SCHEMA.ocsf_version}, expected ${OCSF_SCHEMA_VERSION}`);
}

export const OCSF_VALIDATION_MODE = "vendored-ocsf-1.8.0-subset-structural" as const;

type JsonSchema = Record<string, unknown> | boolean;

function primitiveSchema(typeName: string): JsonSchema {
  const chain: SubsetType[] = [];
  let current: string | undefined = typeName;
  const seen = new Set<string>();
  while (current && SCHEMA.types[current] && !seen.has(current)) {
    seen.add(current);
    chain.push(SCHEMA.types[current]);
    if (current === "string_t" || current === "integer_t" || current === "long_t" ||
        current === "float_t" || current === "boolean_t" || current === "json_t") {
      break;
    }
    current = SCHEMA.types[current].type;
  }
  const base = current;
  const schema: Record<string, unknown> = {};
  switch (base) {
    case "string_t": schema.type = "string"; break;
    case "integer_t":
    case "long_t": schema.type = "integer"; break;
    case "float_t": schema.type = "number"; break;
    case "boolean_t": schema.type = "boolean"; break;
    case "json_t": break;
    default: return false;
  }
  for (const t of chain) {
    if (t.regex && schema.pattern === undefined) schema.pattern = t.regex;
    if (t.max_len && schema.maxLength === undefined) schema.maxLength = t.max_len;
    if (t.range && schema.minimum === undefined) {
      schema.minimum = t.range[0];
      schema.maximum = t.range[1];
    }
  }
  return schema;
}

function attributeSchema(attr: SubsetAttribute): JsonSchema {
  let item: JsonSchema;
  if (SCHEMA.types[attr.type]) {
    item = primitiveSchema(attr.type);
    if (attr.enum && typeof item === "object") {
      const numeric = item.type === "integer";
      item = { ...item, enum: Object.keys(attr.enum).map(k => (numeric ? Number(k) : k)) };
    }
  } else if (attr.type === "object") {
    // OCSF free-form object (e.g. `unmapped`).
    item = { type: "object" };
  } else if (SCHEMA.objects[attr.type]) {
    item = { $ref: `#/$defs/${attr.type}` };
  } else {
    // Valid OCSF object that is not vendored: reject rather than pass unchecked.
    item = false;
  }
  return attr.is_array ? { type: "array", items: item } : item;
}

function recordSchema(record: SubsetRecord): Record<string, unknown> {
  const properties: Record<string, JsonSchema> = {};
  const required: string[] = [];
  for (const [name, attr] of Object.entries(record.attributes)) {
    if (attr.profile) continue; // profile attributes are not enabled
    properties[name] = attributeSchema(attr);
    if (attr.requirement === "required") required.push(name);
  }
  const schema: Record<string, unknown> = {
    type: "object",
    properties,
    required,
    additionalProperties: false,
  };
  const all: unknown[] = [];
  if (record.constraints?.at_least_one) {
    all.push({ anyOf: record.constraints.at_least_one.map(n => ({ required: [n] })) });
  }
  if (record.constraints?.just_one) {
    all.push({ oneOf: record.constraints.just_one.map(n => ({ required: [n] })) });
  }
  if (all.length > 0) schema.allOf = all;
  return schema;
}

const $defs: Record<string, unknown> = {};
for (const [name, obj] of Object.entries(SCHEMA.objects)) {
  $defs[name] = recordSchema(obj);
}

const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false, unicodeRegExp: false });

const CLASS_VALIDATORS = new Map<number, { record: SubsetRecord; validate: ValidateFunction }>();
for (const record of Object.values(SCHEMA.classes)) {
  if (typeof record.uid !== "number") continue;
  const schema = { $defs, ...recordSchema(record) };
  CLASS_VALIDATORS.set(record.uid, { record, validate: ajv.compile(schema) });
}

/** OCSF class uids this validator can check. */
export const OCSF_VALIDATED_CLASS_UIDS: readonly number[] = Object.freeze([...CLASS_VALIDATORS.keys()].sort((a, b) => a - b));

const SIBLINGS: ReadonlyArray<[string, string]> = [
  ["activity_id", "activity_name"],
  ["category_uid", "category_name"],
  ["class_uid", "class_name"],
  ["type_uid", "type_name"],
  ["severity_id", "severity"],
  ["status_id", "status"],
];

function ajvIssues(errors: ErrorObject[] | null | undefined): OcsfValidationIssue[] {
  return (errors ?? []).map(e => ({
    path: e.instancePath,
    message:
      e.keyword === "additionalProperties"
        ? `has attribute '${(e.params as { additionalProperty: string }).additionalProperty}' not allowed by the vendored OCSF ${OCSF_SCHEMA_VERSION} subset`
        : e.message ?? e.keyword,
  }));
}

/**
 * Validates one OCSF event. Returns an empty list when the event passes the
 * local vendored-subset checks described above.
 */
export function validateOcsfEvent(event: unknown): OcsfValidationIssue[] {
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    return [{ path: "", message: "must be an object" }];
  }
  const e = event as Record<string, unknown>;
  const entry = typeof e.class_uid === "number" ? CLASS_VALIDATORS.get(e.class_uid) : undefined;
  if (!entry) {
    return [{ path: "/class_uid", message: `is not a vendored OCSF ${OCSF_SCHEMA_VERSION} class (${OCSF_VALIDATED_CLASS_UIDS.join(", ")})` }];
  }

  const issues: OcsfValidationIssue[] = [];
  if (!entry.validate(event)) {
    issues.push(...ajvIssues(entry.validate.errors));
  }

  if (typeof e.activity_id === "number" && e.type_uid !== (e.class_uid as number) * 100 + e.activity_id) {
    issues.push({ path: "/type_uid", message: "must equal class_uid * 100 + activity_id" });
  }

  for (const [idName, captionName] of SIBLINGS) {
    const id = e[idName];
    const caption = e[captionName];
    const enumeration = entry.record.attributes[idName]?.enum;
    if (typeof id !== "number" || caption === undefined || !enumeration) {
      continue;
    }
    if (id === 99) {
      const generic = enumeration["99"];
      if (generic !== undefined && caption === generic) {
        issues.push({
          path: `/${captionName}`,
          message: `must carry a source-specific value for ${idName} 99, not the generic caption '${generic}' (exporter policy; OCSF Toolkit: validation_attribute_enum_sibling_suspicious_other warning)`,
        });
      }
      continue;
    }
    if (idName === "type_uid" && id % 100 === 99) {
      continue;
    }
    const expected = enumeration[String(id)];
    if (expected !== undefined && caption !== expected) {
      issues.push({ path: `/${captionName}`, message: `must be '${expected}' for ${idName} ${id}` });
    }
  }

  const metadata = e.metadata as Record<string, unknown> | undefined;
  if (metadata && typeof metadata === "object") {
    if (metadata.version !== OCSF_SCHEMA_VERSION) {
      issues.push({ path: "/metadata/version", message: `must be '${OCSF_SCHEMA_VERSION}'` });
    }
  }

  return issues;
}
