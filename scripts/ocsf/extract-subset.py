#!/usr/bin/env python3
"""Extract the OCSF 1.8.0 subset vendored for the ACS -> OCSF export validator.

Input: the JSON produced by the official OCSF compiler (ocsf-lib) from the
official ocsf-schema repository at tag v1.8.0:

    git clone --depth 1 --branch v1.8.0 https://github.com/ocsf/ocsf-schema.git
    pip install ocsf-lib==0.10.4
    python -m ocsf.compile ocsf-schema > compiled.json
    python scripts/ocsf/extract-subset.py compiled.json > schemas/ocsf/1.8.0/ocsf-1.8.0-subset.json

The output keeps, verbatim from the compiled schema, the attribute names,
types, requirement levels, array flags, profile annotations, enum ids and
object constraints of the classes and objects the exporter emits. Prose
descriptions are dropped. Objects not listed in OBJECTS are intentionally
not vendored; the local validator rejects any attribute that would need
them.
"""
import json
import sys

CLASSES = ["base_event", "detection_finding"]
OBJECTS = ["metadata", "product", "finding_info"]

SOURCE = {
    "repository": "https://github.com/ocsf/ocsf-schema",
    "tag": "v1.8.0",
    "commit": "6fa6499a0f8c9f449d342816e90e5f687c224b0a",
    "compiler": "ocsf-lib 0.10.4 (python -m ocsf.compile, default options)",
}


def attributes(attrs):
    out = {}
    for name in sorted(attrs):
        a = attrs[name]
        entry = {
            "type": a.get("type"),
            "requirement": a.get("requirement") or "optional",
            "is_array": bool(a.get("is_array")),
        }
        if a.get("object_type"):
            entry["object_type"] = a["object_type"]
        if a.get("profile"):
            entry["profile"] = a["profile"]
        if a.get("enum"):
            entry["enum"] = {k: v.get("caption") for k, v in sorted(a["enum"].items(), key=lambda kv: int(kv[0]))}
        out[name] = entry
    return out


def main(path):
    with open(path) as f:
        schema = json.load(f)
    if schema.get("version") != "1.8.0":
        raise SystemExit(f"expected OCSF 1.8.0, got {schema.get('version')!r}")

    classes = {}
    for name in CLASSES:
        c = schema["classes"][name]
        classes[name] = {
            "caption": c.get("caption"),
            "uid": c.get("uid"),
            "profiles": sorted(c.get("profiles") or []),
            "constraints": c.get("constraints"),
            "attributes": attributes(c["attributes"]),
        }

    objects = {}
    for name in OBJECTS:
        o = schema["objects"][name]
        objects[name] = {
            "caption": o.get("caption"),
            "constraints": o.get("constraints"),
            "attributes": attributes(o["attributes"]),
        }

    types = {}
    for name in sorted(schema["types"]):
        t = schema["types"][name]
        types[name] = {k: t.get(k) for k in ("type", "regex", "max_len", "range", "values") if t.get(k) is not None}

    out = {
        "ocsf_version": schema["version"],
        "source": SOURCE,
        "note": "Vendored subset of the compiled OCSF 1.8.0 schema. Not the complete schema.",
        "types": types,
        "classes": classes,
        "objects": objects,
    }
    json.dump(out, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
