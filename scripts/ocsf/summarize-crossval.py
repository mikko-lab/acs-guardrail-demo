#!/usr/bin/env python3
"""Summarizes an OCSF Toolkit cross-validation run produced by cross-validate.sh.

All counts are computed from the corpus files and Toolkit reports; exit status
is 1 when any default-level error or suspicious_other warning is present.
"""
import collections
import json
import os
import sys

SUSPICIOUS = "validation_attribute_enum_sibling_suspicious_other"
RECOMMENDED = "validation_attribute_recommended_missing"


def findings(report_path):
    with open(report_path) as f:
        return json.load(f).get("validation", {}).get("findings", [])


def main(out):
    with open(os.path.join(out, "local-validation.json")) as f:
        local = {r["name"]: r for r in json.load(f)}
    names = sorted(local)
    classes = collections.Counter()
    errors = warnings = suspicious = local_fail = 0
    warning_codes = collections.Counter()
    recommended = collections.Counter()

    print(f"{'event':42} {'acs event_type':26} class type_uid  local official")
    for name in names:
        with open(os.path.join(out, "events", f"{name}.json")) as f:
            event = json.load(f)
        classes[event["class_uid"]] += 1
        fs = findings(os.path.join(out, "official", "reports", f"{name}.report.json"))
        e = [x for x in fs if x["level"] == "error"]
        w = [x for x in fs if x["level"] == "warning"]
        errors += len(e)
        warnings += len(w)
        suspicious += sum(1 for x in fs if x["code"] == SUSPICIOUS)
        warning_codes.update(x["code"] for x in w)
        local_fail += local[name]["local_validation"] != "PASS"
        for x in findings(os.path.join(out, "official-recommended", "reports", f"{name}.report.json")):
            if x["code"] == RECOMMENDED:
                recommended[x["details"].get("attribute_path")] += 1
        official = "PASS" if not e and not w else f"{len(e)} error(s), {len(w)} warning(s)"
        print(f"{name:42} {event['unmapped']['acs']['event_type']:26} {event['class_uid']:5} "
              f"{event['type_uid']:8}  {local[name]['local_validation']:5} {official}")
        for x in e + w:
            print(f"    {x['level']}: {x['code']} at {x['details'].get('attribute_path')}: {x['message']}")

    print()
    print(f"events: {len(names)}  "
          f"(Base Event: {classes[0]}, Detection Finding: {classes[2004]}, other: {len(names) - classes[0] - classes[2004]})")
    print(f"local validator failures: {local_fail}")
    print(f"official default-level errors: {errors}")
    print(f"official default-level warnings: {warnings} {dict(warning_codes)}")
    print(f"official {SUSPICIOUS}: {suspicious}")
    print(f"informational {RECOMMENDED} (not an error): {sum(recommended.values())} {dict(sorted(recommended.items()))}")
    return 1 if errors or suspicious or local_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
