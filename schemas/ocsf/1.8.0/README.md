# OCSF 1.8.0 vendored subset

`ocsf-1.8.0-subset.json` is a **subset** of the Open Cybersecurity Schema
Framework (OCSF) schema, version **1.8.0**. It is used only by the local
validator in `src/ocsf/validator.ts`.

- **Upstream repository:** https://github.com/ocsf/ocsf-schema
- **Tag / commit:** `v1.8.0` / `6fa6499a0f8c9f449d342816e90e5f687c224b0a`
- **Compiler:** official `ocsf-lib` 0.10.4 (`python -m ocsf.compile`, default options)
- **Extraction script:** [`scripts/ocsf/extract-subset.py`](../../../scripts/ocsf/extract-subset.py)
- **License:** Apache License 2.0 (upstream). See the root [NOTICE](../../../NOTICE).

## Contents

Copied from the compiled schema without semantic change (prose descriptions
dropped):

- classes: `base_event` (class_uid 0), `detection_finding` (class_uid 2004);
- objects: `metadata`, `product`, `finding_info`;
- all OCSF 1.8.0 data types (`*_t`).

For each attribute: `type`, `requirement`, `is_array`, `profile`, and enum ids
with captions. Object `constraints` are kept.

## What this is not

- It is not the complete OCSF 1.8.0 schema.
- It is not the JSON Schema produced by the OCSF Server.
- The JSON Schema used at runtime is generated from this subset by local code
  in `src/ocsf/validator.ts`; that translation is repository code, not an
  OCSF artifact.

## Regenerating

```bash
git clone --depth 1 --branch v1.8.0 https://github.com/ocsf/ocsf-schema.git
pip install ocsf-lib==0.10.4
python -m ocsf.compile ocsf-schema > compiled.json
python scripts/ocsf/extract-subset.py compiled.json > schemas/ocsf/1.8.0/ocsf-1.8.0-subset.json
```
