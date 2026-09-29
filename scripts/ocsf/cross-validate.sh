#!/usr/bin/env bash
# Cross-validates representative exporter output with the official OCSF Toolkit.
#
#   scripts/ocsf/setup-crossval-toolchain.sh   # once
#   scripts/ocsf/cross-validate.sh
#
# Override the toolchain with OCSF_TOOLKIT=<binary> OCSF_SCHEMA=<compiled schema json>;
# the schema must still match the pinned SHA-256 in crossval-pins.sh.
# Exit status is non-zero if the Toolkit reports any error, or any
# validation_attribute_enum_sibling_suspicious_other warning, at default levels.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=crossval-pins.sh
. "$SCRIPT_DIR/crossval-pins.sh"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASE="${OCSF_CROSSVAL_DIR:-$ROOT/.ocsf-crossval}"
TOOLKIT="${OCSF_TOOLKIT:-$BASE/toolchain/ocsf-toolkit}"
SCHEMA="${OCSF_SCHEMA:-$BASE/toolchain/ocsf-schema-v1.8.0.json}"
OUT="$BASE/run"

for f in "$TOOLKIT" "$SCHEMA"; do
  [ -e "$f" ] || { echo "error: $f not found; run scripts/ocsf/setup-crossval-toolchain.sh" >&2; exit 2; }
done

# Refuse to validate against any schema artifact other than the pinned one.
schema_sha="$(verify_schema_sha "$SCHEMA")"
echo "schema: $SCHEMA (sha256 $schema_sha, matches pin)"

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$ROOT"

# 1. Corpus from the current exporter (exportAuditToOcsf), plus local validation baseline.
npx ts-node scripts/ocsf/generate-crossval-corpus.ts "$OUT/events"

# 2. Official validation at default levels (no enrichment: events are not mutated).
"$TOOLKIT" --schema "$SCHEMA" --events-dir "$OUT/events" --validate --output-dir "$OUT/official"

# 3. Informational run: missing recommended attributes (default: ignored) enabled as warnings.
"$TOOLKIT" --schema "$SCHEMA" --events-dir "$OUT/events" --validate \
  --validation-level validation_attribute_recommended_missing=warning --output-dir "$OUT/official-recommended"

# 4. Summary computed from the reports.
python3 scripts/ocsf/summarize-crossval.py "$OUT"
