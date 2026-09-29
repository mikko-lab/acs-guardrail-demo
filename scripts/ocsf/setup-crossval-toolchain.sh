#!/usr/bin/env bash
# Builds the official OCSF toolchain used for cross-validation, pinned to:
#   OCSF schema         ocsf/ocsf-schema  v1.8.0  (6fa6499a0f8c9f449d342816e90e5f687c224b0a)
#   Schema compiler     ocsf-schema-compiler 1.1.1 (PyPI) on CPython 3.14.7
#   Validator           ocsf/ocsf-toolkit v0.9.0  (a99619fcd148791a6a9fe5f82c1e0d839f658591)
#
# Requires: git, go >= 1.25, uv (a version that can install CPython 3.14.7).
# Output (git-ignored): .ocsf-crossval/toolchain/{ocsf-toolkit,ocsf-schema-v1.8.0.json}
set -euo pipefail

SCHEMA_TAG="v1.8.0"
SCHEMA_COMMIT="6fa6499a0f8c9f449d342816e90e5f687c224b0a"
TOOLKIT_TAG="v0.9.0"
TOOLKIT_COMMIT="a99619fcd148791a6a9fe5f82c1e0d839f658591"
COMPILER_VERSION="1.1.1"
PYTHON_VERSION="3.14.7"
# sha256 of the compiled schema observed with the pins above (also identical under 3.14.0rc2).
SCHEMA_JSON_SHA256="1df1c2e9c023cc8767717844ab9b60f1071defa7d8994b89fc2c102b92f6fada"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${OCSF_CROSSVAL_DIR:-$ROOT/.ocsf-crossval}/toolchain"
mkdir -p "$WORK"
cd "$WORK"

checkout() { # repo dir tag commit
  if [ ! -d "$2/.git" ]; then
    git clone --quiet --single-branch --branch "$3" "$1" "$2"
  fi
  local actual
  actual="$(git -C "$2" rev-parse HEAD)"
  if [ "$actual" != "$4" ]; then
    echo "error: $2 is at $actual, expected $4 ($3)" >&2
    exit 1
  fi
}

checkout https://github.com/ocsf/ocsf-schema.git "ocsf-schema-$SCHEMA_TAG" "$SCHEMA_TAG" "$SCHEMA_COMMIT"
checkout https://github.com/ocsf/ocsf-toolkit.git ocsf-toolkit-src "$TOOLKIT_TAG" "$TOOLKIT_COMMIT"

(cd ocsf-toolkit-src && go build -o "$WORK/ocsf-toolkit" ./cmd/ocsf-toolkit)

uv python install "$PYTHON_VERSION" >/dev/null
[ -x compiler-venv/bin/ocsf-schema-compiler ] || {
  uv venv --quiet --python "$PYTHON_VERSION" compiler-venv
  VIRTUAL_ENV="$WORK/compiler-venv" uv pip install --quiet "ocsf-schema-compiler==$COMPILER_VERSION"
}
compiler-venv/bin/ocsf-schema-compiler "ocsf-schema-$SCHEMA_TAG" > ocsf-schema-v1.8.0.json 2> compile.log

actual_sha="$(sha256sum ocsf-schema-v1.8.0.json | cut -d' ' -f1)"
if [ "$actual_sha" != "$SCHEMA_JSON_SHA256" ]; then
  echo "warning: compiled schema sha256 $actual_sha differs from recorded $SCHEMA_JSON_SHA256" >&2
fi

echo "python:   $(compiler-venv/bin/python --version)"
echo "compiler: ocsf-schema-compiler $COMPILER_VERSION"
echo "schema:   ocsf-schema $SCHEMA_TAG $SCHEMA_COMMIT -> $WORK/ocsf-schema-v1.8.0.json ($actual_sha)"
echo "toolkit:  ocsf-toolkit $TOOLKIT_TAG $TOOLKIT_COMMIT -> $WORK/ocsf-toolkit"
