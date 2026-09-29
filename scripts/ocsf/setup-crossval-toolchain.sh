#!/usr/bin/env bash
# Builds the official OCSF toolchain used for cross-validation, pinned in
# crossval-pins.sh:
#   OCSF schema         ocsf/ocsf-schema  v1.8.0  (6fa6499a0f8c9f449d342816e90e5f687c224b0a)
#   Schema compiler     ocsf-schema-compiler 1.1.1 (PyPI) on CPython 3.14.7
#   Validator           ocsf/ocsf-toolkit v0.9.0  (a99619fcd148791a6a9fe5f82c1e0d839f658591)
#
# Fails (non-zero exit) if a checkout, the compiler venv or the compiled schema
# SHA-256 does not match the pins.
#
# Requires: git, go >= 1.25, uv (a version that can install CPython 3.14.7),
# and sha256sum (Linux) or shasum (macOS).
# Output (git-ignored): .ocsf-crossval/toolchain/{ocsf-toolkit,ocsf-schema-v1.8.0.json}
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=crossval-pins.sh
. "$SCRIPT_DIR/crossval-pins.sh"

ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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

# Prints "<python version> <compiler version>" as installed in compiler-venv.
venv_versions() {
  compiler-venv/bin/python -c 'import importlib.metadata as m, platform; print(platform.python_version(), m.version("ocsf-schema-compiler"))' 2>/dev/null
}

checkout https://github.com/ocsf/ocsf-schema.git "ocsf-schema-$SCHEMA_TAG" "$SCHEMA_TAG" "$SCHEMA_COMMIT"
checkout https://github.com/ocsf/ocsf-toolkit.git ocsf-toolkit-src "$TOOLKIT_TAG" "$TOOLKIT_COMMIT"

(cd ocsf-toolkit-src && go build -o "$WORK/ocsf-toolkit" ./cmd/ocsf-toolkit)

expected_versions="$PYTHON_VERSION $COMPILER_VERSION"
if [ "$(venv_versions || true)" != "$expected_versions" ]; then
  # Missing or not matching the pins: rebuild. compiler-venv lives only under $WORK.
  rm -rf "$WORK/compiler-venv"
  rebuild_failed() {
    echo "error: cannot rebuild compiler venv with CPython $PYTHON_VERSION and ocsf-schema-compiler $COMPILER_VERSION using $(uv --version 2>/dev/null || echo 'uv (not found)'); a uv release that can install CPython $PYTHON_VERSION is required" >&2
    exit 1
  }
  uv python install "$PYTHON_VERSION" >/dev/null || rebuild_failed
  uv venv --quiet --python "$PYTHON_VERSION" compiler-venv || rebuild_failed
  VIRTUAL_ENV="$WORK/compiler-venv" uv pip install --quiet "ocsf-schema-compiler==$COMPILER_VERSION" || rebuild_failed
fi
installed_versions="$(venv_versions || true)"
if [ "$installed_versions" != "$expected_versions" ]; then
  echo "error: compiler venv has '${installed_versions:-unknown}', expected '$expected_versions' (python compiler)" >&2
  exit 1
fi
read -r installed_python installed_compiler <<<"$installed_versions"

compiler-venv/bin/ocsf-schema-compiler "ocsf-schema-$SCHEMA_TAG" > ocsf-schema-v1.8.0.json 2> compile.log
schema_sha="$(verify_schema_sha ocsf-schema-v1.8.0.json)"

echo "python:   CPython $installed_python (compiler-venv)"
echo "compiler: ocsf-schema-compiler $installed_compiler (compiler-venv)"
echo "schema:   ocsf-schema $SCHEMA_TAG $SCHEMA_COMMIT -> $WORK/ocsf-schema-v1.8.0.json (sha256 $schema_sha, matches pin)"
echo "toolkit:  ocsf-toolkit $TOOLKIT_TAG $TOOLKIT_COMMIT -> $WORK/ocsf-toolkit"
