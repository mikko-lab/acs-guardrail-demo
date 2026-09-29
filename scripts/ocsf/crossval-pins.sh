# Pinned official OCSF toolchain for cross-validation. Sourced by
# setup-crossval-toolchain.sh and cross-validate.sh; not executable on its own.
SCHEMA_TAG="v1.8.0"
SCHEMA_COMMIT="6fa6499a0f8c9f449d342816e90e5f687c224b0a"
TOOLKIT_TAG="v0.9.0"
TOOLKIT_COMMIT="a99619fcd148791a6a9fe5f82c1e0d839f658591"
COMPILER_VERSION="1.1.1"
PYTHON_VERSION="3.14.7"
# sha256 of ocsf-schema-compiler output for the pins above.
SCHEMA_JSON_SHA256="1df1c2e9c023cc8767717844ab9b60f1071defa7d8994b89fc2c102b92f6fada"

# sha256_of FILE: prints the hex SHA-256 of FILE (Linux sha256sum, macOS shasum).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    echo "error: neither sha256sum nor shasum is available to hash $1" >&2
    return 1
  fi
}

# verify_schema_sha FILE: fails unless FILE has the pinned SHA-256.
verify_schema_sha() {
  local actual
  actual="$(sha256_of "$1")" || return 1
  if [ "$actual" != "$SCHEMA_JSON_SHA256" ]; then
    echo "error: compiled OCSF schema $1 does not match the pinned artifact" >&2
    echo "  expected sha256: $SCHEMA_JSON_SHA256" >&2
    echo "  actual sha256:   $actual" >&2
    return 1
  fi
  echo "$actual"
}
