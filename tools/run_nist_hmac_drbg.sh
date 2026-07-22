#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"

BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"
VECTOR_DIR="${NIST_DRBG_VECTOR_DIR:-$PROJECT_ROOT/test_vectors/nist_drbg}"
RUNNER="$BUILD_DIR/hmac_drbg_rsp_runner.exe"

if [[ ! -x "$RUNNER" ]]; then
    echo "Runner not found: $RUNNER" >&2
    echo "Build the hmac_drbg_rsp_runner target first." >&2
    exit 1
fi

mapfile -d '' RESPONSE_FILES < <(
    find "$VECTOR_DIR" \
        -type f \
        -name 'HMAC_DRBG.rsp' \
        -print0
)

if [[ ${#RESPONSE_FILES[@]} -eq 0 ]]; then
    echo "No HMAC_DRBG.rsp files found under: $VECTOR_DIR" >&2
    exit 1
fi

"$RUNNER" "${RESPONSE_FILES[@]}"