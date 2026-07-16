#!/usr/bin/env bash
set -euo pipefail

vector_root="${1:-test_vectors/nist_drbg}"
runner="${2:-build/drbg_rsp_runner.exe}"

if [[ ! -x "$runner" && ! -f "$runner" ]]; then
    echo "Test runner not found: $runner" >&2
    exit 1
fi

mapfile -d '' response_files < <(
    find "$vector_root" \
        -type f \
        -name 'Hash_DRBG.rsp' \
        -print0
)

if (( ${#response_files[@]} == 0 )); then
    echo "No Hash_DRBG.rsp files found under: $vector_root" >&2
    exit 1
fi

"$runner" "${response_files[@]}"
