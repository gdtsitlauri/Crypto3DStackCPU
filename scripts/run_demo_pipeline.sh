#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build-linux"
OUT="${ROOT}/results/linux-demo"
mkdir -p "$OUT"

if [[ ! -x "$BUILD/asm_to_hex" ]]; then
  cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD" -j"${JOBS:-2}"
fi

TEXT="$OUT/text.hex"
DATA="$OUT/data.hex"
IMAGE="$OUT/demo.hex"
DECRYPTED="$OUT/decrypted_text.hex"
RESEALED="$OUT/demo_after.hex"
POSTCONTRACT="$OUT/postrun.contract"

"$BUILD/asm_to_hex" "$ROOT/programs/demo.asm" "$TEXT" "$DATA"
"$BUILD/encryptor_single" "$TEXT" "$DATA" "$IMAGE" --deterministic-test-key=2026
"$BUILD/decryptor_single" "$IMAGE" "$TEXT" "$DECRYPTED"
"$BUILD/crypto3d_cpu_test" "$IMAGE" "$ROOT/programs/demo.contract" --write-output "$RESEALED"

awk '
  BEGIN {found=0}
  /^[[:space:]]*signature\.pre_zero[[:space:]]*=/ {print "signature.pre_zero=false"; found=1; next}
  {print}
  END {if (!found) print "signature.pre_zero=false"}
' "$ROOT/programs/demo.contract" > "$POSTCONTRACT"

"$BUILD/crypto3d_cpu_test" "$RESEALED" "$POSTCONTRACT"
sha256sum "$TEXT" "$DATA" "$IMAGE" "$RESEALED" > "$OUT/SHA256SUMS.txt"
printf '\n[DEMO PIPELINE PASSED]\nArtifacts: %s\n' "$OUT"
