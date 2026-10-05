#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build-linux"
OUT="${ROOT}/results/linux-security-audit"
mkdir -p "$OUT"

"$ROOT/scripts/run_demo_pipeline.sh" >/dev/null
CLEAN="$ROOT/results/linux-demo/demo.hex"
CPU="$BUILD/crypto3d_cpu_test"
CONTRACT="$ROOT/programs/demo.contract"

cp "$CLEAN" "$OUT/clean.hex"

python3 - "$CLEAN" "$OUT" <<'PY'
import sys
from pathlib import Path
src=Path(sys.argv[1]); out=Path(sys.argv[2])
words=[int(x.strip(),16) for x in src.read_text().splitlines() if x.strip()]

def write(name, idx, mask):
    w=words.copy(); w[idx]^=mask
    (out/name).write_text('\n'.join(f'{x:08X}' for x in w)+'\n')

text_start=words[4]
write('tamper_text.hex', text_start, 0x1)
write('tamper_wrapped_key.hex', 12, 0x1)
write('tamper_image_tag.hex', 20, 0x1)
PY

expect_reject() {
  local file="$1"
  if "$CPU" "$file" "$CONTRACT" >"$file.log" 2>&1; then
    echo "[FAIL] tampered image unexpectedly accepted: $file"
    cat "$file.log"
    return 1
  fi
  echo "[PASS] rejected tampered image: $(basename "$file")"
}

expect_reject "$OUT/tamper_text.hex"
expect_reject "$OUT/tamper_wrapped_key.hex"
expect_reject "$OUT/tamper_image_tag.hex"
sha256sum "$OUT"/*.hex > "$OUT/SHA256SUMS.txt"
echo "[LINUX SECURITY AUDIT PASSED]"
