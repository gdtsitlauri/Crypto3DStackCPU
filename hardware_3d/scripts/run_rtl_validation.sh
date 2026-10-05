#!/usr/bin/env bash
# RTL validation for the Vertical Trust Fabric (free tools only).
#
#   1. Verilator -Wall lint of every synthesizable top (must be warning-free)
#   2. Icarus Verilog simulation of five testbenches (fail-closed):
#        tb_vertical_trust_guard, tb_stacked_memory_3d_model,
#        tb_vtf_attack_campaign  (15 attacks, protected vs unprotected),
#        tb_aes_cmac32           (FIPS-197 / SP 800-38B / HLS known answers),
#        tb_vtf_system           (integrated in-RTL CMAC system, 26 scenarios,
#                                 vectors from scripts/vtf_reference.py)
#   3. Optional Yosys (+slang) Xilinx 7-series synthesis estimate
#   4. Optional SymbiYosys formal proof of the guard + mutation check (formal/)
#
# Tools: verilator, iverilog/vvp, optional yosys with the slang plugin, optional sby.
# The OSS CAD Suite (https://github.com/YosysHQ/oss-cad-suite-build) provides
# all of them: `source oss-cad-suite/environment` first.
#
# Usage: hardware_3d/scripts/run_rtl_validation.sh [out_dir]
set -euo pipefail
HW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$HW/.." && pwd)"
OUT="${1:-$ROOT/results/hardware_eval/rtl}"
mkdir -p "$OUT"
cd "$HW"

CORE=(rtl/crypto3d_stack_pkg.sv rtl/stacked_memory_3d_model.sv rtl/vertical_trust_guard.sv
      rtl/tier_sentinel_monitor.sv rtl/crypto3d_secure_stack_top.sv rtl/crypto3d_unprotected_stack_top.sv)
SYS=("${CORE[@]}" rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/vtf_key_schedule.sv rtl/crypto3d_vtf_system_top.sv)
LINT_FLAGS=(--lint-only -Wall -Wno-TIMESCALEMOD -Wno-IMPORTSTAR -Wno-UNUSEDPARAM)

{
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "verilator=$(verilator --version 2>&1 | head -1)"
  echo "iverilog=$(iverilog -V 2>&1 | head -1)"
  command -v yosys >/dev/null && echo "yosys=$(yosys -V 2>&1 | head -1)" || echo "yosys=unavailable"
} > "$OUT/tool_versions.txt"

echo "== Verilator lint"
for top in crypto3d_secure_stack_top crypto3d_unprotected_stack_top tier_sentinel_monitor; do
  verilator "${LINT_FLAGS[@]}" --top-module "$top" "${CORE[@]}" 2>&1 | tee "$OUT/lint_$top.log"
done
verilator "${LINT_FLAGS[@]}" --top-module crypto3d_vtf_system_top "${SYS[@]}" 2>&1 | tee "$OUT/lint_crypto3d_vtf_system_top.log"

echo "== Icarus simulation"
for tb in tb_vertical_trust_guard tb_stacked_memory_3d_model tb_vtf_attack_campaign; do
  iverilog -g2012 -o "$OUT/$tb.vvp" "${CORE[@]}" "tb/$tb.sv"
  vvp -n "$OUT/$tb.vvp" | tee "$OUT/$tb.log"
  grep -q "\[SV TEST PASS\]" "$OUT/$tb.log" || { echo "FAILED: $tb"; exit 1; }
done
grep -E '^CAMPAIGN(_HEADER)?,' "$OUT/tb_vtf_attack_campaign.log" | sed 's/^CAMPAIGN_HEADER,//; s/^CAMPAIGN,//' \
  > "$OUT/attack_campaign.csv"
for tb in tb_aes_cmac32 tb_vtf_system; do
  iverilog -g2012 -I tb -o "$OUT/$tb.vvp" "${SYS[@]}" "tb/$tb.sv"
  vvp -n "$OUT/$tb.vvp" | tee "$OUT/$tb.log"
  grep -q "\[SV TEST PASS\]" "$OUT/$tb.log" || { echo "FAILED: $tb"; exit 1; }
done
grep -E '^CAMPAIGN(_HEADER)?,' "$OUT/tb_vtf_system.log" | sed 's/^CAMPAIGN_HEADER,//; s/^CAMPAIGN,//' \
  > "$OUT/system_campaign.csv"
grep -E '^METRIC,' "$OUT/tb_vtf_system.log" | sed 's/^METRIC,//' > "$OUT/system_metrics.csv"

if command -v yosys >/dev/null && yosys -m slang -p "help read_slang" >/dev/null 2>&1; then
  echo "== Yosys xc7 synthesis estimate"
  for top in vertical_trust_guard crypto3d_unprotected_stack_top crypto3d_secure_stack_top aes_cmac32 crypto3d_vtf_system_top; do
    yosys -q -m slang -p "read_slang ${SYS[*]} --top $top; synth_xilinx -family xc7 -top $top -noiopad -noclkbuf; tee -q -o $OUT/yosys_$top.stat stat"
    grep -E '^\s+[0-9]+\s+(cells|\$lut|LUT[1-6]|FDRE|FDSE|RAMB36E1|RAMB18E1|CARRY4)\s*$' "$OUT/yosys_$top.stat" || true
  done
else
  echo "== Yosys with slang plugin not found; skipping synthesis estimate"
fi
if command -v sby >/dev/null; then
  echo "== SymbiYosys formal proof of vertical_trust_guard (+ cover, mutation check)"
  (cd "$HW/formal" && sby -f vertical_trust_guard.sby prove prove_ft cover | tee "$OUT/formal_sby.log" | grep -E 'DONE|summary')
  grep -q "vertical_trust_guard_prove.*DONE (PASS" "$OUT/formal_sby.log" || { echo "FAILED: formal prove"; exit 1; }
  grep -q "vertical_trust_guard_cover.*DONE (PASS" "$OUT/formal_sby.log" || { echo "FAILED: formal cover"; exit 1; }
  grep -q "vertical_trust_guard_prove_ft.*DONE (PASS" "$OUT/formal_sby.log" || { echo "FAILED: formal prove_ft"; exit 1; }
  (cd "$HW/formal" && python3 run_mutation_check.py | tee "$OUT/formal_mutation.log")
  grep -q "FORMAL MUTATION CHECK PASS" "$OUT/formal_mutation.log" || { echo "FAILED: mutation check"; exit 1; }
  cp "$HW/formal/mutation_results.json" "$OUT/formal_mutation_results.json"
else
  echo "== sby not found; skipping formal proof"
fi
echo "RTL validation passed. Outputs: $OUT"
