#!/usr/bin/env bash
# Phase-2 validation (roadmap 2.1-2.6), free tools only. Fail-closed.
#
#   2.1 memory encryption + integrity tree : Python reference self-test, lint, tb_memory_integrity
#   2.2 masked AES S-box                   : lint, functional check + simulated TVLA (tvla.py)
#   2.3 fault-injection hardening          : lint/sim of FAULT_HARDEN=1, SEU campaign both variants
#   2.4 PUF fuzzy extractor                : reliability study (Python), lint, tb_puf_fuzzy_extractor
#   2.5 bitstream security                 : constraint file present (board-only check, phase 3)
#   2.6 CPU bridge + SoC                   : lint, program traces from the C++ CPU replayed on RTL
#
# Needs: iverilog/vvp, verilator, python3 with `cryptography`, and for 2.6 the CPU
# binaries from the CMake build (asm_to_hex, encryptor_single, crypto3d_cpu_test).
#
# Usage: hardware_3d/scripts/run_phase2_validation.sh [out_dir] [cpu_bin_dir]
#   env: TVLA_TRACES (default 20000), FI_TRIALS (default 60), FI_EXHAUSTIVE=1 for the
#        full timed-attacker sweep (slow: tens of minutes)
set -euo pipefail
HW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$HW/.." && pwd)"
OUT="${1:-$ROOT/results/hardware_eval/phase2}"
BIN="${2:-$ROOT/build-linux}"
TVLA_TRACES="${TVLA_TRACES:-20000}"
FI_TRIALS="${FI_TRIALS:-60}"
mkdir -p "$OUT"
cd "$HW"

CORE=(rtl/crypto3d_stack_pkg.sv rtl/stacked_memory_3d_model.sv rtl/vertical_trust_guard.sv
      rtl/tier_sentinel_monitor.sv rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/vtf_key_schedule.sv
      rtl/crypto3d_vtf_system_top.sv)
SOC=("${CORE[@]}" rtl/crypto3d_vtf_cpu_bridge.sv rtl/crypto3d_vtf_soc_top.sv)
LINT=(--lint-only -Wall -Wno-TIMESCALEMOD -Wno-IMPORTSTAR -Wno-UNUSEDPARAM)
pass() { grep -q "$1" "$2" || { echo "FAILED: $2"; exit 1; }; }

echo "== Python references"
python3 scripts/mem_integrity_reference.py --self-test | tee "$OUT/mit_reference.log"
pass "SELF-TEST PASS" "$OUT/mit_reference.log"
python3 scripts/puf_fuzzy_extractor.py --study --out "$OUT/puf_study.json" | tee "$OUT/puf_study.log"

echo "== Verilator lint"
verilator "${LINT[@]}" --top-module memory_integrity_tree rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/memory_integrity_tree.sv
verilator "${LINT[@]}" --top-module mit_untrusted_store rtl/mit_untrusted_store.sv
verilator "${LINT[@]}" --top-module aes_sbox_masked rtl/aes_sbox_masked.sv
verilator "${LINT[@]}" --top-module puf_fuzzy_extractor rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/puf_fuzzy_extractor.sv
verilator "${LINT[@]}" -GFAULT_HARDEN=1 --top-module crypto3d_vtf_system_top "${CORE[@]}"
verilator "${LINT[@]}" --top-module crypto3d_vtf_soc_top "${SOC[@]}"

echo "== 2.1 memory integrity tree"
iverilog -g2012 -I tb -o "$OUT/mit.vvp" rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/mit_untrusted_store.sv \
  rtl/memory_integrity_tree.sv tb/tb_memory_integrity.sv
vvp -n "$OUT/mit.vvp" | tee "$OUT/tb_memory_integrity.log"
pass "SV TEST PASS" "$OUT/tb_memory_integrity.log"

echo "== 2.2 masked S-box + simulated TVLA ($TVLA_TRACES traces)"
iverilog -g2012 -Ptb_tvla_sbox.TRACES="$TVLA_TRACES" -o "$OUT/tvla.vvp" rtl/aes_sbox_masked.sv tb/tb_tvla_sbox.sv
vvp -n "$OUT/tvla.vvp" > "$OUT/tvla_traces.log"
pass "SV TEST PASS" "$OUT/tvla_traces.log"
python3 scripts/tvla.py "$OUT/tvla_traces.log" --out "$OUT/tvla_summary.json" | tee "$OUT/tvla.log"
pass "TVLA FIRST-ORDER PASS" "$OUT/tvla.log"

echo "== 2.3 fault hardening"
iverilog -g2012 -I tb -Ptb_vtf_system.FAULT_HARDEN=1 -o "$OUT/sys_ft.vvp" "${CORE[@]}" tb/tb_vtf_system.sv
vvp -n "$OUT/sys_ft.vvp" | tee "$OUT/tb_vtf_system_ft.log"
pass "SV TEST PASS" "$OUT/tb_vtf_system_ft.log"
MODES=(0); [[ "${FI_EXHAUSTIVE:-0}" == "1" ]] && MODES=(0 1)
for H in 0 1; do
  for M in "${MODES[@]}"; do
    iverilog -g2012 -I tb -Ptb_fault_campaign.FAULT_HARDEN=$H -Ptb_fault_campaign.TRIALS="$FI_TRIALS" \
      -Ptb_fault_campaign.MODE=$M -o "$OUT/fi_h${H}_m${M}.vvp" "${CORE[@]}" tb/tb_fault_campaign.sv
    vvp -n "$OUT/fi_h${H}_m${M}.vvp" > "$OUT/fi_h${H}_m${M}.log"
    grep -E '^(FISUM|FITOTAL)' "$OUT/fi_h${H}_m${M}.log"
  done
done
# the hardened design must show no bypass / silent corruption
grep -q "FITOTAL,1,mode=0,.*violations=0," "$OUT/fi_h1_m0.log" || { echo "FAILED: hardened design has violations"; exit 1; }

echo "== 2.4 PUF fuzzy extractor"
python3 scripts/puf_fuzzy_extractor.py --emit-sv "$OUT/puf_vectors.svh" >/dev/null
iverilog -g2012 -I tb -o "$OUT/puf.vvp" rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/puf_fuzzy_extractor.sv \
  tb/tb_puf_fuzzy_extractor.sv
vvp -n "$OUT/puf.vvp" | tee "$OUT/tb_puf.log"
pass "SV TEST PASS" "$OUT/tb_puf.log"

echo "== 2.5 bitstream security constraints (applied by vivado_secure_bitstream.tcl; board test = phase 3)"
test -f constraints/bitstream_security.xdc

echo "== 2.6 CPU bridge + SoC: program traces"
iverilog -g2012 -I tb -o "$OUT/soc.vvp" "${SOC[@]}" tb/tb_vtf_soc.sv
iverilog -g2012 -I tb -Ptb_vtf_soc.FAULT_HARDEN=1 -o "$OUT/soc_ft.vvp" "${SOC[@]}" tb/tb_vtf_soc.sv
if [[ -x "$BIN/asm_to_hex" || -x "$BIN/asm_to_hex.exe" ]]; then
  python3 scripts/vtf_trace_overhead.py --bin-dir "$BIN" --vvp "$OUT/soc.vvp" --vvp-ft "$OUT/soc_ft.vvp" \
    --out "$OUT/soc" | tee "$OUT/soc.log"
  pass "SOC TRACE OVERHEAD PASS" "$OUT/soc.log"
else
  echo "   CPU binaries not found in $BIN (build with scripts/run_core_validation.sh first); skipping"
fi
echo "Phase-2 validation passed. Outputs: $OUT"
