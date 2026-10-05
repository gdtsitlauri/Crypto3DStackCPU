#!/usr/bin/env bash
# One-command hardware research gate for Crypto3DStackCPU / VTF.
#
#   1. C++ regression (CMake/CTest), including the HLS CMAC testbench
#   2. RTL validation: Verilator lint, Icarus simulation, 15-attack campaign
#   3. Vitis HLS: csim -> csynth -> cosim -> Vivado synthesis of the CMAC
#   4. Vivado out-of-context PPA: unprotected vs VTF-protected vs guard
#   5. Collect everything into results/hardware_eval/summary.{json,md}
#      and table_vtf_overhead.tex
#
# Tools are detected; a missing tool skips its step and is recorded in
# gate_status.txt (never silently treated as passed). Any executed step that
# fails stops the run.
#
# Environment overrides:
#   OUT=results/hardware_eval  PART=xc7a200tfbg676-2  PERIOD=10.0  IMPL=1
#   OSS_CAD_SUITE=/path/to/oss-cad-suite   (sourced for verilator/iverilog/yosys)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-$ROOT/results/hardware_eval}"
PART="${PART:-xc7a200tfbg676-2}"
PERIOD="${PERIOD:-10.0}"
IMPL="${IMPL:-1}"
mkdir -p "$OUT"
STATUS="$OUT/gate_status.txt"
: > "$STATUS"
note() { echo "$1" | tee -a "$STATUS"; }

if [[ -n "${OSS_CAD_SUITE:-}" ]]; then
  # shellcheck disable=SC1091
  source "$OSS_CAD_SUITE/environment"
fi

# 1. C++ regression
if command -v cmake >/dev/null; then
  cmake -S . -B "$OUT/cpp_build" -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$OUT/cpp_build" -j"$(nproc 2>/dev/null || echo 2)"
  ctest --test-dir "$OUT/cpp_build" --output-on-failure | tee "$OUT/cpp_ctest.log"
  note "cpp_regression=passed"
else
  note "cpp_regression=skipped (cmake not found)"
fi

# 2. RTL validation
if command -v verilator >/dev/null && command -v iverilog >/dev/null; then
  bash hardware_3d/scripts/run_rtl_validation.sh "$OUT/rtl"
  note "rtl_validation=passed"
  bash hardware_3d/scripts/run_phase2_validation.sh "$OUT/phase2" "$OUT/cpp_build"
  note "phase2_validation=passed"
else
  note "rtl_validation=skipped (verilator/iverilog not found; set OSS_CAD_SUITE)"
fi

# 3. Vitis HLS
HLS_ARGS=("$PART" "$OUT/hls" 1 1 "$PERIOD")
if command -v vitis_hls >/dev/null; then
  vitis_hls -f hardware_3d/scripts/vitis_hls_vtf_cmac.tcl -tclargs "${HLS_ARGS[@]}" | tee "$OUT/hls_run.log"
  note "hls_cmac=ran (vitis_hls)"
elif command -v vitis-run >/dev/null; then
  C3D_PART="$PART" C3D_HLS_OUT="$OUT/hls" C3D_COSIM=1 C3D_RTL_SYNTH=1 C3D_PERIOD="$PERIOD" \
    vitis-run --mode hls --tcl hardware_3d/scripts/vitis_hls_vtf_cmac.tcl | tee "$OUT/hls_run.log"
  note "hls_cmac=ran (vitis-run)"
else
  note "hls_cmac=skipped (vitis_hls / vitis-run not found)"
fi

# 4. Vivado PPA
if command -v vivado >/dev/null; then
  vivado -mode batch -nojournal -nolog -source hardware_3d/scripts/vivado_synth.tcl \
    -tclargs "$PART" "$OUT/vivado" "$IMPL" "$PERIOD" | tee "$OUT/vivado_run.log"
  note "vivado_ppa=ran (impl=$IMPL)"
else
  note "vivado_ppa=skipped (vivado not found)"
fi

# 5. Collect
python3 hardware_3d/scripts/collect_hardware_results.py --results "$OUT"
note "collected=$OUT/summary.json"
cat "$STATUS"
