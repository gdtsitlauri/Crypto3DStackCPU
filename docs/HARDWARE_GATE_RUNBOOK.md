# Hardware gate runbook (VTF)

This is the "next research gate" from `RESEARCH_STATUS_2026.md`: hardware
evidence for the Vertical Trust Fabric. All code for the gate exists and has
been executed as far as free tools allow; what remains is running the AMD tools.

## One command (Linux with Vivado/Vitis in PATH)

```bash
OSS_CAD_SUITE=/opt/oss-cad-suite PART=xc7a200tfbg676-2 PERIOD=10.0 IMPL=1 \
  bash scripts/run_hardware_gate.sh
```

Outputs go to `results/hardware_eval/`:

| Path | Content |
|---|---|
| `gate_status.txt` | which steps ran / were skipped (missing tools are never counted as passed) |
| `cpp_ctest.log` | C++ regression incl. `vtf_hls_tb` |
| `rtl/` | lint logs, three simulation logs, `attack_campaign.csv`, Yosys estimates |
| `hls/vtf_cmac/sol1/` | HLS csim/csynth/cosim/export reports for the AES-CMAC authenticator |
| `vivado/<top>/` | utilization/timing (synth + impl), power, checkpoints |
| `summary.json`, `summary.md`, `table_vtf_overhead.tex` | paper-ready collected numbers |

Individual steps:

```bash
bash hardware_3d/scripts/run_rtl_validation.sh                       # free tools
vitis_hls -f hardware_3d/scripts/vitis_hls_vtf_cmac.tcl -tclargs xc7a200tfbg676-2 results/hardware_eval/hls 1 1 10.0
vivado -mode batch -source hardware_3d/scripts/vivado_synth.tcl -tclargs xc7a200tfbg676-2 results/hardware_eval/vivado 1 10.0
python3 hardware_3d/scripts/collect_hardware_results.py --results results/hardware_eval
```

Windows (free tools only): `powershell -File hardware_3d\scripts\run_rtl_validation.ps1 -OssCadSuite C:\oss-cad-suite`.

A free WebPACK license covers the Artix-7 parts used here
(xc7a200t AC701 default; `xc7a35ticsg324-1L` for Arty A7-35 also works).

## What was executed on 2026-10-03 (free tools, Windows)

| Step | Tool | Result |
|---|---|---|
| Lint, all synthesizable tops | Verilator 5.053 `-Wall` | 0 warnings |
| `tb_vertical_trust_guard` | Icarus Verilog | PASS |
| `tb_stacked_memory_3d_model` | Icarus Verilog | PASS |
| `tb_vtf_attack_campaign` (15 attacks) | Icarus Verilog | PASS: protected detected 15/15, data preserved 14/15 (bit-flip during write is detected, not prevented); unprotected detected 2/15; no false positive |
| C++ suite (5 existing tests + `vtf_hls_tb`) | zig c++ (clang) | all pass; HLS CMAC matches independent AES-CMAC reference vectors |
| Xilinx 7-series synthesis estimate | Yosys + slang (classic ABC LUT map) | unprotected 106 LUT / 36 FF / 4 RAMB36; protected 473 LUT / 293 FF / 4 RAMB36; guard alone 365 LUT / 257 FF |
| Vivado / Vitis Tcl scripts | Tcl dry run with stubbed AMD commands | all sources resolve; 3 synth + 3 route; HLS csim→csynth→cosim→export |

The Yosys numbers are estimates for sanity checking only; publish the Vivado
numbers from `table_vtf_overhead.tex`.

## Fixes made while bringing the RTL up

1. `tb/tb_vertical_trust_guard.sv` used `sequence` (a SystemVerilog keyword) as a
   signal name and did not compile in any simulator; renamed to `seq_num`.
2. `tb/tb_stacked_memory_3d_model.sv` sampled the one-cycle `denied` pulse after
   it had returned to 0 and therefore always failed; it now captures the response
   in the response cycle.
3. `rtl/stacked_memory_3d_model.sv` could not be mapped to block RAM (2-D array,
   XOR and reset between the array and the read register). It now uses a flat
   array with a pure read register and applies fault masking after it; externally
   visible cycle behavior is unchanged (all three testbenches pass) and it maps to
   4×RAMB36E1. Without this, the Vivado area comparison would have been dominated
   by 131 kbit of LUT/FF memory.
4. `rtl/vertical_trust_guard.sv`: width-clean comparisons (no functional change).
5. New `rtl/crypto3d_unprotected_stack_top.sv` baseline with identical ports, used
   for the overhead difference and the attack campaign.

## Still out of scope of this gate

The CMAC is not in the RTL path (the guard consumes `auth_ok_i` from the HLS
block); the HLS report gives its separate cost/latency. Physical side channels,
glitching, board-level tests and any 3D/TSV silicon remain future work.
