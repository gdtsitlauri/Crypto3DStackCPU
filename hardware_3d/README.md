# hardware_3d

This directory contains the hardware-oriented 3D stacked-memory readiness package for Crypto3DStackCPU.

## Contents

```text
constraints/      FPGA and TSV/floorplan templates
rtl/              SystemVerilog-level 3D memory, VTF guard, protected and unprotected tops
tb/               testbenches: guard, memory, 15-attack campaign, integrated system (26 scenarios),
                  memory integrity tree, masked S-box/TVLA, PUF, fault injection, CPU SoC
scripts/          RTL validation (sh/ps1), Vivado PPA and Vitis HLS Tcl, results collector
docs/             architecture and scope notes
fabrication/      PDK/foundry/GDSII readiness checklists
formal/           SymbiYosys proof of the VTF guard (P1-P8) + mutation check
stack_config.json high-level 4-layer stack description
tsv_layer_map.csv TSV/channel mapping metadata
```

## Layer roles

```text
Layer 0: encrypted text + secure header compatibility image
Layer 1: data-plane / cache-layer separation
Layer 2: key and security metadata
Layer 3: tamper sentinels and redundancy metadata
```

## Running

See `../docs/HARDWARE_GATE_RUNBOOK.md`. Quick check with free tools:
`bash scripts/run_rtl_validation.sh` (Linux) or
`powershell -File scripts\run_rtl_validation.ps1 -OssCadSuite C:\oss-cad-suite` (Windows).

## Scope

This package is an RTL/model/readiness package. It is not a fabricated 3D IC. Real fabrication would require PDK access, die/TSV floorplanning, DRC/LVS/signoff, package design, and foundry involvement.
