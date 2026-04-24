# hardware_3d

This directory contains the hardware-oriented 3D stacked-memory readiness package for Crypto3DStackCPU.

## Contents

```text
constraints/      FPGA and TSV/floorplan templates
rtl/              SystemVerilog-level 3D memory and TSV models
tb/               SystemVerilog testbench for the memory model
docs/             architecture and scope notes
fabrication/      PDK/foundry/GDSII readiness checklists
paper_appendix/   LaTeX appendix text for the paper
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

## Scope

This package is an RTL/model/readiness package. It is not a fabricated 3D IC. Real fabrication would require PDK access, die/TSV floorplanning, DRC/LVS/signoff, package design, and foundry involvement.
