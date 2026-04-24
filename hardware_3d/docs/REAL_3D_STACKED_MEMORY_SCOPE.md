# Real 3D Stacked Memory Scope

This document defines the precise scope of the 3D stacked-memory work in Crypto3DStackCPU.

## Current Level

Crypto3DStackCPU now includes:

- a 4-layer C++/HLS `StackedMemory3D` abstraction in the main CPU source;
- a regression test for multi-layer behavior;
- a SystemVerilog behavioral 4-layer memory model;
- TSV interface and interconnect models;
- layer mapping metadata;
- PDK/foundry/GDSII signoff checklists.

## Levels of Realism

| Level | Meaning | Current Status |
|---|---|---|
| L0 | Original C++ single-layer sealed-memory prototype | superseded by 4-layer abstraction |
| L1 | C++/HLS 4-layer memory abstraction | implemented in main `3d.h` / `3d.cpp` |
| L2 | RTL behavioral 4-layer 3D memory + TSV model | included in `hardware_3d/rtl` |
| L3 | FPGA-emulated multi-layer memory | future work |
| L4 | PDK-bound 3D SRAM/HBM/TSV macros | future work |
| L5 | GDSII + DRC/LVS/STA/IR/thermal signoff | future work |
| L6 | Fabricated 3D IC silicon | future work |

## Correct Claim

> Crypto3DStackCPU implements a validated cryptographic CPU prototype with a 4-layer C++/HLS 3D-stacked-memory abstraction and RTL-level multi-layer memory/TSV models.

## Incorrect Claim

> Crypto3DStackCPU contains fabricated real 3D stacked-memory silicon.

That would require foundry access, PDKs, physical SRAM macros, TSV cells, packaging, and silicon validation.
