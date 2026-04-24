# Architecture Coverage

This document records how the final organized Crypto3DStackCPU repository covers computer-organization and computer-architecture concepts.

## Final Repository Organization

```text
src/        C++ CPU, tools, tests, headers
programs/   ASM programs and contracts
docs/       architecture and security notes
paper/      IEEE-style paper
results/    validation logs and summaries
hardware_3d/ RTL/TSV/fabrication-readiness package
```

The final regression was rerun after this reorganization and passed.

## Concepts Covered

| Area | Covered in project |
|---|---|
| Assembly / ISA | MIPS-like assembly, registers, operands, `.text`, `.data`, pseudo-op `la` |
| CPU organization | hardwired control, fetch/decrypt/decode/execute/memory/writeback pipeline |
| Secure execution | encrypted text fetch, secure image validation, app-key unwrap, tamper lock |
| Hazards | forwarding, load-use stalls, store-data forwarding |
| Branches | static branch prediction/recovery, frontend flush, branch counters |
| Memory hierarchy | secure 4-layer memory abstraction, instruction/data cache counters |
| Cryptography | AES-128 KAT, AES ISA instructions, image sealing, key/image tags |
| Evaluation | fixed-window counters, CPI, stalls, forwarding, branch, cache, AES counters |
| Benchmarks | demo, demo_alt, pipeline_hazard, memory_stress, branch_stress, aes_stress |
| 3D memory | 4-layer abstraction, TSV model, layer map, hardware-readiness package |

## Course Mapping

| Course topic | Implementation evidence |
|---|---|
| Principles of Computer Operation | custom assembler, MIPS-like programs, integer and memory instructions |
| Computer Organization | datapath, hardwired pipeline control, hazards, branch handling |
| Computer Architecture | counters, benchmarks, CPI, branch/stall/performance discussion |
| Parallel Systems / HDL | layered memory model, SystemVerilog 3D memory/TSV abstractions |

## Explicit Non-Coverage

The project does not implement:

- out-of-order execution;
- Tomasulo reservation stations;
- reorder buffer;
- superscalar issue;
- VLIW ISA format;
- multicore cache coherence;
- OpenMP/MPI runtime;
- real fabricated 3D stacked-memory silicon.

These are intentionally left as future work because the current objective is a deterministic, verifiable, secure in-order cryptographic CPU.

## Final Regression Evidence

Final marker from the after-reorganization run:

```text
[ALL REGRESSION TESTS PASSED]
Crypto KATs, multi-layer memory tests, assembler negative tests, demo audits, alt audits,
pipeline hazard/forwarding audit, architecture benchmark suite, and extended tamper rejection tests all passed.
```

Representative validated benchmarks:

| Program | Purpose | Expected signature |
|---|---|---|
| `programs/demo.asm` | broad ISA/security coverage | `0x000000AE` |
| `programs/demo_alt.asm` | alternate contract path | `0x0000002A` |
| `programs/pipeline_hazard.asm` | forwarding/stall/store-forward validation | `0x00000036` |
| `programs/memory_stress.asm` | secure memory path stress | `0x0000000A` |
| `programs/branch_stress.asm` | branch prediction/recovery stress | `0x0000000D` |
| `programs/aes_stress.asm` | AES ISA instruction stress | `0x0000000A` |

## Target Hardware

The intended FPGA target is the **Xilinx/AMD AC701 Artix-7 Evaluation Kit (EK-A7-AC701-G)** with device `xc7a200tfbg676-2`. The 4-layer 3D-stacked-memory abstraction (4 layers × 1024 × 32-bit = 16 KiB) fits comfortably in the 365 × 18 Kb BRAMs available on `xc7a200t`. Clocking uses the onboard 200 MHz LVDS oscillator (`SYSCLK_P/N`) divided to 100 MHz by a Clocking Wizard, matching the 10 ns HLS clock target.

## Performance Counter Note

Counters are collected over a fixed 2000-cycle validation window. They are used for architectural visibility and regression comparison. They are not final Vivado timing or FPGA board performance results.
