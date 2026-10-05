# Crypto3DStackCPU Research Status — 2026 Vertical-Trust Extension

## What is implemented now

The repository now contains two validated layers of work:

1. **Legacy secure CPU path** — the existing sealed-image MIPS-like CPU, AES ISA extensions, authenticated image validation, hazards/forwarding, benchmarks, reseal, and tamper tests.
2. **Vertical Trust Fabric (VTF)** — a new 3D-specific security architecture model that makes the tier boundary active rather than purely organizational.

VTF currently provides:

- AES-CMAC-128 authenticated vertical requests and responses in C++;
- a NIST SP 800-38B CMAC known-answer test;
- per-tier role-based access control;
- authenticated binding of requester, operation, tier, address, payload, sequence, and epoch;
- monotonic replay rejection;
- layer-spoof and payload-bit-flip detection tests;
- a key/metadata tier that is zeroized and disabled on severe events;
- sentinel-tier canaries with raw corruption detection;
- thermal and physical-fault trip models;
- a 128-bit simulation device-root interface instead of a single 32-bit fixed root seed;
- an HLS-facing CMAC wrapper;
- RTL Vertical Trust Guard and integration-oriented secure-stack top;
- Linux/CMake reproducibility in addition to the original PowerShell flow.

## What has been executed in this environment

Validated with GNU C++ on Linux:

- AES-128 FIPS-197 KAT;
- AES-CMAC NIST SP 800-38B KAT;
- multi-layer memory regression;
- 128-bit root provisioning regression;
- VTF policy/authentication/replay/layer-spoof/payload-fault/thermal/sentinel tests;
- full demo assemble -> seal -> decrypt-check -> CPU execute -> reseal -> second execute pipeline.

Update 2026-10-03: the SystemVerilog is now lint-clean (Verilator `-Wall`),
all three testbenches pass in Icarus Verilog, including a 15-attack
protected-vs-unprotected campaign, and the design synthesizes for Xilinx
7-series in Yosys (memory maps to 4×RAMB36E1). Two testbench bugs and one
BRAM-inference problem were fixed on the way. Vivado/Vitis HLS scripts and a
results collector are ready; see `docs/HARDWARE_GATE_RUNBOOK.md`. Vivado and
Vitis HLS themselves have **not** been run yet, so no Vivado PPA/Fmax claim is
made.

## Claims boundary

### Supported today

> Crypto3DStackCPU is a software/HLS-ready secure processor research prototype with a four-tier 3D memory abstraction and a validated Vertical Trust Fabric software model that provides authenticated tier transactions, replay protection, role-based access, sentinel monitoring, thermal/fault response, and key-tier zeroization.

### Not supported yet

Do not claim:

- fabricated 3D silicon;
- physical TSV authentication measured on silicon;
- FPGA timing closure or board validation;
- PDK signoff;
- resistance to power/EM side channels;
- voltage/clock glitch resistance measured on hardware;
- production-grade PUF/eFuse provisioning;
- a peer-reviewed novelty claim before a systematic literature/patent review.

## Next research gate

The next gate is **hardware evidence**, not more software features:

1. synthesize VTF CMAC + guard + stack interface — scripts ready (`vitis_hls_vtf_cmac.tcl`, `vivado_synth.tcl`); run them;
2. report PPA/Fmax and transaction latency — `collect_hardware_results.py` produces the table;
3. compare unprotected vs VTF-protected vertical transactions — baseline top added; Vivado run pending;
4. run controlled replay, layer-spoof, bit-flip, thermal, and fault-injection experiments — **done in RTL simulation** (`tb_vtf_attack_campaign.sv`);
5. only then freeze the architecture for paper-level evaluation.

One command: `bash scripts/run_hardware_gate.sh` (see `docs/HARDWARE_GATE_RUNBOOK.md`).
