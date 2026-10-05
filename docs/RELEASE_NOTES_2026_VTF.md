# Crypto3DStackCPU — 2026 Vertical Trust Fabric Research Release

This release extends the original Crypto3DStackCPU prototype with a **Vertical Trust Fabric (VTF)** that makes logical inter-tier traffic an explicit security boundary.

## What is new

- AES-CMAC-128 authentication for logical inter-tier requests and responses.
- Binding of requester, operation, tier, address, payload, sequence, epoch, and route nonce.
- Per-requester monotonic replay protection and epoch checks.
- Role-based tier authorization for CPU fetch, CPU data, DMA, security, and debug requesters.
- Four explicit tier roles: instruction, data, key/metadata, and sentinel.
- Sentinel canaries plus modeled thermal and physical-fault trip handling.
- Fail-closed lockdown and severe-event zeroization/disable of the key/metadata tier in the C++ model.
- 128-bit simulation device-root interface; the public default is a test vector only and is not a production secret.
- NIST SP 800-38B AES-CMAC implementation and known-answer test.
- HLS-facing CMAC wrapper for future Vitis HLS integration.
- RTL policy/replay/epoch/thermal guard, sentinel monitor, secure-stack integration top, and a SystemVerilog testbench.
- Cross-platform CMake/CTest build, Linux validation scripts, sanitizer validation, and additional PowerShell regression entry points.
- Updated threat model, security properties, architecture coverage, claims/limitations, hardware documentation, and research paper.

## Validation executed in this environment

- GNU C++ / CMake / CTest: **5/5 tests passed**.
- Clang / CMake / CTest: **5/5 tests passed**.
- AddressSanitizer + UndefinedBehaviorSanitizer: **5/5 tests passed**.
- Complete assemble → seal → decrypt-check → execute → reseal → reload demo: **PASS**.
- Expected demo signature: `0x000000AE`.
- Sealed-image negative tests: encrypted-text tamper, wrapped-key tamper, and image-tag tamper were all **rejected as expected**.
- VTF regressions cover authorization, field-binding mutations, replay, payload/layer tampering, thermal trip, sentinel corruption, response binding, and key-tier zeroization.

See `results/validation_manifest.json` and the logs under `results/` for the recorded validation scope.

## Hardware assets included but not executed here

The release includes SystemVerilog/HLS-oriented assets, but this execution environment did not contain a SystemVerilog simulator, Vivado, or Vitis HLS. Therefore the following are **prepared for external validation, not claimed as measured results**:

- SystemVerilog compilation/simulation of the new VTF RTL;
- HLS synthesis of the CMAC wrapper;
- Vivado synthesis, place-and-route, timing closure, and FPGA-board validation;
- ASIC/PDK/TSV physical implementation;
- measured power, EM, timing side-channel, or physical fault-injection resistance.

## Research status

This is a **PhD-oriented research prototype**, not a claim of a completed PhD contribution or fabricated 3D-IC. The new VTF gives the project a concrete 3D-security research direction; publication-grade novelty still requires a formal literature/patent novelty study plus external hardware/EDA evaluation.
