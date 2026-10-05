# Claims and Limitations

## Safe claims

You may claim that the repository contains:

- a software-validated secure MIPS-like CPU execution path;
- encrypted/authenticated sealed-image flow and reseal validation;
- executable AES ISA extensions;
- four-tier C++/HLS memory abstraction;
- a **validated software Vertical Trust Fabric** with AES-CMAC request/response authentication, RBAC, replay/epoch checks, layer/payload binding, sentinel canaries, thermal/fault response, and severe-event key-tier zeroization;
- an HLS-facing AES-CMAC wrapper;
- RTL modules for VTF policy/replay/thermal guarding, sentinel monitoring, and secure-stack integration;
- reproducible GNU C++/CMake validation on Linux plus the original PowerShell flow.

## Claims that still require hardware evidence

Do **not** claim yet:

- FPGA-proven VTF timing/performance;
- Vivado timing closure;
- physical AC701 measurements;
- fabricated 3D stacked-memory silicon;
- PDK/TSV DRC/LVS/STA signoff;
- measured power/EM/thermal attack resistance;
- production-grade PUF/eFuse device-root provisioning;
- side-channel security;
- peer-reviewed algorithm/architecture novelty.

## Recommended wording

> Crypto3DStackCPU is a validated software/HLS-ready secure CPU research prototype with a four-tier 3D memory abstraction. Its 2026 Vertical Trust Fabric extension authenticates and authorizes logical inter-tier transactions, rejects replay and route/payload modification, models sentinel and thermal/fault response, and provides an RTL/HLS integration path. Physical 3D-IC and FPGA validation remain future work.
