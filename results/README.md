# Results

This directory stores validation logs, benchmark outputs, and regression evidence.

## 2026 Vertical Trust Fabric validation

The current package was rebuilt and tested on GNU C++/Linux after the Vertical Trust Fabric (VTF) extension.

Executed and passed:

| Component | Result |
|---|---|
| AES-128 FIPS-197 KAT | PASS |
| AES-CMAC NIST SP 800-38B KAT | PASS |
| 4-layer `StackedMemory3D` regression | PASS |
| 128-bit device-root provisioning regression | PASS |
| VTF authenticated request/response path | PASS |
| VTF tier authorization | PASS |
| VTF layer-spoof rejection | PASS |
| VTF payload-bit-flip rejection | PASS |
| VTF replay rejection | PASS |
| VTF thermal trip / key-tier zeroization | PASS |
| VTF sentinel raw-corruption detection | PASS |
| VTF field-mutation property tests | PASS |
| Address/UndefinedBehavior sanitizers on CTest suite | PASS |
| Full demo assemble -> seal -> decrypt-check -> CPU -> reseal -> second execution | PASS |
| Linux sealed-image tamper audit: encrypted text | REJECTED AS EXPECTED |
| Linux sealed-image tamper audit: wrapped key | REJECTED AS EXPECTED |
| Linux sealed-image tamper audit: image tag | REJECTED AS EXPECTED |

Relevant logs/artifacts:

- `demo_pipeline_validation.log`
- `sanitizer_validation.log`
- `linux-demo/`
- `linux-security-audit/`
- `vtf/host_microbenchmark.txt`

## Representative CPU counter summary

The demo pipeline still reports the validated fixed-window counters:

| Program | Retired | Stalls | Load-use | Fwd MEM | Fwd WB | Branch mispred. | AES inst. | Signature |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `demo.asm` | 60 | 1 | 1 | 17 | 10 | 2 | 2 | `0xAE` |

The validation window is 2000 cycles, so the reported CPI is a regression/visibility metric and **not** a post-synthesis FPGA performance number.

## VTF host microbenchmark caveat

`vtf/host_microbenchmark.txt` measures the C++ software model on the execution host. It demonstrates that authenticated transactions execute correctly and gives a software-cost reference, but it is **not** an FPGA/ASIC latency or throughput result. Hardware numbers must come from HLS/Vivado/FPGA or ASIC tools.

## Original Windows regression

The repository retains the original PowerShell regression suite (`run_all_tests.ps1`), now extended with `run_vtf_validation.ps1`. The historical architecture workloads remain in the project, but the current Linux environment does not provide PowerShell, so the newly generated logs in this package are from the cross-platform CMake/Bash flow.
