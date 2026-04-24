# Results

This directory stores validation logs, benchmark outputs, and final regression evidence.

## Latest Full Regression Status

The final full regression run after the repository was reorganized into `src/`, `programs/`, and `docs/` completed successfully.

Final marker:

```text
[ALL REGRESSION TESTS PASSED]
Crypto KATs, multi-layer memory tests, assembler negative tests, demo audits, alt audits,
pipeline hazard/forwarding audit, architecture benchmark suite, and extended tamper rejection tests all passed.
```

## Validated Components

| Component | Result |
|---|---|
| AES-128 FIPS-197 KAT | PASS |
| 4-layer 3D memory abstraction | PASS |
| assembler negative tests | PASS |
| `programs/demo.asm` secure audit | PASS |
| `programs/demo_alt.asm` secure audit | PASS |
| pipeline hazard / forwarding audit | PASS |
| architecture benchmark suite | PASS |
| memory stress benchmark | PASS |
| branch stress benchmark | PASS |
| AES stress benchmark | PASS |
| extended tamper rejection | PASS |

## Representative Counter Summary

Counters are measured over a fixed 2000-cycle validation window.

| Program | Retired | Stalls | Load-use | Fwd MEM | Fwd WB | Store fwd | Branch mispred. | AES inst. | Signature |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `demo.asm` | 60 | 1 | 1 | 17 | 10 | 0 | 2 | 2 | `0xAE` |
| `demo_alt.asm` | 11 | 0 | 0 | 3 | 1 | 0 | 0 | 0 | `0x2A` |
| `pipeline_hazard.asm` | 14 | 2 | 2 | 5 | 5 | 1 | 0 | 0 | `0x36` |
| `memory_stress.asm` | 14 | 0 | 0 | 4 | 4 | 1 | 0 | 0 | `0x0A` |
| `branch_stress.asm` | 7 | 0 | 0 | 4 | 1 | 0 | 2 | 0 | `0x0D` |
| `aes_stress.asm` | 11 | 0 | 0 | 3 | 3 | 0 | 0 | 4 | `0x0A` |

## Important CPI Note

The reported CPI is:

```text
CPI = fixed validation window cycles / retired instructions
```

The validation window is 2000 cycles. Therefore, CPI values are useful for architectural visibility and regression comparison, but they are not final optimized FPGA/Vivado performance results.

## Saving Logs

To save a timestamped full regression log:

```powershell
New-Item -ItemType Directory -Force .\results | Out-Null
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$log = ".\results\run_all_tests_$ts.log"
powershell -ExecutionPolicy Bypass -File .\run_all_tests.ps1 *>&1 | Tee-Object -FilePath $log
```

Keep the latest successful log in this directory as project evidence.
