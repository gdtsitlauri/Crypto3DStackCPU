# Security Validation Notes

Crypto3DStackCPU validates functional correctness and tamper rejection through a reproducible regression suite. The current repository layout uses `src/` for code and `programs/` for assembly/contract inputs.

## Security Model

The project protects sealed program images before execution:

- encrypted `.text` region;
- encrypted `.data` region;
- secure 32-word header;
- nonce/epoch-bound image mapping;
- wrapped app key;
- key tag;
- image tag;
- measurement field;
- validation-before-fetch;
- failure-closed CPU lock on validation failure.

## 4-Layer Memory Security Separation

| Layer | Role |
|---:|---|
| 0 | encrypted instruction text |
| 1 | encrypted program data |
| 2 | key/security metadata abstraction |
| 3 | tamper/sentinel markers |

This separation gives the 3D memory abstraction a security purpose rather than using it only as a larger flat memory.

## Positive Tests

The regression suite validates:

- AES-128 FIPS-197 known-answer test;
- multi-layer memory behavior;
- assembler correctness for valid programs;
- contract-based program execution;
- post-execution reseal validation;
- reload validation of resealed output;
- performance counter visibility.

## Negative Tests

The assembler negative tests reject:

- invalid register names;
- branch target outside `.text`;
- duplicate labels;
- misaligned branch targets;
- misaligned jump targets;
- unaligned `lw` offsets;
- unknown instructions.

The extended tamper suite rejects modifications to:

- header magic;
- header policy;
- wrapped key words;
- key tag words;
- image tag words;
- encrypted text;
- encrypted data.

## Pipeline Security and Correctness Checks

The current CPU includes:

- forwarding from later pipeline stages;
- load-use stall handling;
- store-data forwarding;
- branch recovery and frontend flush;
- branch prediction/misprediction counters;
- architectural counters for stalls, forwarding, AES instructions, and cache events.

The `programs/pipeline_hazard.asm` contract validates the hazard path and final signature.

## Final Result

The final after-reorganization regression completed successfully:

```text
[ALL REGRESSION TESTS PASSED]
Crypto KATs, multi-layer memory tests, assembler negative tests, demo audits, alt audits,
pipeline hazard/forwarding audit, architecture benchmark suite, and extended tamper rejection tests all passed.
```

## Claims Discipline

Allowed wording:

> Validated software/HLS-ready cryptographic CPU prototype with an integrated 4-layer 3D-stacked-memory abstraction and authenticated tamper rejection.

Not allowed yet:

- side-channel secure;
- FPGA-proven;
- Vivado timing-closed;
- Artix-7 board validated;
- production-grade secure processor;
- fabricated real 3D stacked-memory silicon.

## Future Security Work

Future hardening should include:

- bitsliced or masked AES;
- fault-detection redundancy;
- power/EM side-channel measurements;
- TVLA-style leakage testing;
- real FPGA board tests;
- ASIC/PDK/foundry collaboration for real 3D IC fabrication.
