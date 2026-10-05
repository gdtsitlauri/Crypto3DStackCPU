# Crypto3DStackCPU

**Can a cryptographic CPU trust every transfer between the tiers of a 3D-stacked memory — and detect physical attacks on them?**

Crypto3DStackCPU is a pipelined MIPS-like CPU with AES instructions. It executes only encrypted and authenticated
program images, on top of a 4-tier 3D-stacked-memory model: instruction, data, key and sentinel tiers. Every
vertical (TSV) transaction goes through the **Vertical Trust Fabric (VTF)**:

- the requester, operation, tier, address, payload, sequence number and security epoch are authenticated with
  AES-CMAC, using per-epoch, per-role keys;
- responses are signed;
- a guard enforces role policy (e.g. DMA never reaches the key tier), freshness (anti-replay) and the
  thermal, physical-fault and sentinel alarms;
- any severe event latches lockdown and zeroizes the keys.

Only the keys are secret (Kerckhoffs).

The CPU is C++ for Vitis HLS. The VTF, the memory and all Phase-2 extensions are SystemVerilog RTL, checked
against independent C++ and Python models:

| layer | content | evidence |
|---|---|---|
| CPU | sealed images, `aesenc`/`aesdec`, forwarding, hazards, branch recovery, performance counters | full C++ regression, 6 programs with contracts |
| VTF (Phase 1) | in-RTL AES-128 + CMAC, epoch/role key schedule, guard, sentinel monitor, signed responses | 26-scenario system testbench, formal proof |
| Phase 2 | memory encryption + integrity tree, masked S-box, fault hardening, PUF key, bitstream security, CPU bridge | attack campaigns, simulated TVLA, SEU campaign, program traces |

## Main findings

All numbers come from simulation and formal verification with free tools (Icarus, Verilator, SymbiYosys, Yosys).
They are not FPGA or silicon measurements. Full tables: `docs/PHASE2_RESULTS_2026.md`.

1. **The VTF works as one RTL system and matches the reference bit for bit.**
   - AES/CMAC equal the FIPS-197, NIST SP 800-38B and HLS vectors.
   - Keys and tags equal an independent Python model (`cryptography`) and the C++ model.
   - 26/26 function and attack scenarios pass: forged tags, TSV bit flips, replay, stale epoch, impersonation,
     thermal, physical, sentinel, fault injection, response tampering.
   - Cost: **56 cycles per authenticated transaction**.
2. **The guard is formally verified.** Eight properties (P1–P8) are proven **unbounded** (abc pdr) over fully
   unconstrained inputs, with and without fault hardening. Examples:
   - no access without authentication;
   - no replayed or out-of-order sequence;
   - lockdown is permanent until reset;
   - every severe event zeroizes the keys in the same cycle.

   Each of 13 deliberately injected security bugs breaks the proof (13/13 mutants killed).
3. **Data at rest is protected, not only transfers.** AES-CTR with per-block counters, a CMAC binding the address,
   and a Merkle tree whose root stays on chip detect 9/9 attacks:
   - bit flips;
   - splicing;
   - counter rollback;
   - full replay of an old memory snapshot;
   - tree-node tampering.

   Cost: read 132, write 239 cycles (untuned).
4. **Single-fault (SEU) attacks are fully detected with hardening.** One bit flip in a security register at one
   cycle: forged requests accepted, replays re-enabled, wrong data signed.

   | | random (8,400 faults) | exhaustive (every bit × every cycle) |
   |---|---|---|
   | unhardened | 93 violations | 86 violations |
   | `FAULT_HARDEN=1` | **0** (2,286 effective faults all detected) | **0** (8,836 effective faults all detected) |

   Cost: 82 instead of 56 cycles per transaction. The campaign also found five bugs, which were fixed.
5. **First-order masking removes first-order leakage in simulation.** The DOM-masked AES S-box is correct for all
   inputs. A simulated TVLA over 50,000 traces gives max |t| = **1.2** masked against **221** unmasked
   (threshold 4.5).
6. **The root key can come from a PUF instead of being stored.**
   - Model study over 40 devices: uniqueness 0.500; repetition code ×11 gives ≤ 0.2% key failure at 85 °C.
   - The RTL fuzzy extractor recovers the key from a re-read with 96 bit errors, rejects another device's
     response, and wipes the secret.
7. **The CPU runs end to end on the protected memory.** A bridge signs every CPU fetch/load/store and checks every
   response. All 6 programs execute correctly from recorded traces.

## Negative and limiting results (reported as such)

- **Performance:** about **110 cycles per vertical access** (sign + VTF + verify), against about 2 unprotected.
  On the small, cold-start test programs this adds 220–430 cycles per instruction. A deployable design needs
  per-cache-line authentication and pipelined sign/verify; this is the next research step.
- **No real 3D silicon:** the 3D stack is a logical model; on an FPGA it is BRAM. Real TSVs need a foundry PDK.
- **Physical results are simulations:** TVLA uses a register Hamming-weight model (no glitches, coupling or
  noise); fault injection is single-bit register upsets; the PUF is a statistical model. None of this replaces
  board measurements.
- **Not yet run:** no Vivado timing/power and no Vitis HLS synthesis yet. Yosys gives only LUT/FF estimates
  (e.g. full VTF system ≈ 13k LUT, dominated by the key registers).
- **Bitstream protection** (`hardware_3d/constraints/bitstream_security.xdc`) is written but checkable only on a
  board.
- The first-order masking claim does not cover higher orders. Masking was not checked with maskVerif/SILVER.
- A systematic literature/patent novelty audit has not been done.

## Folder map

```
Crypto3DStackCPU/
  README.md, LICENSE (MIT), FUTURE_WORK_ROADMAP.md (status + what remains)
  SUMMARY_FOR_SUPERVISOR_GR.txt   plain-language summary of the whole study (Greek)
  src/                            C++/HLS CPU, AES/CMAC, VTF and memory-integrity models, tests
  programs/                       assembly programs and their result contracts
  hardware_3d/
    rtl/                          AES, CMAC, key schedule, guard, VTF system, integrity tree, masked S-box,
                                  PUF extractor, CPU bridge, SoC top
    tb/                           testbenches: system campaign, integrity tree, TVLA, PUF, fault injection, SoC
    formal/                       SymbiYosys proof of the guard (P1-P8) + mutation check
    scripts/                      run_rtl_validation (phase 1), run_phase2_validation, Python reference models,
                                  Vivado/HLS Tcl, TVLA analysis
    constraints/, docs/, fabrication/
  docs/                           threat model, Phase-2 results, formal properties, technical details
  results/hardware_eval/          rtl/, phase2/, fault_campaign/, tvla_sim/, puf_sim/, soc/
  scripts/                        Linux validation + hardware gate (Vivado/HLS)
  3D_hls_component/               Vitis HLS component
```

`docs/TECHNICAL_DETAILS.md` has the full architecture description: pipeline, ISA, secure image layout,
cryptographic construction and build options.

## Reproducing

Free tools: OSS CAD Suite (Icarus, Verilator, Yosys + slang, SymbiYosys), CMake + a C++17 compiler, Python with
`cryptography`, `numpy`.

| result | command | runtime |
|---|---|---|
| CPU regression | `./scripts/run_core_validation.sh` (Windows: `.\run_all_tests.ps1`) | minutes |
| 1, 2 | `bash hardware_3d/scripts/run_rtl_validation.sh` (Windows: `.ps1 -OssCadSuite <path>`) | ~5 min |
| 3–7 | `bash hardware_3d/scripts/run_phase2_validation.sh [out] [cpu_bin_dir]` | ~10 min |
| 4, full campaign | `iverilog` + `tb/tb_fault_campaign.sv` with `TRIALS=300`, `MODE=0/1` | ~30 min |
| FPGA numbers | `bash scripts/run_hardware_gate.sh` (needs Vivado + Vitis HLS) | 2–4 h |

## Status and what remains

Roadmap Phases 1 and 2 are implemented. What remains is only runs and lab work (`FUTURE_WORK_ROADMAP.md`):

- **Runs:** Vivado PPA/timing/power for every top and Vitis HLS synthesis of the CPU.
- **Lab:**
  - real power/EM TVLA (ChipWhisperer);
  - clock/voltage glitching;
  - PUF on many boards and temperatures;
  - bitstream encryption and JTAG lock on an Artix-7 board.
- **Research:** reduce the per-access cost (cache-line authentication, pipelining).

## Protocol discipline

Golden values come from independent implementations: Python `cryptography` and NIST/FIPS vectors, never from
the RTL itself. Testbenches are fail-closed (`[SV TEST PASS]` or an error). The formal properties were checked by
mutation: a property set that does not catch the 13 injected bugs would have been rejected.

The fault-injection campaigns ran before and after every fix. Each fix is listed in
`docs/PHASE2_RESULTS_2026.md`. Two classification artefacts of the first campaign are documented there:
- a forged tag one bit away from the valid tag;
- a stale response status.

The draft paper was removed; it will be rewritten after the hardware runs.

## Citation and license

George David Tsitlauri, University of Thessaly, 2026. MIT License (`LICENSE`).
