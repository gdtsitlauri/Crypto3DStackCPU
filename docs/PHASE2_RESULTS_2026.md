# Crypto3DStackCPU / VTF: results of roadmap Phases 1–2 (2026-10-04)

These results come from simulation and formal verification, using free tools only.
They are not silicon or FPGA measurements; those belong to the run-only steps and to Phase 3.
To regenerate them:

- `hardware_3d/scripts/run_rtl_validation.sh`
- `hardware_3d/scripts/run_phase2_validation.sh`

## Phase 1

| Item | Result |
|---|---|
| 1.1 integrated in-RTL VTF system | 26/26 attack/function scenarios (`tb_vtf_system`)<br>AES/CMAC equal to FIPS-197, SP 800-38B and HLS vectors<br>keys and tags equal to an independent Python model (`cryptography`)<br>**56 cycles per transaction** (82 with `FAULT_HARDEN=1`) |
| 1.2 formal (SymbiYosys) | P1–P8 proven **unbounded** (abc pdr) over fully free inputs, with and without `FAULT_HARDEN`<br>6/6 cover goals reached<br>**13/13** injected security bugs break the proof (mutation check) |
| 1.3 epoch/role keys | `K_req[r,e]` and `K_rsp[e]` bit-exact across RTL, C++ and Python<br>an epoch-1 tag replayed in epoch 2 is rejected |
| 1.4 threat model | `docs/THREAT_MODEL_2026.md`: assets, boundary, attacks A1–A11 → defences → evidence |

## 2.1 Memory encryption and integrity tree

- **Construction:**
  - AES-CTR with a per-block write counter;
  - a CMAC per block that binds the address;
  - a Merkle tree of CMACs over the counters, with the root kept on chip.
- **Results:**
  - The root, ciphertext and MAC of the RTL, C++ and Python models are bit-identical.
  - Attacks detected (RTL and C++), 9/9: ciphertext flip, MAC flip, splicing (with and without the counter), counter rollback, full replay of an old snapshot, sibling-counter tamper, tree-node tamper (which also blocks the write), and tamper detected on first use.
- **Cost:** 16 blocks of 128 bits; read **132** cycles, write **239** cycles. These are untuned: one CMAC engine, and the keystream runs in parallel with path verification.

## 2.2 First-order masked AES S-box (DOM)

- Correct for 256 inputs × 8 maskings.
- Simulated TVLA, 50,000 traces, fixed vs random, Hamming-weight model of all registers:

| | max \|t\| first order | max \|t\| second order |
|---|---|---|
| unmasked | **221.5** | 118.1 |
| masked | **1.21** (< 4.5 ✓) | 2.2 |

- Model limitations: no glitches, coupling or noise. Phase 3 needs maskVerif/SILVER and a real TVLA.

## 2.3 Fault-injection (SEU) detection

`FAULT_HARDEN=1` adds:

- temporal redundancy of the CMAC;
- an 8-bit encoded auth decision;
- a re-check of the latched fields against the authenticated message;
- a dual-rail FSM;
- parity on the response;
- an equality check between the signed message and the fields before release;
- a dual-rail lockdown and parity on `last_sequence` in the guard.

The campaign injects single-bit flips into security registers (7 groups) during forged, replay, read and write transactions (`tb/tb_fault_campaign.sv`):

| | Random (8,400 trials) | Exhaustive timed (every bit × every cycle) |
|---|---|---|
| unhardened | **93** violations | **86** violations |
| hardened (`FAULT_HARDEN=1`) | **0** (2,286 effective faults, all detected or fail-safe) | **0** (8,836 effective faults, all detected or fail-safe) |

What the violations in the unhardened design are:

- a flipped `r_auth_ok` accepts a forged request;
- a flipped `last_sequence` re-enables replay;
- flips in response or request registers sign wrong data, or write to the wrong address.

The campaign found bugs that were then fixed:

- response-state hygiene between transactions (both variants);
- response outputs are taken from the signed bytes (both variants);
- the signed bytes are re-checked against the fields before release (hardened);
- the fields are re-checked against the authenticated message in the memory cycle (hardened);
- the CPU bridge requires the exact written word to be echoed on writes.

Raw logs: `results/hardware_eval/fault_campaign/`.

## 2.4 PUF + fuzzy extractor

- RO-PUF model (40 devices): uniqueness 0.500, bias 0.498, intra-HD 5.3% at 25 °C (5.9% at −20 °C, 6.5% at 85 °C).
- Key-failure rate of code-offset with repetition code REP:

| REP | −20 °C | 25 °C | 85 °C |
|---|---|---|---|
| 7 | 4.95% | 3.2% | 8.1% |
| 9 | 0.65% | 0.7% | 1.15% |
| **11** | **0%** | **0%** | **0.2%** |

- RTL reconstruction (REP=11, 1,408 bits) corrects 96 errors of a hot re-read.
- Another device does not produce the key.
- The secret is wiped after the KDF.

## 2.5 Bitstream

`constraints/bitstream_security.xdc` (AES-256 + HMAC, BBRAM, readback Level2, JTAG off) and `scripts/vivado_secure_bitstream.tcl` (the key file must sit outside the repository). This is checked only on a board.

## 2.6 CPU ↔ VTF

- `crypto3d_vtf_cpu_bridge` signs CPU_FETCH and CPU_DATA requests and checks the tag and every field of each response.
- Every vertical access recorded by the C++ CPU on `programs/*.asm` was replayed on the RTL SoC. All 6 programs are correct end to end (I-fetch, encrypted data loads/stores).

| Program | retired | F/R/W | ΔCPI (VTF) | ΔCPI (FT) |
|---|---|---|---|---|
| demo | 60 | 84/28/12 | 223 | 277 |
| aes_stress | 11 | 16/4/4 | 236 | 292 |
| memory_stress | 14 | 20/28/8 | 432 | 536 |

- **Honest finding:** each vertical access costs about 110 cycles (sign + VTF + verify), against about 2 cycles unprotected. These programs are tiny and dominated by cold misses.
- **Design requirement for the next paper:** authenticate per cache line (4–8 words per tag), and pipeline the sign and verify steps.

## Remaining steps

- **Run only:** Vivado PPA/timing/power for all tops, including `crypto3d_vtf_system_top_ft`, `memory_integrity_tree`, `aes_sbox_masked` and `puf_fuzzy_extractor`; Vitis HLS.
- **Phase 3 (lab):** real TVLA, glitching, PUF on many boards, bitstream encryption/JTAG on a board.
