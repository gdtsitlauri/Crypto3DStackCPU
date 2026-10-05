# Threat Model — Vertical Trust Fabric (roadmap 1.4)

## Principle

Kerckhoffs: the adversary is assumed to know the complete RTL, C++/HLS model,
scripts and documentation. The only secrets are keys: the device root
`K_root` and the keys derived from it. The goal is not "zero weaknesses". The
goal is an explicit model, a defence for everything inside it, and a clear
statement of what is outside it.

## Assets

| Asset | Where |
|---|---|
| Device root `K_root` | key schedule input (`vtf_key_schedule.sv`); today a simulation test vector, later PUF/eFUSE (roadmap 2.4) |
| Derived keys `K_req[r,e]`, `K_rsp[e]` and CMAC subkeys | `vtf_key_schedule.sv` registers / `VerticalTrustFabric` |
| Key/metadata tier contents | layer with role `KEY_HIDE` / `KEY_METADATA` |
| Instruction and data tier contents | EXEC / DATA layers |
| Protocol state: per-requester sequence, active epoch, lockdown latch | `vertical_trust_guard.sv` |

## Trust boundary

Trusted: the guard, the key schedule, the CMAC engine, the sentinel monitor and the
root-key input path. Untrusted: everything that crosses a vertical (inter-tier)
channel, the requesters' claimed identity, memory contents written outside the
VTF path, and the environment (temperature, physical-fault reports, sentinel words).

## Key hierarchy (roadmap 1.3)

```
K_req      = AES_{K_root}("VTFREQUESTK1" || 00000001)
K_rsp      = AES_{K_root}("VTFRESPONSEK" || 00000001)
K_req[r,e] = AES_{K_req}("VTFE" || e || r || "KDF1")      r = requester, e = epoch
K_rsp[e]   = AES_{K_rsp}("VTFE" || e || "RSP0" || "KDF1")
```

Consequences:
- A requester holding only its own key cannot produce tags for another requester.
- A tag from epoch *e* is useless in epoch *e+1*.
- Implemented identically in RTL, C++ and the independent Python reference
  (`hardware_3d/scripts/vtf_reference.py`), with bit-exact cross-checks.

## In scope: attacks, defences, evidence

| # | Attack | Defence | Evidence |
|---|---|---|---|
| A1 | Forged request (wrong/guessed tag) | AES-CMAC over all 32 request bytes, constant-time compare | `tb_vtf_system` forged-tag rows; C++ `vtf_property_test` |
| A2 | Field tampering on the TSV channel (requester, op, layer, addr, data, seq, epoch, nonce) | Every field is inside the CMAC message | `tb_vtf_system` TSV bit-flip rows; `vtf_property_test` per-field mutations |
| A3 | Replay of an accepted transaction | Per-requester strictly incrementing sequence (`seq = last+1`) | Formal P2 (unbounded proof); `tb_vtf_system` replay row |
| A4 | Stale-epoch replay / old-epoch key | Epoch check + per-epoch keys | Formal P1; `tb_vtf_system` stale-epoch and old-epoch-key rows; C++ "epoch-1 tag forged into epoch 2" |
| A5 | Requester impersonation (e.g. DMA claims SECURITY) | Per-requester keys `K_req[r,e]` | `tb_vtf_system` impersonation row; C++ distinct-key check |
| A6 | Privilege abuse: DMA/CPU into the key or exec tier, fetch-writes, locked debug | Role policy matrix in the guard | Formal P6 |
| A7 | Response tampering (forged read data) | Responses signed with `K_rsp[e]` | `tb_vtf_system` response-tamper row |
| A8 | Thermal, physical-fault or sentinel-corruption events | Fail-closed lockdown + key zeroize | Formal P3–P5; `tb_vtf_system` thermal/physical/sentinel rows |
| A9 | Persistence after a severe event (retry until success) | Sticky lockdown until reset; zeroized keys | Formal P3; `tb_vtf_system` "lockdown persists after root reload" |
| A10 | Silent probing via failed attempts | Every auth/epoch/replay failure is severe (P8) | Formal P8 |
| A11 | Fault injection on a write in transit | Tag mismatch → deny | `tb_vtf_system` fault-injection row |

Formal evidence:
- `hardware_3d/formal/vertical_trust_guard.sby` proves P1–P8 unbounded (abc pdr)
  over fully unconstrained inputs.
- `run_mutation_check.py` shows that each of 13 injected security bugs breaks the proof.

## Assumptions

- AES-128 is a PRP and AES-CMAC is a PRF/MAC (standard assumptions).
- `K_root` is delivered over a trusted path. Today it is a simulation constant;
  roadmap 2.4 plans PUF/eFUSE.
- Sequence numbers do not wrap within an epoch (2^32 transactions per requester).
  The epoch must be advanced before wrap.
- The environment sensors (temperature, physical-fault, sentinel) report honestly
  when triggered. Sensor calibration is out of scope.

## Out of scope (Phase 3: needs a lab or a foundry)

- Power/EM side-channel leakage of the AES/CMAC engines. Masking is roadmap 2.2,
  checked only in simulation until a real TVLA.
- Measured clock/voltage/laser glitching. Simulated register-level fault detection is roadmap 2.3.
- Invasive probing, FIB edits, logic locking or camouflaging (ASIC only).
- Data-at-rest attacks: direct memory writes or replay that bypass the VTF path.
  The transfer is protected; the stored data is not, until roadmap 2.1
  (memory encryption + integrity tree).
- Bitstream extraction/reverse engineering of the FPGA (roadmap 2.5, board only).
- Analog TSV crosstalk, Rowhammer-like effects on a physical macro, malicious
  foundry modifications, and any claim about fabricated 3D silicon.
- Denial of service: an attacker who can trigger a severe event can force lockdown
  by design (fail-closed). Availability is not a goal.
