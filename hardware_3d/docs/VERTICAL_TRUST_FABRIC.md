# Vertical Trust Fabric (VTF)

## Purpose

The Vertical Trust Fabric is the 2026 research extension that turns the four-tier memory organization from a passive layout abstraction into an explicit security boundary. Instead of assuming that a vertical transaction reaches the intended tier unchanged, VTF binds the requester, operation, layer, address, payload, sequence number, and security epoch into an authenticated transaction.

The current repository implements the mechanism in the software/HLS model and supplies an RTL policy/replay/thermal guard. It does **not** claim fabricated TSV security or side-channel resistance.

## Tier roles

| Tier | Role | Default VTF access |
|---:|---|---|
| 0 | Instruction / execution | `CPU_FETCH` read, `SECURITY` read/write |
| 1 | Data | `CPU_DATA` read/write, `DMA` read/write, `SECURITY` read/write |
| 2 | Key / metadata | `SECURITY` only |
| 3 | Sentinel | `SECURITY` only |

Debug access is denied by default. If explicitly unlocked for a laboratory experiment, debug may access instruction/data tiers but never key/sentinel tiers.

## Authenticated request

Each request includes:

- protocol/domain marker;
- requester identity;
- read/write operation;
- destination tier;
- word address;
- write payload (zero for reads);
- monotonic requester sequence number;
- active security epoch;
- route nonce derived from requester/sequence/tier/epoch.

The C++/HLS path authenticates the serialized request with AES-CMAC-128 (NIST SP 800-38B). Therefore changing the layer, address, operation, payload, sequence, or epoch after signing invalidates the tag.

## Replay protection

The receiver tracks the last accepted sequence number for each requester. A valid next transaction must have exactly `last + 1`. A repeated or skipped sequence is treated as a severe protocol event and causes lockdown in the current strict model.

## Failure policy

A normal authorization failure (for example, `CPU_DATA` trying to read the key tier) is denied but does not destructively reset the system. This makes the policy usable by real software.
Because the request was already authenticated and freshness-checked, that denial still consumes its sequence number. The C++ and RTL protocol models use the same rule so requester and receiver state cannot silently diverge after a legitimate denied request.

The following are modeled as severe events:

- authentication tag failure;
- replay/sequence failure;
- epoch mismatch;
- invalid request fields;
- physical fault report;
- over-temperature trip;
- sentinel corruption.

A severe event latches VTF lockdown and zeroizes/disables the key/metadata tier in the C++ model.

## Sentinel tier

The software model installs eight AES-CMAC-derived canaries in the sentinel tier. A raw/physical modification that bypasses the normal access path is detected when the bank is checked. This is an architectural canary model; a physical implementation should replace or complement it with active mesh, ECC/redundancy, TSV monitors, and process-specific sensors.

## Thermal/fault model

The C++ VTF exposes per-tier milli-Celsius temperature updates and a configurable trip threshold. The RTL guard accepts per-tier temperature sensor inputs and separate physical/sentinel fault signals.

This is a **fault-response architecture**, not a claim that actual on-die sensors have been implemented or characterized.

## Hardware split

The RTL intentionally does not implement an ad-hoc "MAC". Instead:

1. `src/vtf_hls.cpp` provides an HLS-facing AES-CMAC tag/verify function.
2. `hardware_3d/rtl/vertical_trust_guard.sv` consumes `auth_ok_i` and enforces policy, replay, epoch, thermal/fault lockdown, and zeroize signalling.
3. `hardware_3d/rtl/crypto3d_secure_stack_top.sv` gates memory transactions with the guard.

This separation avoids overstating the security of an unreviewed custom RTL checksum and gives a clear integration path for a validated AES-CMAC IP.

## What remains for physical PhD-grade validation

- synthesize the CMAC authenticator and guard in Vitis HLS/Vivado;
- integrate real FPGA BRAM/AXI interfaces;
- measure LUT/FF/BRAM/DSP, Fmax, latency, and power;
- connect real or emulated thermal/glitch sensors;
- run fault-injection campaigns with timing/voltage/bit-flip models;
- for real 3D IC work, use PDK-specific TSV cells, floorplanning, STA, IR/EM, thermal analysis, DRC/LVS, and silicon measurement.
