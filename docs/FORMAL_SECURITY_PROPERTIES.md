# Vertical Trust Fabric - Security Properties and Test Mapping

This document states the security properties implemented by the current VTF model. They are engineering invariants and testable properties, **not a formal cryptographic proof of the entire processor**.

## P1 - Route and payload binding

For a request

`R = (requester, op, layer, addr, data, sequence, epoch, route_nonce)`

the tag is `CMAC_K(enc(R))`. Therefore, under the security assumption of AES-CMAC, any post-authentication change to a bound field should be rejected unless an attacker can forge the tag.

**Tests:** `vtf_property_test.cpp` mutates requester, operation, layer, address, payload, sequence, epoch, route nonce, and tag independently. Each mutation is rejected.

## P2 - Replay rejection

For each requester, the receiver accepts only the next sequence number `s = last + 1`. A previously accepted request cannot be accepted again in the same epoch.

**Tests:** `vertical_trust_fabric_test.cpp` replays a previously valid write and verifies lockdown.

## P3 - Epoch freshness

A request is accepted only when its authenticated epoch equals the current active epoch. Advancing the epoch resets protocol sequence state.

**Tests:** field-mutation property test plus VTF epoch checking logic.

## P4 - Least-privilege tier authorization

Default access matrix:

| Requester | Instruction | Data | Key/metadata | Sentinel |
|---|---:|---:|---:|---:|
| CPU_FETCH | read | deny | deny | deny |
| CPU_DATA | deny | read/write | deny | deny |
| DMA | deny | read/write | deny | deny |
| DEBUG | locked by default; optional instruction/data laboratory access only | | deny | deny |
| SECURITY | read/write | read/write | read/write | read/write |

Ordinary policy violations are denied without destructive reset.

**Tests:** `vertical_trust_fabric_test.cpp` and `vtf_property_test.cpp`.

## P5 - Severe-event fail-closed behavior

Bad authentication, replay, epoch mismatch, invalid request fields, thermal trip, reported physical fault, and sentinel corruption cause a latched lockdown in the current strict model.

**Tests:** layer-spoof, payload-bit-flip, replay, thermal, and sentinel tests.

## P6 - Critical-tier zeroization

On a severe event, the software VTF clears the key/metadata tier and disables access to that tier when zeroization policy is enabled.

**Tests:** authentication-failure and thermal-trip cases explicitly inspect raw key-tier storage after the event.

## P7 - Sentinel integrity

The sentinel tier is provisioned with AES-CMAC-derived canaries. Raw corruption that bypasses the normal write path must be detected at verification time.

**Tests:** direct raw corruption of a sentinel word followed by `verifySentinels()`.

## Assumptions and limits

These properties assume the AES primitive and AES-CMAC construction are correctly implemented, and that the root/authentication keys remain inside the trusted boundary. The repository validates AES with FIPS-197 vectors and AES-CMAC with NIST SP 800-38B vectors.

The current model does not prove resistance to side-channel key leakage, analog fault attacks, malicious fabrication, or compromised hardware-root provisioning. Those require hardware-specific analysis and measurement.

## Machine-checked RTL properties (roadmap 1.2, 2026-10)

`hardware_3d/formal/vertical_trust_guard_props.sv` states P1-P8 for the RTL guard
over fully unconstrained inputs:

- P1: no allow without authentication, a matching epoch and a valid requester/layer.
- P2: anti-replay, tracked from the outputs only.
- P3: lockdown is sticky.
- P4: every severe event triggers zeroize and lockdown in the same cycle.
- P5: any environmental fault blocks the access.
- P6: the role policy (key/sentinel tiers only for SECURITY, fetch never writes, CPU_DATA/DMA only touch DATA tiers, debug needs unlock).
- P7: output consistency.
- P8: every authentication/epoch/malformed-request failure is severe.

SymbiYosys proves them **unbounded** (abc pdr), both with and without `FAULT_HARDEN`.
`run_mutation_check.py` checks the properties themselves: each of 13 injected
security bugs makes the proof fail (13/13 killed).
