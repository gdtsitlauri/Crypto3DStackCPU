# 3D Memory Architecture Specification

## Purpose

The four-tier stack is the secure storage substrate for Crypto3DStackCPU and the protected endpoint of the Vertical Trust Fabric (VTF). It separates execution, data, key/metadata, and sentinel state so the security policy can reason about vertical destinations explicitly.

## Logical stack

| Tier | Role | VTF policy |
|---:|---|---|
| 0 | Instruction / execution | CPU fetch read + security provisioning |
| 1 | Data | CPU data and DMA read/write + security provisioning |
| 2 | Key / metadata | security-only; zeroized/disabled on severe event |
| 3 | Sentinel | security-only; stores canaries / future sensor metadata |

The legacy sealed-image CPU regression still boots a complete image from layer 0 for compatibility. The VTF research path exercises the explicit four-role split. A future CPU integration can migrate instruction/data/key/sentinel traffic onto their dedicated physical tiers without changing the VTF transaction format.

## VTF transaction fields

A protected vertical request binds:

| Field | Meaning |
|---|---|
| requester | CPU fetch, CPU data, security, DMA, debug |
| operation | read/write |
| layer | destination tier |
| address | word address |
| payload | write data |
| sequence | anti-replay counter |
| epoch | security/reseal epoch |
| route nonce | deterministic route-domain value |
| AES-CMAC tag | authenticates the request tuple |

## Hardware partition

- `src/vtf_hls.cpp`: HLS-facing AES-CMAC tag/verify function.
- `hardware_3d/rtl/vertical_trust_guard.sv`: RBAC, replay, epoch, thermal/fault lockdown, zeroize output.
- `hardware_3d/rtl/tier_sentinel_monitor.sv`: provisioned sentinel comparison.
- `hardware_3d/rtl/crypto3d_secure_stack_top.sv`: integration-oriented guard + memory model top.
- `hardware_3d/rtl/stacked_memory_3d_model.sv`: BRAM-inferable behavioral stack model.

## Physical implementation requirements

A real 3D IC implementation must replace behavioral structures with target technology components:

- SRAM/HBM or other memory macros per tier;
- PDK-specific TSV/hybrid-bond structures;
- layer-aware floorplanning and routing;
- inter-tier STA;
- IR/EM and thermal signoff;
- DRC/LVS;
- calibrated fault/thermal sensors;
- hardware-root provisioning.
