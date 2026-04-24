# 3D Memory Architecture Specification

## Purpose

The 3D stacked memory is the secure storage substrate for Crypto3DStackCPU. It stores:
- secure header
- encrypted instruction blocks
- encrypted data blocks
- wrapped-key metadata
- hidden key-binding bits
- future sentinel/tamper layers

## Proposed Physical Stack

| Layer | Role | Description |
|---:|---|---|
| 0 | Execution layer | Validated CPU execution image layer |
| 1 | Data/cache layer | Future encrypted data expansion |
| 2 | Key-hiding layer | Future separated hidden-key-bit placement |
| 3 | Sentinel layer | Future redundancy/tamper detection layer |

## Logical Interface

Each transaction contains:

| Field | Width | Meaning |
|---|---:|---|
| `layer` | 2 bits | selects one of four layers |
| `addr` | 10 bits | selects one of 1024 words |
| `wdata` | 32 bits | write data |
| `rdata` | 32 bits | read data |
| `ren` | 1 bit | read enable |
| `wen` | 1 bit | write enable |
| `ready` | 1 bit | transaction done |
| `denied` | 1 bit | access blocked |
| `tamper` | 1 bit | tamper/fault alert |

## Security Policy

The model supports:
- per-layer access control
- out-of-range tamper latching
- fault injection for verification
- future ECC/syndrome channels
- separation of execution/data/key/sentinel roles

## Physical Implementation Notes

A real 3D IC implementation must replace behavioral arrays with:
- SRAM macros per layer
- TSV standard cells or process-specific vertical interconnect
- layer-aware floorplan
- inter-layer timing constraints
- thermal constraints
- DRC/LVS/STA/IR/EM signoff

## Integration with Existing CPU

The existing CPU may keep using layer 0 for validated execution.

Future policies may split:
- instruction fetch from layer 0
- secure data from layer 1
- hidden key bits from layer 2
- sentinel/tamper metadata from layer 3
