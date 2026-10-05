# TSV / Vertical-Channel Security Model

## Implemented architectural controls

| Threat | Current model response | Evidence |
|---|---|---|
| TSV/data bit flip | Request payload is AES-CMAC bound; modified packet is rejected | `vertical_trust_fabric_test.cpp` |
| Layer spoofing | Layer ID is inside AES-CMAC request; post-signing change fails authentication | `vertical_trust_fabric_test.cpp` |
| Replay | Monotonic per-requester sequence check | C++ VTF + RTL guard |
| Old epoch | Epoch is authenticated and checked against active epoch | C++ VTF + RTL guard |
| Unauthorized tier access | Requester/tier/operation RBAC | C++ VTF + RTL guard |
| Key-tier exposure | Key tier restricted to SECURITY requester; severe trips zeroize/disable tier | C++ VTF model |
| Sentinel corruption | CMAC-derived canary bank + sentinel-fault input | C++ VTF + RTL sentinel monitor |
| Thermal event | Per-tier temperature threshold causes lockdown/zeroize | C++ VTF + RTL guard |
| Physical fault report | Severe event causes lockdown/zeroize | C++ VTF + RTL guard |

## Authentication boundary

The C++/HLS implementation uses AES-CMAC-128 (NIST SP 800-38B) to authenticate vertical requests. The RTL policy guard deliberately receives an `auth_ok_i` signal from an external/HLS CMAC authenticator rather than implementing a custom checksum and calling it cryptographic authentication.

## Physical countermeasures still required

For fabricated 3D hardware, add and measure:

- TSV redundancy and/or ECC;
- shield/guard TSVs where appropriate;
- calibrated thermal sensors;
- voltage/frequency glitch detectors;
- active tamper mesh;
- JTAG/debug lifecycle controls;
- secure boot binding to a PUF/eFuse/BBRAM root;
- physical design constraints and signoff for inter-tier paths.

## Current scope

The included models are intended for architecture simulation, software/HLS validation, interface planning, and future hardware experiments. They are **not** evidence of side-channel-hardened or silicon-validated TSV security.
