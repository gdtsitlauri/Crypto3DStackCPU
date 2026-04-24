# TSV Security Model

## Threats

| Threat | Description | Model Support |
|---|---|---|
| TSV bit flip | Fault on vertical data path | `fault_inject` + `fault_mask` |
| Layer spoofing | Malicious layer-select change | `layer` checked against range |
| Access violation | Host tries to read disabled layer | `layer_access` and `denied` |
| Out-of-range access | Invalid layer/address | tamper latch |
| Data exposure | plaintext leaves secure boundary | must be prevented by integration policy |

## Future Physical Countermeasures

For fabricated 3D hardware, add:
- TSV redundancy
- shield TSVs
- parity/ECC on TSV groups
- thermal sensors
- active tamper mesh
- voltage/frequency glitch detectors
- JTAG lockout
- secure boot binding to hardware root

## Current Scope

The included RTL model is behavioral and intended for:
- architecture simulation
- interface validation
- integration planning
- future hardware work

It is not a side-channel-hardened TSV implementation.
