# Crypto3DStackCPU

**Author:** George David Tsitlauri  
**Contact:** gdtsitlauri@gmail.com  
**Website:** gdtsitlauri.dev  
**GitHub:** github.com/gdtsitlauri  
**Year:** 2026

Comprehensive single-layer secure CPU stack with:

- custom no-MARS assembler flow (`.asm` -> `text.hex` + `data.hex`)
- secure image sealing with wrapped app key and authenticated header
- runtime secure validation before execution
- encrypted `.text` fetch/decrypt pipeline
- encrypted-at-rest data region with secure `lw`/`sw` handling
- executable custom AES instructions (`aesenc`, `aesdec`)
- contract-based functional validation for arbitrary ASM programs
- tamper-audit flow with required negative test

This README is the full implementation and operation guide for the current state of the project.

## Evidence Status

| Item | Current status |
| --- | --- |
| Secure CPU stack implementation | Present |
| Contract-based validation flow | Present |
| Tamper-audit negative test | Present |
| HLS integration scaffolding | Present |
| Manuscript-quality writeup | Present in `paper/crypto3dstackcpu_paper.tex` |
| Broad benchmark suite | Not yet committed |

## Research Positioning

Crypto3DStackCPU is best presented as a hardware/security research extension repo: the implementation is real, the security workflow is concrete, and the next gap is broader benchmarking rather than missing core engineering.

## 1) What Is Implemented

### 1.1 Core Execution and Security

- Single active layer policy (layer 0).
- Secure header in words `0..31` with policy/region/nonce/wrapped-key/tag metadata.
- App key generated per image build (key rotation per artifact).
- Wrapped-key extraction + image validation performed before trusted instruction fetch.
- Epoch-driven logical->physical text block mapping supported.
- Data region encrypted at rest and accessed through decrypt-modify-encrypt block path.

### 1.2 Toolchain and Validation

- Internal assembler (`asm_to_hex.cpp`) removes MARS dependency.
- One-command pipeline (`run_custom_pipeline.ps1`) does build + assemble + encrypt + run + verify.
- Security audit (`run_security_audit.ps1`) enforces:
	- positive execution proof on untampered image
	- tampered image rejection
- Functional checks are contract-driven (not hardcoded to one signature value).

### 1.3 ISA Coverage in Demo

Default `demo.asm` is a comprehensive coverage program that exercises:

- arithmetic/logic: `add`, `sub`, `and`, `or`, `xor`, `addi`, `lui`, `ori`
- bit operations: `sll`, `srl`, `mult`
- memory path: `la`, `lw`, `sw`
- control flow: `beq`, `bne`, `j` with taken and not-taken paths
- custom AES ops: `aesenc`, `aesdec`

Important current behavior:

- frontend branch/jump redirection is block-granular (`INSTRS_PER_BLOCK = 4`)
- taken targets in `demo.asm` are intentionally block-aligned for deterministic coverage

## 2) Project Layout

- `3d.cpp`, `3d.h`: CPU pipeline, secure runtime path, memory model, HLS top integration.
- `header.h`: shared secure-header constants and C API declarations.
- `asm_to_hex.cpp`: local assembler (`.data/.text/.word/.space/la` + supported instruction subset).
- `encryptor.cpp`: builds sealed image (`demo.hex`) from `text.hex` and `data.hex`.
- `decryptor.cpp`: validates and decrypts text for verification.
- `3d_test.cpp`: testbench, contract parser, runtime execution proof, memory feature checks.
- `demo.asm`: default comprehensive coverage program.
- `demo.contract`: expected outputs for default demo.
- `demo_alt.asm`, `demo_alt.contract`: alternate sample proving generic contract support.
- `run_custom_pipeline.ps1`: full no-MARS pipeline.
- `run_security_audit.ps1`: positive+negative functional/security audit.
- `3D_hls_component/`: Vitis HLS config/artifacts.

## 3) Supported Assembly Behavior

### 3.1 Assembler Inputs

Assembler supports:

- sections: `.text`, `.data`
- directives: `.word`, `.space`, `.globl`
- symbol/address helper: `la`

### 3.2 Instruction Support

Current subset includes:

- R-type: `add`, `sub`, `and`, `or`, `xor`, `sll`, `srl`, `mult`
- I-type: `addi`, `ori`, `lui`, `lw`, `sw`, `beq`, `bne`
- J-type: `j`
- custom crypto: `aesenc rd, rs, rt`, `aesdec rd`

`aesenc`/`aesdec` are executable CPU instructions (not stored data words).

## 4) Secure Image Layout

Image memory is 1024 words by default. High-level layout:

- words `0..31`: secure header (magic/version/policy/nonce/wrapped-key/tags/regions)
- text region: encrypted blocks (logical fetch maps to physical blocks)
- data region: plaintext loaded then sealed encrypted-at-rest by encryptor flow
- remainder: zero-padded

See `header.h` constants (`SEC_HDR_*`) for exact word offsets.

## 5) HLS Top Interface

Top function:

- `Crypto3DStackCPU_top(image, word_count, status_word)`

Arguments:

- `image`: AXI memory buffer for full image in/out
- `word_count`: valid input words (`0` means full `MEM_SIZE`)
- `status_word[0]`: status bitfield
	- bit0: security lock
	- bit1: key-check failure
	- bits31:16: retired instruction count

## 6) Build and Run

Run commands from this folder.

### 6.1 Manual Build

```powershell
g++ -std=c++17 -O2 asm_to_hex.cpp -o asm_to_hex.exe
g++ -std=c++17 -O2 3d.cpp encryptor.cpp -o encryptor_single.exe
g++ -std=c++17 -O2 3d.cpp decryptor.cpp -o decryptor_single.exe
g++ -std=c++17 -O2 3d.cpp 3d_test.cpp -o 3d_test_single.exe
```

### 6.2 Manual End-to-End (No MARS)

```powershell
./asm_to_hex.exe demo.asm text.hex data.hex
./encryptor_single.exe text.hex data.hex demo.hex
./3d_test_single.exe demo.hex demo.contract
```

Optional decrypt check:

```powershell
./decryptor_single.exe demo.hex text.hex text_out_check.hex
Compare-Object (Get-Content text.hex) (Get-Content text_out_check.hex)
```

### 6.3 One-Command Pipeline

```powershell
./run_custom_pipeline.ps1
```

Parameters:

- `-AsmFile` default `demo.asm`
- `-TextFile` default `text.hex`
- `-DataFile` default `data.hex`
- `-ImageFile` default `demo.hex`
- `-ContractFile` default `demo.contract`

Example with custom program:

```powershell
./run_custom_pipeline.ps1 -AsmFile myprog.asm -ContractFile myprog.contract
```

### 6.4 Security Audit (Required Negative Test)

```powershell
./run_security_audit.ps1
```

or use existing artifacts:

```powershell
./run_security_audit.ps1 -SkipPipeline
```

Audit behavior:

- computes and prints artifact hashes
- runs positive proof on untampered image
- flips one protected text word in temporary tamper image
- expects test failure/rejection for tampered image

Success marker:

- `[AUDIT PASS] Functional + security checks passed.`

## 7) Contract Format

Contract file is `key=value` (comments start with `#`).

Supported keys:

- `signature.enabled=true|false`
- `signature.pre_zero=true|false`
- `signature.offset=<word offset from data_start>`
- `signature.expected=<u32>`
- `reg.<index>=<u32>`

Default demo contract (`demo.contract`) currently expects:

- pre-run signature at configured location equals `0x00000000`
- post-run signature equals `0x000000AE`
- register checks including AES round-trip proof (`reg.11=0x00000005`)

## 8) Demo Programs

### 8.1 Default Demo

- file: `demo.asm`
- purpose: comprehensive instruction-path coverage
- expected output: defined in `demo.contract`

### 8.2 Alternate Demo

- file: `demo_alt.asm`
- purpose: prove validation is generic and contract-driven
- expected output: `demo_alt.contract`

## 9) Trace and Debug Options

`3d.cpp` supports compile-time debug flags (default disabled):

- `TRACE_PIPELINE=1`: fetch/decrypt block trace
- `TRACE_POST_TEXT_DUMP=1`: post-execution decrypted text dump

Example:

```powershell
g++ -std=c++17 -O2 -DTRACE_PIPELINE=1 -DTRACE_POST_TEXT_DUMP=1 3d_test.cpp 3d.cpp -o 3d_test_single.exe
```

## 10) Vitis HLS Notes

- `3D_hls_component/3D_hls_config.cfg` uses relative `csim.argv=../demo.hex`.
- Generate fresh `demo.hex` before CSIM.
- Top function includes explicit HLS interfaces (`m_axi` and `s_axilite`) suitable for IP flow.

## 11) Safe Cleanup (Generated Artifacts)

These can be regenerated by the pipeline and are safe to remove:

```powershell
Remove-Item -Force *.exe,*.hex,text_out_check.hex,demo_tamper.hex -ErrorAction SilentlyContinue
```

Do not delete source/config files such as:

- `3d.cpp`, `3d.h`, `header.h`
- `asm_to_hex.cpp`, `encryptor.cpp`, `decryptor.cpp`, `3d_test.cpp`
- `demo.asm`, `demo.contract`, `run_custom_pipeline.ps1`, `run_security_audit.ps1`

## Citation

```bibtex
@misc{tsitlauri2026crypto3dstackcpu,
  author = {George David Tsitlauri},
  title  = {Crypto3DStackCPU: A Single-Layer Secure CPU Stack with AES Instruction Support},
  year   = {2026},
  institution = {University of Thessaly},
  email  = {gdtsitlauri@gmail.com}
}
```

