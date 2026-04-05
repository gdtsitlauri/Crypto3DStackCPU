param(
    [string]$AsmFile = "demo.asm",
    [string]$TextFile = "text.hex",
    [string]$DataFile = "data.hex",
    [string]$ImageFile = "demo.hex",
    [string]$ContractFile = "demo.contract"
)

$ErrorActionPreference = "Stop"

Write-Host "[STEP] Build custom assembler"
g++ -std=c++17 -O2 asm_to_hex.cpp -o asm_to_hex.exe
if ($LASTEXITCODE -ne 0) { throw "Failed to build asm_to_hex.exe" }

Write-Host "[STEP] Assemble ASM -> HEX (no MARS)"
./asm_to_hex.exe $AsmFile $TextFile $DataFile
if ($LASTEXITCODE -ne 0) { throw "Failed to assemble ASM into hex files" }

Write-Host "[STEP] Build encryptor/test binaries"
g++ -std=c++17 -O2 3d.cpp encryptor.cpp -o encryptor_single.exe
if ($LASTEXITCODE -ne 0) { throw "Failed to build encryptor_single.exe" }
g++ -std=c++17 -O2 3d.cpp 3d_test.cpp -o 3d_test_single.exe
if ($LASTEXITCODE -ne 0) { throw "Failed to build 3d_test_single.exe" }

Write-Host "[STEP] Encrypt image"
./encryptor_single.exe $TextFile $DataFile $ImageFile
if ($LASTEXITCODE -ne 0) { throw "Failed to create encrypted image" }

Write-Host "[STEP] Execute and verify on CPU"
if ([string]::IsNullOrWhiteSpace($ContractFile)) {
    ./3d_test_single.exe $ImageFile
} else {
    if (-not (Test-Path $ContractFile)) { throw "Contract file not found: $ContractFile" }
    ./3d_test_single.exe $ImageFile $ContractFile
}
if ($LASTEXITCODE -ne 0) { throw "CPU execution verification failed" }
