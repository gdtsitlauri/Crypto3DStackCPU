param(
    [string]$Cxx = "g++"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "[RUN] $Name"
    Write-Host "============================================================"

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$CommonFlags = @(
    "-std=c++17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wno-unknown-pragmas"
)

Invoke-Checked "Build and run crypto/integrated KATs" {
    & $Cxx @CommonFlags "src\3d.cpp" "src\crypto_kat_test.cpp" "-o" "crypto_kat_test.exe"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & ".\crypto_kat_test.exe"
}

Invoke-Checked "Run multi-layer 3D memory model test" {
    & ".\run_multilayer_memory_test.ps1" -Cxx $Cxx
}

Invoke-Checked "Run assembler negative tests" {
    & ".\run_assembler_negative_tests.ps1" -Cxx $Cxx
}

Invoke-Checked "Run demo security audit" {
    & ".\run_security_audit.ps1" `
        -AsmFile "programs\demo.asm" `
        -ImageFile "demo.hex" `
        -ContractFile "programs\demo.contract" `
        -Cxx $Cxx
}

Invoke-Checked "Run demo_alt security audit" {
    & ".\run_security_audit.ps1" `
        -AsmFile "programs\demo_alt.asm" `
        -ImageFile "demo_alt.hex" `
        -ContractFile "programs\demo_alt.contract" `
        -Cxx $Cxx
}


Invoke-Checked "Run pipeline hazard/forwarding audit" {
    & ".\run_security_audit.ps1" `
        -AsmFile "programs\pipeline_hazard.asm" `
        -ImageFile "pipeline_hazard.hex" `
        -ContractFile "programs\pipeline_hazard.contract" `
        -Cxx $Cxx
}


Invoke-Checked "Run architecture benchmark suite" {
    & ".\run_architecture_benchmarks.ps1" -Cxx $Cxx
}

Invoke-Checked "Run extended tamper tests on demo" {
    & ".\run_extended_tamper_tests.ps1" `
        -AsmFile "programs\demo.asm" `
        -ImageFile "demo.hex" `
        -ContractFile "programs\demo.contract" `
        -Cxx $Cxx
}

Write-Host ""
Write-Host "============================================================"
Write-Host "[ALL REGRESSION TESTS PASSED]"
Write-Host "Crypto KATs, multi-layer memory tests, assembler negative tests, demo audits, alt audits,"
Write-Host "pipeline hazard/forwarding audit, architecture benchmark suite, and extended tamper rejection tests all passed."
Write-Host "============================================================"

