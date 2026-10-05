param(
    [string]$Cxx = "g++"
)

# Run from the repository root regardless of where the script is started.
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Flags = @(
    "-std=c++17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wno-unknown-pragmas"
)

Write-Host "============================================================"
Write-Host " Vertical Trust Fabric validation"
Write-Host "============================================================"

& $Cxx @Flags "src\3d.cpp" "src\vtf_hls.cpp" "src\vertical_trust_fabric_test.cpp" "-o" "vertical_trust_fabric_test.exe"
if ($LASTEXITCODE -ne 0) { throw "VTF build failed with exit code $LASTEXITCODE" }

& ".\vertical_trust_fabric_test.exe"
if ($LASTEXITCODE -ne 0) { throw "VTF validation failed with exit code $LASTEXITCODE" }


& $Cxx @Flags "src\3d.cpp" "src\vtf_hls.cpp" "src\vtf_property_test.cpp" "-o" "vtf_property_test.exe"
if ($LASTEXITCODE -ne 0) { throw "VTF property test build failed with exit code $LASTEXITCODE" }

& ".\vtf_property_test.exe"
if ($LASTEXITCODE -ne 0) { throw "VTF property test failed with exit code $LASTEXITCODE" }

& $Cxx @Flags "src\3d.cpp" "src\root_provisioning_test.cpp" "-o" "root_provisioning_test.exe"
if ($LASTEXITCODE -ne 0) { throw "Root provisioning test build failed with exit code $LASTEXITCODE" }

& ".\root_provisioning_test.exe"
if ($LASTEXITCODE -ne 0) { throw "Root provisioning test failed with exit code $LASTEXITCODE" }

Write-Host "[PASS] VTF + 128-bit root provisioning validation completed."
