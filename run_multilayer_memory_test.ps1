param(
    [string]$Cxx = "g++"
)

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
Write-Host " Build and run multi-layer 3D memory abstraction test"
Write-Host "============================================================"

& $Cxx @Flags "src\3d.cpp" "src\multilayer_memory_test.cpp" "-o" "multilayer_memory_test.exe"

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

& ".\multilayer_memory_test.exe"

if ($LASTEXITCODE -ne 0) {
    throw "Multi-layer memory test failed with exit code $LASTEXITCODE"
}

Write-Host "[PASS] Multi-layer 3D memory abstraction test completed."

