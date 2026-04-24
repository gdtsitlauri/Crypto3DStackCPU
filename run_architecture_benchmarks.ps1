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
    Write-Host "[BENCH] $Name"
    Write-Host "============================================================"

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$Benchmarks = @(
    @{ Name = "memory_stress";   Asm = "programs\memory_stress.asm";   Contract = "programs\memory_stress.contract";   Image = "memory_stress.hex" },
    @{ Name = "branch_stress";   Asm = "programs\branch_stress.asm";   Contract = "programs\branch_stress.contract";   Image = "branch_stress.hex" },
    @{ Name = "aes_stress";      Asm = "programs\aes_stress.asm";      Contract = "programs\aes_stress.contract";      Image = "aes_stress.hex" },
    @{ Name = "pipeline_hazard"; Asm = "programs\pipeline_hazard.asm"; Contract = "programs\pipeline_hazard.contract"; Image = "pipeline_hazard.hex" }
)

foreach ($b in $Benchmarks) {
    Invoke-Checked $b.Name {
        & ".\run_security_audit.ps1" `
            -AsmFile $b.Asm `
            -ImageFile $b.Image `
            -ContractFile $b.Contract `
            -Cxx $Cxx
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "[BENCH PASS] Architecture benchmark suite passed."
Write-Host "============================================================"
exit 0

