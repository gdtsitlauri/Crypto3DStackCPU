param(
    [string]$AsmFile = "demo.asm",
    [string]$TextFile = "text.hex",
    [string]$DataFile = "data.hex",
    [string]$ImageFile = "demo.hex",
    [string]$ContractFile = "demo.contract",
    [string]$TamperFile = "demo_tamper.hex",
    [switch]$SkipPipeline,
    [switch]$KeepTamper
)

$ErrorActionPreference = "Stop"

function Require-Success {
    param(
        [int]$ExitCode,
        [string]$StepName
    )

    if ($ExitCode -ne 0) {
        throw "$StepName failed with exit code $ExitCode"
    }
}

Write-Host "[AUDIT] Crypto CPU functional + security audit"

if (-not $SkipPipeline) {
    Write-Host "[STEP] Run clean build/assemble/encrypt/verify pipeline"
    & .\run_custom_pipeline.ps1 -AsmFile $AsmFile -TextFile $TextFile -DataFile $DataFile -ImageFile $ImageFile -ContractFile $ContractFile
    Require-Success -ExitCode $LASTEXITCODE -StepName "run_custom_pipeline.ps1"
} else {
    Write-Host "[STEP] Skip pipeline (using current artifacts)"
}

foreach ($artifact in @($TextFile, $DataFile, $ImageFile)) {
    if (-not (Test-Path $artifact)) {
        throw "Missing required artifact: $artifact"
    }
}

if (-not [string]::IsNullOrWhiteSpace($ContractFile) -and -not (Test-Path $ContractFile)) {
    throw "Missing contract file: $ContractFile"
}

Write-Host "[STEP] Artifact hashes (SHA256)"
foreach ($artifact in @($TextFile, $DataFile, $ImageFile)) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $artifact).Hash
    Write-Host ("[HASH] {0} {1}" -f $artifact, $hash)
}

Write-Host "[STEP] Positive execution proof (untampered image)"
if ([string]::IsNullOrWhiteSpace($ContractFile)) {
    $positiveOutput = (& .\3d_test_single.exe $ImageFile 2>&1 | Out-String)
} else {
    $positiveOutput = (& .\3d_test_single.exe $ImageFile $ContractFile 2>&1 | Out-String)
}
$positiveExit = $LASTEXITCODE
$positiveContractOk = $positiveOutput -match "Functional contract checks passed"

if (($positiveExit -eq 0) -and $positiveContractOk) {
    Write-Host "[OK] Untampered image execution proof passed."
} else {
    Write-Host "[ERROR] Positive proof failed. Raw output:"
    Write-Host $positiveOutput
    throw "Positive execution proof failed (exit=$positiveExit)."
}

Write-Host "[STEP] Tamper image and expect rejection"
$lines = Get-Content -Path $ImageFile
if ($lines.Count -lt 33) {
    throw "Image too small to contain secure header/text region"
}

$textStart = [Convert]::ToUInt32($lines[4], 16)
$textWords = [Convert]::ToUInt32($lines[5], 16)

if ($textWords -eq 0) {
    throw "Header reports zero text words; cannot build tamper test"
}

$offsetInsideText = [Math]::Min(2, [int]$textWords - 1)
$tamperIndex = [int]$textStart + $offsetInsideText

if (($tamperIndex -lt 0) -or ($tamperIndex -ge $lines.Count)) {
    throw "Tamper index out of bounds: $tamperIndex"
}

$oldWord = [Convert]::ToUInt32($lines[$tamperIndex], 16)
$newWord = ($oldWord -bxor 0x00000001)
$lines[$tamperIndex] = ("{0:X8}" -f $newWord)
Set-Content -Path $TamperFile -Value $lines -Encoding ascii

Write-Host ("[INFO] Tampered word @ index {0}: 0x{1:X8} -> 0x{2:X8}" -f $tamperIndex, $oldWord, $newWord)

try {
    if ([string]::IsNullOrWhiteSpace($ContractFile)) {
        $negativeOutput = (& .\3d_test_single.exe $TamperFile 2>&1 | Out-String)
    } else {
        $negativeOutput = (& .\3d_test_single.exe $TamperFile $ContractFile 2>&1 | Out-String)
    }
    $negativeExit = $LASTEXITCODE
    $negativeRejectMarker = ($negativeOutput -match "\[FAIL\]") -or ($negativeOutput -match "\[ERROR\]")

    if (($negativeExit -ne 0) -and $negativeRejectMarker) {
        Write-Host "[OK] Tampered image was rejected as expected."
    } else {
        Write-Host "[ERROR] Tamper test did not fail as expected. Raw output:"
        Write-Host $negativeOutput
        throw "Tamper rejection failed (exit=$negativeExit)."
    }
} finally {
    if (-not $KeepTamper) {
        Remove-Item -Force $TamperFile -ErrorAction SilentlyContinue
        Write-Host "[INFO] Removed temporary tamper artifact"
    }
}

Write-Host "[AUDIT PASS] Functional + security checks passed."
exit 0
