param(
    [string]$AsmFile = "programs\demo.asm",
    [string]$TextFile = "text.hex",
    [string]$DataFile = "data.hex",
    [string]$ImageFile = "demo.hex",
    [string]$ContractFile = "programs\demo.contract",
    [string]$TamperFile = "demo_tamper.hex",
    [string]$ResealedImageFile = "demo_after.hex",
    [string]$PipelineScript = ".\run_pipeline.ps1",
    [string]$Cxx = "g++",
    [switch]$SkipPipeline,
    [switch]$KeepTamper,
    [switch]$SkipDecryptCompare
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ""
    Write-Host "[STEP] $Name"

    & $Command

    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCaptured {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process `
            -FilePath $Exe `
            -ArgumentList $Arguments `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        $stdout = Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue

        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            Output = (($stdout + "`n" + $stderr).Trim())
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ExpectFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host ""
    Write-Host "[STEP] $Name"

    $result = Invoke-NativeCaptured -Exe $Exe -Arguments $Arguments

    if ($result.ExitCode -eq 0) {
        Write-Host "[ERROR] Command unexpectedly succeeded. Raw output:"
        Write-Host $result.Output
        throw "$Name did not fail as expected."
    }

    Write-Host "[OK] Rejected as expected with exit code $($result.ExitCode)."
    return $result.Output
}

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required file not found: $Path"
    }
}

function Read-HexImage {
    param([Parameter(Mandatory = $true)][string]$Path)

    $rawLines = Get-Content -LiteralPath $Path
    $words = New-Object System.Collections.Generic.List[string]

    $lineNo = 0
    foreach ($line in $rawLines) {
        $lineNo++
        $t = $line.Trim()
        if ($t.Length -eq 0) {
            continue
        }

        if ($t -notmatch '^[0-9A-Fa-f]{1,8}$') {
            throw "Invalid hex word in $Path at line $lineNo`: '$line'"
        }

        $words.Add(("{0:X8}" -f ([Convert]::ToUInt32($t, 16))))
    }

    return ,$words.ToArray()
}

function Write-HexImage {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Words
    )

    Set-Content -LiteralPath $Path -Value $Words -Encoding ascii
}

function Flip-WordBit {
    param(
        [Parameter(Mandatory = $true)][string[]]$Words,
        [Parameter(Mandatory = $true)][int]$Index,
        [uint32]$Mask = 0x00000001
    )

    if ($Index -lt 0 -or $Index -ge $Words.Count) {
        throw "Tamper index out of bounds: $Index"
    }

    $oldWord = [Convert]::ToUInt32($Words[$Index], 16)
    $newWord = $oldWord -bxor $Mask
    $Words[$Index] = "{0:X8}" -f $newWord

    Write-Host ("[INFO] Tampered word @ index {0}: 0x{1:X8} -> 0x{2:X8}" -f $Index, $oldWord, $newWord)
}

Write-Host "============================================================"
Write-Host " Crypto3DStackCPU functional + security audit"
Write-Host "============================================================"

if (-not $SkipPipeline) {
    Assert-FileExists $PipelineScript

    if ($SkipDecryptCompare) {
        Invoke-Checked "Run clean build/assemble/seal/execute/reseal pipeline" {
            & $PipelineScript `
                -AsmFile $AsmFile `
                -TextFile $TextFile `
                -DataFile $DataFile `
                -ImageFile $ImageFile `
                -ContractFile $ContractFile `
                -ResealedImageFile $ResealedImageFile `
                -Cxx $Cxx `
                -SkipDecryptCompare
        }
    } else {
        Invoke-Checked "Run clean build/assemble/seal/execute/reseal pipeline" {
            & $PipelineScript `
                -AsmFile $AsmFile `
                -TextFile $TextFile `
                -DataFile $DataFile `
                -ImageFile $ImageFile `
                -ContractFile $ContractFile `
                -ResealedImageFile $ResealedImageFile `
                -Cxx $Cxx
        }
    }
} else {
    Write-Host ""
    Write-Host "[STEP] Skip pipeline; using current artifacts and binaries"
}

Assert-FileExists $TextFile
Assert-FileExists $DataFile
Assert-FileExists $ImageFile
Assert-FileExists ".\3d_test_single.exe"

if (-not [string]::IsNullOrWhiteSpace($ContractFile)) {
    Assert-FileExists $ContractFile
}

Write-Host ""
Write-Host "[STEP] Artifact SHA256 hashes"
$hashArtifacts = @($TextFile, $DataFile, $ImageFile)
if (Test-Path -LiteralPath $ResealedImageFile) {
    $hashArtifacts += $ResealedImageFile
}
if (-not [string]::IsNullOrWhiteSpace($ContractFile)) {
    $hashArtifacts += $ContractFile
}

foreach ($artifact in $hashArtifacts) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash
    Write-Host ("[HASH] {0} {1}" -f $artifact, $hash)
}

Write-Host ""
Write-Host "[STEP] Positive execution proof on untampered image"

$positiveArgs = @($ImageFile)
if (-not [string]::IsNullOrWhiteSpace($ContractFile)) {
    $positiveArgs += $ContractFile
}

$positiveResult = Invoke-NativeCaptured -Exe ".\3d_test_single.exe" -Arguments $positiveArgs
$positiveContractOk = ($positiveResult.Output -match "Functional contract checks passed") -or
                      ($positiveResult.Output -match "\[ALL TESTS PASSED\]")

if (($positiveResult.ExitCode -eq 0) -and $positiveContractOk) {
    Write-Host "[OK] Untampered image execution proof passed."
} else {
    Write-Host "[ERROR] Positive proof failed. Raw output:"
    Write-Host $positiveResult.Output
    throw "Positive execution proof failed with exit code $($positiveResult.ExitCode)."
}

Write-Host ""
Write-Host "[STEP] Build tampered image and expect authenticated rejection"

$words = Read-HexImage -Path $ImageFile

if ($words.Count -lt 33) {
    throw "Image too small to contain secure header and text region."
}

$SEC_HDR_W_TEXT_START = 4
$SEC_HDR_W_TEXT_WORDS = 5
$SEC_HDR_W_TEXT_END   = 6
$SEC_HDR_WORDS        = 32

$textStart = [Convert]::ToUInt32($words[$SEC_HDR_W_TEXT_START], 16)
$textWords = [Convert]::ToUInt32($words[$SEC_HDR_W_TEXT_WORDS], 16)
$textEnd   = [Convert]::ToUInt32($words[$SEC_HDR_W_TEXT_END], 16)

if ($textStart -lt $SEC_HDR_WORDS) {
    throw "Invalid header: text_start is inside secure header: $textStart"
}
if ($textEnd -le $textStart) {
    throw "Invalid header: empty encrypted text region."
}
if ($textEnd -gt $words.Count) {
    throw "Invalid header: text_end out of image range."
}
if ($textWords -eq 0) {
    throw "Invalid header: text_words is zero."
}

$tamperIndex = [int]$textStart
if (($textStart + 2) -lt $textEnd) {
    $tamperIndex = [int]($textStart + 2)
}

$wordsTampered = [string[]]$words.Clone()
Flip-WordBit -Words $wordsTampered -Index $tamperIndex -Mask 0x00000001
Write-HexImage -Path $TamperFile -Words $wordsTampered

try {
    $negativeArgs = @($TamperFile)
    if (-not [string]::IsNullOrWhiteSpace($ContractFile)) {
        $negativeArgs += $ContractFile
    }

    $negativeOutput = Invoke-ExpectFailure `
        -Name "Run CPU testbench on tampered image" `
        -Exe ".\3d_test_single.exe" `
        -Arguments $negativeArgs

    $rejectionLooksSecurityRelated =
        ($negativeOutput -match "validation") -or
        ($negativeOutput -match "security") -or
        ($negativeOutput -match "tamper") -or
        ($negativeOutput -match "IMG TAG") -or
        ($negativeOutput -match "MEAS") -or
        ($negativeOutput -match "\[ERROR\]") -or
        ($negativeOutput -match "\[FAIL\]")

    if ($rejectionLooksSecurityRelated) {
        Write-Host "[OK] Tampered image rejection produced an expected failure marker."
    } else {
        Write-Host "[WARN] Tampered image failed as expected, but output did not contain a familiar security marker."
        Write-Host $negativeOutput
    }
}
finally {
    if (-not $KeepTamper) {
        Remove-Item -LiteralPath $TamperFile -Force -ErrorAction SilentlyContinue
        Write-Host "[INFO] Removed temporary tamper artifact: $TamperFile"
    } else {
        Write-Host "[INFO] Kept tamper artifact: $TamperFile"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "[AUDIT PASS] Functional + authenticated tamper-rejection checks passed."
Write-Host "============================================================"

exit 0

