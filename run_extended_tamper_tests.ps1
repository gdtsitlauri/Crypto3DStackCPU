param(
    [string]$AsmFile = "programs\demo.asm",
    [string]$ImageFile = "demo.hex",
    [string]$ContractFile = "programs\demo.contract",
    [string]$TextFile = "text.hex",
    [string]$DataFile = "data.hex",
    [string]$ResealedImageFile = "demo_after.hex",
    [string]$PipelineScript = ".\run_pipeline.ps1",
    [string]$Cxx = "g++",
    [switch]$SkipPipeline,
    [switch]$KeepTamperFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required file not found: $Path"
    }
}

function Invoke-Checked {
    param([string]$Name, [scriptblock]$Command)
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
        [string]$Name,
        [string]$TamperPath,
        [string]$ContractPath
    )

    Write-Host ""
    Write-Host "[TAMPER] $Name"

    $result = Invoke-NativeCaptured -Exe ".\3d_test_single.exe" -Arguments @($TamperPath, $ContractPath)

    if ($result.ExitCode -eq 0) {
        Write-Host $result.Output
        throw "Tamper case unexpectedly passed: $Name"
    }

    Write-Host "[PASS] Rejected as expected with exit code $($result.ExitCode)"
    if ($result.Output.Length -gt 0) {
        Write-Host $result.Output
    }
}

function Read-HexImage {
    param([string]$Path)
    $lines = Get-Content -LiteralPath $Path
    $words = New-Object System.Collections.Generic.List[string]
    $lineNo = 0
    foreach ($line in $lines) {
        $lineNo++
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t -notmatch '^[0-9A-Fa-f]{1,8}$') {
            throw "Invalid hex word in $Path at line $lineNo`: '$line'"
        }
        $words.Add(("{0:X8}" -f ([Convert]::ToUInt32($t, 16))))
    }
    return ,$words.ToArray()
}

function Write-HexImage {
    param([string]$Path, [string[]]$Words)
    Set-Content -LiteralPath $Path -Value $Words -Encoding ascii
}

function Flip-Index {
    param([string[]]$Words, [int]$Index, [uint32]$Mask = 1)
    if ($Index -lt 0 -or $Index -ge $Words.Count) {
        throw "Tamper index out of bounds: $Index"
    }
    $old = [Convert]::ToUInt32($Words[$Index], 16)
    $new = $old -bxor $Mask
    $Words[$Index] = "{0:X8}" -f $new
    Write-Host ("[INFO] index {0}: 0x{1:X8} -> 0x{2:X8}" -f $Index, $old, $new)
}

Write-Host "============================================================"
Write-Host " Crypto3DStackCPU extended tamper test suite"
Write-Host "============================================================"

if (-not $SkipPipeline) {
    Assert-FileExists $PipelineScript
    Invoke-Checked "Generate fresh sealed image through pipeline" {
        & $PipelineScript `
            -AsmFile $AsmFile `
            -TextFile $TextFile `
            -DataFile $DataFile `
            -ImageFile $ImageFile `
            -ContractFile $ContractFile `
            -ResealedImageFile $ResealedImageFile `
            -Cxx $Cxx `
            -SkipResealedSecondRun
    }
}

Assert-FileExists $ImageFile
Assert-FileExists $ContractFile
Assert-FileExists ".\3d_test_single.exe"

$words = Read-HexImage $ImageFile

$SEC_HDR_W_TEXT_START = 4
$SEC_HDR_W_TEXT_END = 6
$SEC_HDR_W_WRAP0 = 12
$SEC_HDR_W_KEYTAG0 = 16
$SEC_HDR_W_IMGTAG0 = 20
$SEC_HDR_W_DATA_START = 28
$SEC_HDR_W_DATA_END = 30

$textStart = [Convert]::ToUInt32($words[$SEC_HDR_W_TEXT_START], 16)
$textEnd = [Convert]::ToUInt32($words[$SEC_HDR_W_TEXT_END], 16)
$dataStart = [Convert]::ToUInt32($words[$SEC_HDR_W_DATA_START], 16)
$dataEnd = [Convert]::ToUInt32($words[$SEC_HDR_W_DATA_END], 16)

$cases = @(
    @{ Name = "header_magic"; Index = 0; Mask = 1 },
    @{ Name = "header_policy"; Index = 3; Mask = 1 },
    @{ Name = "wrapped_key_word"; Index = $SEC_HDR_W_WRAP0; Mask = 1 },
    @{ Name = "key_tag_word"; Index = $SEC_HDR_W_KEYTAG0; Mask = 1 },
    @{ Name = "image_tag_word"; Index = $SEC_HDR_W_IMGTAG0; Mask = 1 },
    @{ Name = "encrypted_text_word"; Index = [int]($textStart + 2); Mask = 1 }
)

if ($dataEnd -gt $dataStart) {
    $cases += @{ Name = "encrypted_data_word"; Index = [int]$dataStart; Mask = 1 }
}

foreach ($case in $cases) {
    $tampered = [string[]]$words.Clone()
    $tamperPath = "tamper_$($case.Name).hex"
    Flip-Index -Words $tampered -Index ([int]$case.Index) -Mask ([uint32]$case.Mask)
    Write-HexImage -Path $tamperPath -Words $tampered

    try {
        Invoke-ExpectFailure -Name $case.Name -TamperPath $tamperPath -ContractPath $ContractFile
    }
    finally {
        if (-not $KeepTamperFiles) {
            Remove-Item -LiteralPath $tamperPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ""
Write-Host "[PASS] Extended tamper suite passed."
exit 0

