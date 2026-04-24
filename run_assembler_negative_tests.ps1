param(
    [string]$Cxx = "g++",
    [string]$WorkDir = "tests\assembler_negative"
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
        [Parameter(Mandatory = $true)][string]$AsmPath,
        [Parameter(Mandatory = $true)][string]$TextOut,
        [Parameter(Mandatory = $true)][string]$DataOut
    )

    Write-Host ""
    Write-Host "[NEGATIVE] $Name"

    $result = Invoke-NativeCaptured -Exe ".\asm_to_hex.exe" -Arguments @($AsmPath, $TextOut, $DataOut)

    if ($result.ExitCode -eq 0) {
        Write-Host "[ERROR] Negative test unexpectedly succeeded. Output:"
        Write-Host $result.Output
        throw "Negative assembler test failed: $Name"
    }

    Write-Host "[PASS] Rejected as expected with exit code $($result.ExitCode)"
    if ($result.Output.Length -gt 0) {
        Write-Host $result.Output
    }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$tests = @{
"branch_misaligned.asm" = @'
.text
main:
    addi $t0, $zero, 1
    beq  $t0, $t0, bad
    nop
bad:
    nop
'@;

"jump_misaligned.asm" = @'
.text
main:
    j target
    nop
target:
    nop
'@;

"data_branch_target.asm" = @'
.data
x: .word 0x12345678
.text
main:
    beq $zero, $zero, x
    nop
    nop
    nop
'@;

"duplicate_label.asm" = @'
.text
main:
    nop
main:
    nop
'@;

"bad_register.asm" = @'
.text
main:
    add $x0, $t0, $t1
'@;

"unknown_instruction.asm" = @'
.text
main:
    frob $t0, $t1, $t2
'@;

"unaligned_lw_offset.asm" = @'
.text
main:
    lw $t0, 2($zero)
'@;
}

foreach ($name in $tests.Keys) {
    Set-Content -LiteralPath (Join-Path $WorkDir $name) -Value $tests[$name] -Encoding ascii
}

$CommonFlags = @("-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Wno-unknown-pragmas")

Invoke-Checked "Build custom assembler" {
    & $Cxx @CommonFlags "src\asm_to_hex.cpp" "-o" "asm_to_hex.exe"
}

foreach ($name in ($tests.Keys | Sort-Object)) {
    $asm = Join-Path $WorkDir $name
    $textOut = Join-Path $WorkDir ($name + ".text.hex")
    $dataOut = Join-Path $WorkDir ($name + ".data.hex")

    Invoke-ExpectFailure -Name $name -AsmPath $asm -TextOut $textOut -DataOut $dataOut
}

Write-Host ""
Write-Host "[PASS] All assembler negative tests were rejected."
exit 0

