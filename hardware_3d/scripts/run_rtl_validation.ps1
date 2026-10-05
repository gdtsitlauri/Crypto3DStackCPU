# RTL validation for the Vertical Trust Fabric on Windows (free tools only).
# Same steps as run_rtl_validation.sh: Verilator lint, Icarus simulation of
# five testbenches (fail-closed), Yosys+slang xc7 estimate, SymbiYosys formal
# proof + mutation check of the guard.
#
# Requires the OSS CAD Suite for Windows (unpacked .tgz from
# https://github.com/YosysHQ/oss-cad-suite-build/releases).
# Use a path without '--' or spaces for -OssCadSuite (e.g. C:\oss-cad-suite):
# Yosys' ABC step fails on some long Windows paths, in which case the script
# falls back to Yosys' classic LUT mapper for the estimate.
#
# Usage: powershell -File hardware_3d\scripts\run_rtl_validation.ps1 -OssCadSuite C:\oss-cad-suite
param(
    [Parameter(Mandatory = $true)][string]$OssCadSuite,
    [string]$OutDir = ""
)
# Native tools print warnings on stderr; failures are detected via exit codes.
$ErrorActionPreference = 'Continue'
$hw = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $hw
if (-not $OutDir) { $OutDir = Join-Path $root 'results\hardware_eval\rtl' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$env:PATH = "$OssCadSuite\bin;$OssCadSuite\lib;$env:PATH"
$env:VERILATOR_ROOT = "$OssCadSuite\share\verilator"
Set-Location $hw

$core = 'rtl/crypto3d_stack_pkg.sv','rtl/stacked_memory_3d_model.sv','rtl/vertical_trust_guard.sv',
        'rtl/tier_sentinel_monitor.sv','rtl/crypto3d_secure_stack_top.sv','rtl/crypto3d_unprotected_stack_top.sv'

$sys = $core + @('rtl/aes128_core.sv','rtl/aes_cmac32.sv','rtl/vtf_key_schedule.sv','rtl/crypto3d_vtf_system_top.sv')

Write-Host '== Verilator lint'
foreach ($top in 'crypto3d_secure_stack_top','crypto3d_unprotected_stack_top','tier_sentinel_monitor') {
    # verilator is a Perl wrapper; call the binary directly on Windows.
    $log = & verilator_bin.exe --lint-only -Wall -Wno-TIMESCALEMOD -Wno-IMPORTSTAR -Wno-UNUSEDPARAM --top-module $top @core 2>&1 | ForEach-Object { "$_" }
    $log | Set-Content (Join-Path $OutDir "lint_$top.log")
    if ($LASTEXITCODE -ne 0) { $log; throw "lint failed: $top" }
}
$log = & verilator_bin.exe --lint-only -Wall -Wno-TIMESCALEMOD -Wno-IMPORTSTAR -Wno-UNUSEDPARAM --top-module crypto3d_vtf_system_top @sys 2>&1 | ForEach-Object { "$_" }
$log | Set-Content (Join-Path $OutDir 'lint_crypto3d_vtf_system_top.log')
if ($LASTEXITCODE -ne 0) { $log; throw 'lint failed: crypto3d_vtf_system_top' }

Write-Host '== Icarus simulation'
foreach ($tb in 'tb_vertical_trust_guard','tb_stacked_memory_3d_model','tb_vtf_attack_campaign') {
    $vvp = Join-Path $OutDir "$tb.vvp"
    & iverilog.exe -g2012 -o $vvp @core "tb/$tb.sv"
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $tb" }
    $log = & vvp.exe -n $vvp 2>&1 | ForEach-Object { "$_" }
    $log | Set-Content (Join-Path $OutDir "$tb.log")
    $log | Where-Object { $_ -match 'PASS|FAIL|SUMMARY' }
    if (-not ($log -match '\[SV TEST PASS\]')) { throw "simulation failed: $tb" }
}
$log = Get-Content (Join-Path $OutDir 'tb_vtf_attack_campaign.log')
$log | Where-Object { $_ -match '^CAMPAIGN(_HEADER)?,' } | ForEach-Object { $_ -replace '^CAMPAIGN(_HEADER)?,', '' } |
    Set-Content (Join-Path $OutDir 'attack_campaign.csv')
foreach ($tb in 'tb_aes_cmac32','tb_vtf_system') {
    $vvp = Join-Path $OutDir "$tb.vvp"
    & iverilog.exe -g2012 -I tb -o $vvp @sys "tb/$tb.sv"
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $tb" }
    $log = & vvp.exe -n $vvp 2>&1 | ForEach-Object { "$_" }
    $log | Set-Content (Join-Path $OutDir "$tb.log")
    $log | Where-Object { $_ -match 'PASS|FAIL|METRIC' }
    if (-not ($log -match '\[SV TEST PASS\]')) { throw "simulation failed: $tb" }
}
$log = Get-Content (Join-Path $OutDir 'tb_vtf_system.log')
$log | Where-Object { $_ -match '^CAMPAIGN(_HEADER)?,' } | ForEach-Object { $_ -replace '^CAMPAIGN(_HEADER)?,', '' } |
    Set-Content (Join-Path $OutDir 'system_campaign.csv')
$log | Where-Object { $_ -match '^METRIC,' } | ForEach-Object { $_ -replace '^METRIC,', '' } |
    Set-Content (Join-Path $OutDir 'system_metrics.csv')

Write-Host '== Yosys xc7 synthesis estimate'
$c = $sys -join ' '
foreach ($top in 'vertical_trust_guard','crypto3d_unprotected_stack_top','crypto3d_secure_stack_top','aes_cmac32','crypto3d_vtf_system_top') {
    $stat = (Join-Path $OutDir "yosys_$top.stat") -replace '\\', '/'
    & yosys.exe -q -m slang -p "read_slang $c --top $top; synth_xilinx -family xc7 -top $top -noiopad -noclkbuf; tee -q -o $stat stat" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   (abc9 unavailable on this path; using classic LUT mapping for $top)"
        & yosys.exe -q -m slang -p "read_slang $c --top $top; synth_xilinx -family xc7 -top $top -noiopad -noclkbuf -run :map_luts; abc -luts 2:2,3,6:5; clean; tee -q -o $stat stat" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "yosys synthesis failed: $top" }
    }
    $cells = Get-Content $stat | Where-Object { $_ -match '^\s+\d+\s+(cells|.lut|FDRE|FDSE|RAMB36E1|RAMB18E1|CARRY4)\s*$' } | ForEach-Object { $_.Trim() } | Select-Object -Unique
    Write-Host ("   {0}: {1}" -f $top, ($cells -join ' | '))
}
Write-Host '== SymbiYosys formal proof of vertical_trust_guard (+ cover, mutation check)'
Push-Location (Join-Path $hw 'formal')
$log = & sby.exe -f vertical_trust_guard.sby prove prove_ft cover 2>&1 | ForEach-Object { "$_" }
$log | Set-Content (Join-Path $OutDir 'formal_sby.log')
$log | Where-Object { $_ -match 'DONE' }
if (-not ($log -match 'vertical_trust_guard_prove.*DONE \(PASS')) { Pop-Location; throw 'formal prove failed' }
if (-not ($log -match 'vertical_trust_guard_cover.*DONE \(PASS')) { Pop-Location; throw 'formal cover failed' }
if (-not ($log -match 'vertical_trust_guard_prove_ft.*DONE \(PASS')) { Pop-Location; throw 'formal prove_ft failed' }
$log = & python run_mutation_check.py 2>&1 | ForEach-Object { "$_" }
$log | Set-Content (Join-Path $OutDir 'formal_mutation.log')
$log
Copy-Item mutation_results.json (Join-Path $OutDir 'formal_mutation_results.json')
Pop-Location
if (-not ($log -match 'FORMAL MUTATION CHECK PASS')) { throw 'formal mutation check failed' }
Write-Host "RTL validation passed. Outputs: $OutDir"
