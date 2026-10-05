# Phase-2 validation (roadmap 2.1-2.6) on Windows. Same steps as run_phase2_validation.sh.
#
# Usage: powershell -File hardware_3d\scripts\run_phase2_validation.ps1 -OssCadSuite C:\oss-cad-suite `
#            [-CpuBinDir <dir with asm_to_hex/encryptor/cpu exes>] [-TvlaTraces 20000] [-FiTrials 60] [-FiExhaustive]
# python on PATH must have the `cryptography` package.
param(
    [Parameter(Mandatory = $true)][string]$OssCadSuite,
    [string]$OutDir = "",
    [string]$CpuBinDir = "",
    [int]$TvlaTraces = 20000,
    [int]$FiTrials = 60,
    [switch]$FiExhaustive
)
$ErrorActionPreference = 'Continue'
$hw = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $hw
if (-not $OutDir) { $OutDir = Join-Path $root 'results\hardware_eval\phase2' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$env:PATH = "$OssCadSuite\bin;$OssCadSuite\lib;$env:PATH"
$env:VERILATOR_ROOT = "$OssCadSuite\share\verilator"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $hw

$core = 'rtl/crypto3d_stack_pkg.sv','rtl/stacked_memory_3d_model.sv','rtl/vertical_trust_guard.sv',
        'rtl/tier_sentinel_monitor.sv','rtl/aes128_core.sv','rtl/aes_cmac32.sv','rtl/vtf_key_schedule.sv',
        'rtl/crypto3d_vtf_system_top.sv'
$soc = $core + @('rtl/crypto3d_vtf_cpu_bridge.sv','rtl/crypto3d_vtf_soc_top.sv')
$lint = '--lint-only','-Wall','-Wno-TIMESCALEMOD','-Wno-IMPORTSTAR','-Wno-UNUSEDPARAM'

function Run([string]$name, [string]$log, [scriptblock]$cmd, [string]$pattern) {
    $out = & $cmd 2>&1 | ForEach-Object { "$_" }
    $out | Set-Content (Join-Path $OutDir $log)
    $out | Where-Object { $_ -match 'PASS|FAIL|METRIC|FISUM|FITOTAL|max\|t' }
    if ($pattern -and -not ($out -match $pattern)) { throw "$name failed" }
}

Write-Host '== Python references'
Run 'mit reference' 'mit_reference.log' { python scripts/mem_integrity_reference.py --self-test } 'SELF-TEST PASS'
Run 'puf study' 'puf_study.log' { python scripts/puf_fuzzy_extractor.py --study --out (Join-Path $OutDir 'puf_study.json') } ''

Write-Host '== Verilator lint'
$lintRuns = @(
    @('memory_integrity_tree', @('rtl/aes128_core.sv','rtl/aes_cmac32.sv','rtl/memory_integrity_tree.sv'), @()),
    @('mit_untrusted_store', @('rtl/mit_untrusted_store.sv'), @()),
    @('aes_sbox_masked', @('rtl/aes_sbox_masked.sv'), @()),
    @('puf_fuzzy_extractor', @('rtl/aes128_core.sv','rtl/aes_cmac32.sv','rtl/puf_fuzzy_extractor.sv'), @()),
    @('crypto3d_vtf_system_top', $core, @('-GFAULT_HARDEN=1')),
    @('crypto3d_vtf_soc_top', $soc, @())
)
foreach ($l in $lintRuns) {
    $files = $l[1]; $extra = $l[2]
    $o = & verilator_bin.exe @lint @extra --top-module $l[0] @files 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { $o; throw "lint failed: $($l[0])" }
}

Write-Host '== 2.1 memory integrity tree'
& iverilog.exe -g2012 -I tb -o "$OutDir/mit.vvp" rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/mit_untrusted_store.sv rtl/memory_integrity_tree.sv tb/tb_memory_integrity.sv
Run 'tb_memory_integrity' 'tb_memory_integrity.log' { vvp.exe -n "$OutDir/mit.vvp" } 'SV TEST PASS'

Write-Host "== 2.2 masked S-box + simulated TVLA ($TvlaTraces traces)"
& iverilog.exe -g2012 "-Ptb_tvla_sbox.TRACES=$TvlaTraces" -o "$OutDir/tvla.vvp" rtl/aes_sbox_masked.sv tb/tb_tvla_sbox.sv
& vvp.exe -n "$OutDir/tvla.vvp" | Set-Content (Join-Path $OutDir 'tvla_traces.log')
Run 'tvla' 'tvla.log' { python scripts/tvla.py (Join-Path $OutDir 'tvla_traces.log') --out (Join-Path $OutDir 'tvla_summary.json') } 'TVLA FIRST-ORDER PASS'

Write-Host '== 2.3 fault hardening'
& iverilog.exe -g2012 -I tb "-Ptb_vtf_system.FAULT_HARDEN=1" -o "$OutDir/sys_ft.vvp" @core tb/tb_vtf_system.sv
Run 'tb_vtf_system FT' 'tb_vtf_system_ft.log' { vvp.exe -n "$OutDir/sys_ft.vvp" } 'SV TEST PASS'
$modes = @(0); if ($FiExhaustive) { $modes = @(0, 1) }
foreach ($h in 0, 1) {
    foreach ($m in $modes) {
        & iverilog.exe -g2012 -I tb "-Ptb_fault_campaign.FAULT_HARDEN=$h" "-Ptb_fault_campaign.TRIALS=$FiTrials" "-Ptb_fault_campaign.MODE=$m" -o "$OutDir/fi_h${h}_m${m}.vvp" @core tb/tb_fault_campaign.sv
        Run "fault campaign h=$h m=$m" "fi_h${h}_m${m}.log" { vvp.exe -n "$OutDir/fi_h${h}_m${m}.vvp" } 'FI CAMPAIGN DONE'
    }
}
if (-not (Select-String -Path (Join-Path $OutDir 'fi_h1_m0.log') -Pattern 'FITOTAL,1,mode=0,.*violations=0,' -Quiet)) {
    throw 'hardened design has fault-injection violations'
}

Write-Host '== 2.4 PUF fuzzy extractor'
& iverilog.exe -g2012 -I tb -o "$OutDir/puf.vvp" rtl/aes128_core.sv rtl/aes_cmac32.sv rtl/puf_fuzzy_extractor.sv tb/tb_puf_fuzzy_extractor.sv
Run 'tb_puf' 'tb_puf.log' { vvp.exe -n "$OutDir/puf.vvp" } 'SV TEST PASS'

Write-Host '== 2.5 bitstream security constraints (board test = phase 3)'
if (-not (Test-Path constraints/bitstream_security.xdc)) { throw 'bitstream_security.xdc missing' }

Write-Host '== 2.6 CPU bridge + SoC: program traces'
& iverilog.exe -g2012 -I tb -o "$OutDir/soc.vvp" @soc tb/tb_vtf_soc.sv
& iverilog.exe -g2012 -I tb "-Ptb_vtf_soc.FAULT_HARDEN=1" -o "$OutDir/soc_ft.vvp" @soc tb/tb_vtf_soc.sv
if ($CpuBinDir -and (Test-Path $CpuBinDir)) {
    Run 'soc traces' 'soc.log' { python scripts/vtf_trace_overhead.py --bin-dir $CpuBinDir --vvp "$OutDir/soc.vvp" --vvp-ft "$OutDir/soc_ft.vvp" --out (Join-Path $OutDir 'soc') } 'SOC TRACE OVERHEAD PASS'
} else {
    Write-Host '   -CpuBinDir not given; skipping program traces'
}
Write-Host "Phase-2 validation passed. Outputs: $OutDir"
