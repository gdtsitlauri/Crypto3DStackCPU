# Vivado out-of-context PPA evaluation of the Vertical Trust Fabric RTL.
#
# Synthesizes (and optionally places/routes) every top with the same part and
# clock so overheads are direct differences:
#   crypto3d_unprotected_stack_top  baseline: 3D memory only
#   crypto3d_secure_stack_top       VTF guard + same memory (external auth_ok)
#   vertical_trust_guard            guard alone
#   aes_cmac32                      iterative AES-128 + CMAC engine
#   crypto3d_vtf_system_top         integrated system (in-RTL CMAC, keys, sentinel)
#   crypto3d_vtf_system_top_ft      same with FAULT_HARDEN=1 (roadmap 2.3)
#   memory_integrity_tree           memory encryption + integrity tree (roadmap 2.1)
#   aes_sbox_masked                 first-order DOM masked S-box (roadmap 2.2)
#   puf_fuzzy_extractor             PUF key reconstruction (roadmap 2.4)
#
# Usage (from any directory):
#   vivado -mode batch -nojournal -nolog -source hardware_3d/scripts/vivado_synth.tcl \
#          -tclargs [part] [out_dir] [impl] [period_ns]
#   part      default xc7a200tfbg676-2 (AC701, as in 3D_hls_config.cfg)
#   out_dir   default results/hardware_eval/vivado
#   impl      0 = synthesis only (default), 1 = also opt/place/route + power
#   period_ns default 10.0 (100 MHz)
#
# Reports per top in <out_dir>/<top>/: utilization_{synth,impl}.rpt,
# timing_{synth,impl}.rpt, power_impl.rpt, and a .dcp checkpoint.
# collect_hardware_results.py turns them into the paper table.

set part      [expr {[llength $argv] > 0 ? [lindex $argv 0] : "xc7a200tfbg676-2"}]
set out_dir   [expr {[llength $argv] > 1 ? [lindex $argv 1] : "results/hardware_eval/vivado"}]
set do_impl   [expr {[llength $argv] > 2 ? [lindex $argv 2] : 0}]
set period    [expr {[llength $argv] > 3 ? [lindex $argv 3] : 10.0}]

set script_dir [file dirname [file normalize [info script]]]
set rtl_dir    [file normalize [file join $script_dir .. rtl]]
set out_dir    [file normalize $out_dir]
file mkdir $out_dir

set sources [list \
  [file join $rtl_dir crypto3d_stack_pkg.sv] \
  [file join $rtl_dir stacked_memory_3d_model.sv] \
  [file join $rtl_dir vertical_trust_guard.sv] \
  [file join $rtl_dir tier_sentinel_monitor.sv] \
  [file join $rtl_dir crypto3d_secure_stack_top.sv] \
  [file join $rtl_dir crypto3d_unprotected_stack_top.sv] \
  [file join $rtl_dir aes128_core.sv] \
  [file join $rtl_dir aes_cmac32.sv] \
  [file join $rtl_dir vtf_key_schedule.sv] \
  [file join $rtl_dir crypto3d_vtf_system_top.sv] \
  [file join $rtl_dir memory_integrity_tree.sv] \
  [file join $rtl_dir aes_sbox_masked.sv] \
  [file join $rtl_dir puf_fuzzy_extractor.sv] \
]

set xdc [file join $out_dir ooc_clock_${period}ns.xdc]
set fh [open $xdc w]
puts $fh "create_clock -period $period -name clk \[get_ports clk\]"
close $fh

set manifest [open [file join $out_dir run_manifest.txt] w]
puts $manifest "vivado_version=[version -short]"
puts $manifest "part=$part"
puts $manifest "period_ns=$period"
puts $manifest "impl=$do_impl"
if {[catch {clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S}} run_date]} {
  set run_date [clock seconds]
}
puts $manifest "date=$run_date"

foreach run {crypto3d_unprotected_stack_top crypto3d_secure_stack_top vertical_trust_guard
             aes_cmac32 crypto3d_vtf_system_top crypto3d_vtf_system_top_ft
             memory_integrity_tree aes_sbox_masked puf_fuzzy_extractor} {
  set top $run
  set generics {}
  if {$run eq "crypto3d_vtf_system_top_ft"} {
    set top crypto3d_vtf_system_top
    set generics [list -generic FAULT_HARDEN=1]
  }
  set d [file join $out_dir $run]
  file mkdir $d
  puts "=== $top ($part, ${period} ns) ==="
  create_project -in_memory -part $part -force
  read_verilog -sv $sources
  read_xdc -mode out_of_context $xdc
  synth_design -top $top -part $part -mode out_of_context -flatten_hierarchy rebuilt {*}$generics
  report_utilization    -file [file join $d utilization_synth.rpt]
  report_timing_summary -file [file join $d timing_synth.rpt] -max_paths 10
  report_ram_utilization -file [file join $d ram_synth.rpt]
  write_checkpoint -force [file join $d ${run}_synth.dcp]

  if {$do_impl} {
    opt_design
    place_design
    route_design
    report_utilization    -file [file join $d utilization_impl.rpt]
    report_timing_summary -file [file join $d timing_impl.rpt] -max_paths 10
    report_power          -file [file join $d power_impl.rpt]
    write_checkpoint -force [file join $d ${run}_routed.dcp]
  }
  puts $manifest "completed=$run"
  close_project
}
close $manifest
puts "Vivado PPA reports written to $out_dir"
