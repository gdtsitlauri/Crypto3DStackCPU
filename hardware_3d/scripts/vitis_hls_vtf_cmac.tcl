# Vitis HLS flow for the VTF AES-CMAC authenticator (src/vtf_hls.cpp).
#
# Usage:
#   vitis_hls -f hardware_3d/scripts/vitis_hls_vtf_cmac.tcl \
#             -tclargs [part] [out_dir] [cosim] [rtl_synth] [period_ns]
#   (Vitis 2024.2+: vitis-run --mode hls --tcl hardware_3d/scripts/vitis_hls_vtf_cmac.tcl ...)
#
#   part       default xc7a200tfbg676-2
#   out_dir    default results/hardware_eval/hls
#   cosim      1 = run C/RTL co-simulation with the same testbench (default 1)
#   rtl_synth  1 = export_design -flow syn: post-synthesis LUT/FF/BRAM/timing (default 1)
#   period_ns  default 10.0
#
# Steps: csim (src/vtf_hls_tb.cpp, independent AES-CMAC reference vectors) ->
# csynth -> [cosim] -> [Vivado synthesis of the generated RTL].
# Reports: <out_dir>/vtf_cmac/sol1/syn/report/*_csynth.xml and impl/report/.

# Arguments may also come from the environment (C3D_PART, C3D_HLS_OUT,
# C3D_COSIM, C3D_RTL_SYNTH, C3D_PERIOD) for launchers without -tclargs.
if {![info exists argv]} { set argv {} }
proc arg_or_env {idx env_name default} {
  global argv
  if {[llength $argv] > $idx} { return [lindex $argv $idx] }
  if {[info exists ::env($env_name)]} { return $::env($env_name) }
  return $default
}
set part      [arg_or_env 0 C3D_PART      "xc7a200tfbg676-2"]
set out_dir   [arg_or_env 1 C3D_HLS_OUT   "results/hardware_eval/hls"]
set do_cosim  [arg_or_env 2 C3D_COSIM     1]
set do_syn    [arg_or_env 3 C3D_RTL_SYNTH 1]
set period    [arg_or_env 4 C3D_PERIOD    10.0]

set script_dir [file dirname [file normalize [info script]]]
set src_dir    [file normalize [file join $script_dir .. .. src]]
set out_dir    [file normalize $out_dir]
file mkdir $out_dir
cd $out_dir

set cflags "-std=c++14 -I$src_dir -Wno-unknown-pragmas"

open_project -reset vtf_cmac
set_top crypto3d_vtf_cmac_verify
add_files $src_dir/vtf_hls.cpp -cflags $cflags
add_files $src_dir/3d.cpp      -cflags $cflags
add_files -tb $src_dir/vtf_hls_tb.cpp -cflags $cflags

open_solution -reset sol1 -flow_target vivado
set_part $part
create_clock -period $period -name default

csim_design
csynth_design
if {$do_cosim} {
  cosim_design -rtl verilog
}
if {$do_syn} {
  export_design -flow syn -rtl verilog -format ip_catalog
}
exit
