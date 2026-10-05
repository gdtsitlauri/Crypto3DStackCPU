# Encrypted + authenticated bitstream for a routed design (roadmap 2.5).
#
# Usage:
#   vivado -mode batch -nojournal -nolog -source hardware_3d/scripts/vivado_secure_bitstream.tcl \
#          -tclargs <routed.dcp> <keyfile.nky> <out_dir>
#
#   routed.dcp   a placed-and-routed checkpoint of a board-level top (with I/O
#                constraints such as hardware_3d/constraints/fpga_placeholder_constraints.xdc)
#   keyfile.nky  AES-256 + HMAC key file kept OUTSIDE the repository
#                (generate once, e.g. by a first write_bitstream with
#                 BITSTREAM.ENCRYPTION.KEY0/HKEY set to fresh random values, then
#                 program the same key into BBRAM with Vivado Hardware Manager)
#
# The key file path is checked to be outside this repository so the key cannot
# be committed by accident. Board validation (load succeeds only with the key,
# readback blocked, JTAG closed) is roadmap phase 3.

if {[llength $argv] < 3} {
  puts "usage: -tclargs <routed.dcp> <keyfile.nky> <out_dir>"
  exit 1
}
set dcp     [file normalize [lindex $argv 0]]
set keyfile [file normalize [lindex $argv 1]]
set out_dir [file normalize [lindex $argv 2]]

set script_dir [file dirname [file normalize [info script]]]
set repo_root  [file normalize [file join $script_dir .. ..]]
if {[string first $repo_root $keyfile] == 0} {
  puts "ERROR: key file must live outside the repository ($repo_root)"
  exit 1
}
if {![file exists $keyfile]} {
  puts "ERROR: key file not found: $keyfile"
  exit 1
}

file mkdir $out_dir
open_checkpoint $dcp
read_xdc [file join $script_dir .. constraints bitstream_security.xdc]
set_property BITSTREAM.ENCRYPTION.KEYFILE $keyfile [current_design]

report_property [current_design] -regexp {BITSTREAM\..*} -file [file join $out_dir bitstream_properties.rpt]
write_bitstream -force [file join $out_dir crypto3d_vtf_secure.bit]
puts "Encrypted bitstream written to $out_dir (key not stored in the repository)"
