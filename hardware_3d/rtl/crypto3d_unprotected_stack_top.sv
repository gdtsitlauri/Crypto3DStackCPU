// SPDX-License-Identifier: MIT
// Unprotected baseline for crypto3d_secure_stack_top.
//
// Identical ports and the same behavioral 3D memory, but no Vertical Trust
// Guard: every request reaches the memory. It exists only to measure the
// area/timing cost of the guard (scripts/vivado_synth.tcl) and to show which
// attacks the guard is responsible for stopping (tb/tb_vtf_attack_campaign.sv).
// Security inputs are intentionally ignored.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module crypto3d_unprotected_stack_top #(
  parameter int LAYERS = C3D_LAYERS,
  parameter int WORDS = C3D_WORDS
) (
  input  logic clk,
  input  logic rst_n,

  input  logic req_valid_i,
  /* verilator lint_off UNUSEDSIGNAL */
  input  logic [2:0] requester_i,
  input  logic [31:0] sequence_i,
  input  logic [31:0] epoch_i,
  input  logic [31:0] active_epoch_i,
  input  logic auth_ok_i,
  input  logic debug_unlocked_i,
  input  c3d_layer_role_t layer_role_i [LAYERS],
  input  logic signed [17:0] temperature_mc_i [LAYERS],
  input  logic physical_fault_i,
  input  logic sentinel_fault_i,
  /* verilator lint_on UNUSEDSIGNAL */
  input  logic op_write_i,
  input  logic [C3D_LAYER_WIDTH-1:0] layer_i,
  input  logic [C3D_ADDR_WIDTH-1:0] addr_i,
  input  logic [31:0] wdata_i,
  input  logic layer_access_i [LAYERS],
  input  logic fault_inject_i,
  input  logic [31:0] fault_mask_i,

  output logic [31:0] rdata_o,
  output logic ready_o,
  output logic denied_o,
  output logic tamper_o,
  output logic lockdown_o,
  output logic key_zeroize_o,
  output logic [7:0] deny_reason_o
);

  stacked_memory_3d_model #(.LAYERS(LAYERS), .WORDS(WORDS)) mem_i (
    .clk(clk),
    .rst_n(rst_n),
    .layer_i(layer_i),
    .addr_i(addr_i),
    .wdata_i(wdata_i),
    .ren_i(req_valid_i && !op_write_i),
    .wen_i(req_valid_i && op_write_i),
    .layer_access_i(layer_access_i),
    .tamper_clear_i(1'b0),
    .fault_inject_i(fault_inject_i),
    .fault_mask_i(fault_mask_i),
    .rdata_o(rdata_o),
    .ready_o(ready_o),
    .denied_o(denied_o),
    .tamper_o(tamper_o)
  );

  assign lockdown_o = 1'b0;
  assign key_zeroize_o = 1'b0;
  assign deny_reason_o = 8'd0;

endmodule
