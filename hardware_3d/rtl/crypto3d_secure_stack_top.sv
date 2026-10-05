// SPDX-License-Identifier: MIT
// Integration-oriented secure 3D stack top.
//
// auth_ok_i is expected to come from an AES-CMAC authentication block (the
// repository includes an HLS-facing CMAC implementation in src/vtf_hls.cpp).
// This top connects the policy/replay/thermal guard to the behavioral 3D
// memory model and provides a key-tier zeroize indication for secure boot/key
// management logic.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module crypto3d_secure_stack_top #(
  parameter int LAYERS = C3D_LAYERS,
  parameter int WORDS = C3D_WORDS
) (
  input  logic clk,
  input  logic rst_n,

  input  logic req_valid_i,
  input  logic [2:0] requester_i,
  input  logic op_write_i,
  input  logic [C3D_LAYER_WIDTH-1:0] layer_i,
  input  logic [C3D_ADDR_WIDTH-1:0] addr_i,
  input  logic [31:0] wdata_i,
  input  logic [31:0] sequence_i,
  input  logic [31:0] epoch_i,
  input  logic [31:0] active_epoch_i,
  input  logic auth_ok_i,
  input  logic debug_unlocked_i,

  input  c3d_layer_role_t layer_role_i [LAYERS],
  input  logic layer_access_i [LAYERS],
  input  logic signed [17:0] temperature_mc_i [LAYERS],
  input  logic physical_fault_i,
  input  logic sentinel_fault_i,
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

  logic allow;
  logic guard_denied;
  logic severe_event;
  logic mem_ready;
  logic mem_denied;
  logic mem_tamper;

  vertical_trust_guard #(.LAYERS(LAYERS)) guard_i (
    .clk(clk),
    .rst_n(rst_n),
    .req_valid_i(req_valid_i),
    .requester_i(requester_i),
    .op_write_i(op_write_i),
    .layer_i(layer_i),
    .sequence_i(sequence_i),
    .epoch_i(epoch_i),
    .active_epoch_i(active_epoch_i),
    .auth_ok_i(auth_ok_i),
    .debug_unlocked_i(debug_unlocked_i),
    .layer_role_i(layer_role_i),
    .temperature_mc_i(temperature_mc_i),
    .physical_fault_i(physical_fault_i),
    .sentinel_fault_i(sentinel_fault_i),
    .allow_o(allow),
    .denied_o(guard_denied),
    .lockdown_o(lockdown_o),
    .severe_event_o(severe_event),
    .key_zeroize_o(key_zeroize_o),
    .deny_reason_o(deny_reason_o)
  );

  stacked_memory_3d_model #(.LAYERS(LAYERS), .WORDS(WORDS)) mem_i (
    .clk(clk),
    .rst_n(rst_n),
    .layer_i(layer_i),
    .addr_i(addr_i),
    .wdata_i(wdata_i),
    .ren_i(req_valid_i && allow && !op_write_i),
    .wen_i(req_valid_i && allow && op_write_i),
    .layer_access_i(layer_access_i),
    .tamper_clear_i(1'b0),
    .fault_inject_i(fault_inject_i),
    .fault_mask_i(fault_mask_i),
    .rdata_o(rdata_o),
    .ready_o(mem_ready),
    .denied_o(mem_denied),
    .tamper_o(mem_tamper)
  );

  always_comb begin
    denied_o = guard_denied | mem_denied;
    tamper_o = lockdown_o | severe_event | mem_tamper;
    // Guard denials complete immediately; allowed transactions complete when
    // the memory model responds.
    ready_o = guard_denied | mem_ready;
  end

endmodule
