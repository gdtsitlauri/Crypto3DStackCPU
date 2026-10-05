// SPDX-License-Identifier: MIT
// CPU-facing SoC top (roadmap 2.6): crypto3d_vtf_cpu_bridge + crypto3d_vtf_system_top.
// The CPU side is a plain memory port (fetch/load/store); everything that crosses
// a tier is authenticated, policy-checked, freshness-checked and answered with a
// signed response that the bridge verifies. tb/tb_vtf_soc.sv drives it with
// memory traces recorded from the C++ CPU running programs/*.asm.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module crypto3d_vtf_soc_top #(
  parameter bit FAULT_HARDEN = 1'b0
) (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         root_load_i,
  input  logic [127:0] root_key_i,
  input  logic [31:0]  active_epoch_i,
  output logic         ready_o,

  input  logic         cpu_valid_i,
  output logic         cpu_ready_o,
  input  logic         cpu_fetch_i,
  input  logic         cpu_write_i,
  input  logic [7:0]   cpu_layer_i,
  input  logic [31:0]  cpu_addr_i,
  input  logic [31:0]  cpu_wdata_i,
  output logic         cpu_rsp_valid_o,
  output logic         cpu_rsp_ok_o,
  output logic [31:0]  cpu_rsp_rdata_o,

  input  c3d_layer_role_t layer_role_i [C3D_LAYERS],
  input  logic            layer_access_i [C3D_LAYERS],
  input  logic signed [17:0] temperature_mc_i [C3D_LAYERS],
  input  logic            physical_fault_i,
  input  logic            sentinel_provision_i,
  input  logic            sentinel_check_i,
  input  logic [31:0]     sentinel_observed_i [8],
  input  logic [31:0]     sentinel_value_i [8],

  output logic         lockdown_o,
  output logic         tamper_o,
  output logic         fault_alarm_o
);
  logic         b_keys_ready, s_keys_ready;
  logic         v_valid, v_ready, v_write, v_rsp_valid;
  logic [2:0]   v_requester;
  logic [7:0]   v_layer, v_rsp_status, v_rsp_reason;
  logic [31:0]  v_addr, v_data, v_seq, v_epoch, v_nonce, v_rsp_data;
  logic [127:0] v_tag, v_rsp_tag;
  logic [255:0] v_rsp_msg;
  logic         bridge_tamper, sys_tamper, sys_zeroize, sys_auth_ok;

  crypto3d_vtf_cpu_bridge bridge_i (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load_i), .root_key_i(root_key_i),
    .active_epoch_i(active_epoch_i), .keys_ready_o(b_keys_ready),
    .cpu_valid_i(cpu_valid_i), .cpu_ready_o(cpu_ready_o), .cpu_fetch_i(cpu_fetch_i),
    .cpu_write_i(cpu_write_i), .cpu_layer_i(cpu_layer_i), .cpu_addr_i(cpu_addr_i),
    .cpu_wdata_i(cpu_wdata_i), .cpu_rsp_valid_o(cpu_rsp_valid_o), .cpu_rsp_ok_o(cpu_rsp_ok_o),
    .cpu_rsp_rdata_o(cpu_rsp_rdata_o), .tamper_o(bridge_tamper),
    .vtf_req_valid_o(v_valid), .vtf_req_ready_i(v_ready), .vtf_req_requester_o(v_requester),
    .vtf_req_write_o(v_write), .vtf_req_layer_o(v_layer), .vtf_req_addr_o(v_addr),
    .vtf_req_data_o(v_data), .vtf_req_sequence_o(v_seq), .vtf_req_epoch_o(v_epoch),
    .vtf_req_nonce_o(v_nonce), .vtf_req_tag_o(v_tag),
    .vtf_rsp_valid_i(v_rsp_valid), .vtf_rsp_status_i(v_rsp_status), .vtf_rsp_data_i(v_rsp_data),
    .vtf_rsp_msg_i(v_rsp_msg), .vtf_rsp_tag_i(v_rsp_tag)
  );

  crypto3d_vtf_system_top #(.FAULT_HARDEN(FAULT_HARDEN)) vtf_i (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load_i), .root_key_i(root_key_i),
    .active_epoch_i(active_epoch_i), .keys_ready_o(s_keys_ready),
    .req_valid_i(v_valid), .req_ready_o(v_ready), .req_requester_i(v_requester),
    .req_write_i(v_write), .req_layer_i(v_layer), .req_addr_i(v_addr), .req_data_i(v_data),
    .req_sequence_i(v_seq), .req_epoch_i(v_epoch), .req_nonce_i(v_nonce), .req_tag_i(v_tag),
    .rsp_valid_o(v_rsp_valid), .rsp_status_o(v_rsp_status), .rsp_data_o(v_rsp_data),
    .rsp_msg_o(v_rsp_msg), .rsp_tag_o(v_rsp_tag), .rsp_deny_reason_o(v_rsp_reason),
    .debug_unlocked_i(1'b0), .layer_role_i(layer_role_i), .layer_access_i(layer_access_i),
    .temperature_mc_i(temperature_mc_i), .physical_fault_i(physical_fault_i),
    .sentinel_provision_i(sentinel_provision_i), .sentinel_check_i(sentinel_check_i),
    .sentinel_observed_i(sentinel_observed_i), .sentinel_value_i(sentinel_value_i),
    .fault_inject_i(1'b0), .fault_mask_i(32'h0),
    .lockdown_o(lockdown_o), .key_zeroize_o(sys_zeroize), .tamper_o(sys_tamper),
    .auth_ok_o(sys_auth_ok), .fault_alarm_o(fault_alarm_o)
  );

  assign ready_o  = b_keys_ready && s_keys_ready;
  assign tamper_o = bridge_tamper | sys_tamper;

  /* verilator lint_off UNUSEDSIGNAL */
  wire unused_ok = &{1'b0, v_rsp_reason, sys_zeroize, sys_auth_ok};
  /* verilator lint_on UNUSEDSIGNAL */
endmodule
