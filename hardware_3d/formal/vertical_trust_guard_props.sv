// SPDX-License-Identifier: MIT
// Formal property harness for vertical_trust_guard (roadmap item 1.2).
//
// All guard inputs are unconstrained (free) except for reset at cycle 0. The
// harness keeps *observational* shadow state that is updated only from the
// guard's outputs, so the properties below do not restate the RTL's logic:
//
//   P1  no allow without authentication, matching epoch and a valid requester/layer
//   P2  anti-replay: every consumed request carries exactly last-consumed+1
//       for its requester (shadow tracked from outputs only)
//   P3  lockdown is sticky: after any severe event nothing is ever allowed
//       and lockdown_o stays high until reset
//   P4  every severe event raises key zeroize and lockdown in the same cycle
//   P5  any environmental fault (physical/sentinel/thermal) blocks the access
//   P6  role policy: KEY_HIDE/SENTINEL/RESERVED tiers only reachable by SECURITY;
//       CPU_FETCH never writes and only reads EXEC; CPU_DATA/DMA only touch DATA
//       tiers (never exec/key); DEBUG needs debug_unlocked_i
//   P8  every authentication, epoch or malformed-request failure before lockdown is a
//       severe event (zeroize + lockdown), i.e. forgery attempts are never silent
//   P7  output consistency: allow/denied exclusive, deny_reason!=0 iff denied
//
// Cover goals show the properties are not vacuous (allow, replay deny,
// policy deny without lockdown, lockdown then a denied request).

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module vertical_trust_guard_props #(
  parameter bit FAULT_HARDEN = 1'b0
) (
  input logic clk,
  input logic rst_n,
  input logic req_valid_i,
  input logic [2:0] requester_i,
  input logic op_write_i,
  input logic [C3D_LAYER_WIDTH-1:0] layer_i,
  input logic [31:0] sequence_i,
  input logic [31:0] epoch_i,
  input logic [31:0] active_epoch_i,
  input logic auth_ok_i,
  input logic debug_unlocked_i,
  input logic [2:0] role0_i, role1_i, role2_i, role3_i,
  input logic signed [17:0] temp0_i, temp1_i, temp2_i, temp3_i,
  input logic physical_fault_i,
  input logic sentinel_fault_i
);
  localparam int LAYERS = 4;
  localparam int MAX_TEMP_MC = 90000;

  c3d_layer_role_t roles [LAYERS];
  logic signed [17:0] temps [LAYERS];
  assign roles[0] = c3d_layer_role_t'(role0_i);
  assign roles[1] = c3d_layer_role_t'(role1_i);
  assign roles[2] = c3d_layer_role_t'(role2_i);
  assign roles[3] = c3d_layer_role_t'(role3_i);
  assign temps[0] = temp0_i;
  assign temps[1] = temp1_i;
  assign temps[2] = temp2_i;
  assign temps[3] = temp3_i;

  logic allow, denied, lockdown, severe, zeroize;
  logic [7:0] reason;

  vertical_trust_guard #(.LAYERS(LAYERS), .REQUESTERS(5), .TEMP_WIDTH(18),
                         .MAX_TEMP_MC(MAX_TEMP_MC), .FAULT_HARDEN(FAULT_HARDEN)) dut (
    .clk(clk), .rst_n(rst_n),
    .req_valid_i(req_valid_i), .requester_i(requester_i), .op_write_i(op_write_i),
    .layer_i(layer_i), .sequence_i(sequence_i), .epoch_i(epoch_i),
    .active_epoch_i(active_epoch_i), .auth_ok_i(auth_ok_i),
    .debug_unlocked_i(debug_unlocked_i), .layer_role_i(roles),
    .temperature_mc_i(temps), .physical_fault_i(physical_fault_i),
    .sentinel_fault_i(sentinel_fault_i),
    .allow_o(allow), .denied_o(denied), .lockdown_o(lockdown),
    .severe_event_o(severe), .key_zeroize_o(zeroize), .deny_reason_o(reason)
  );

  // ---------------- environment ----------------
  logic init_q = 1'b1;
  always_ff @(posedge clk) init_q <= 1'b0;
  always_comb if (init_q) assume (!rst_n);

  // ---------------- observational shadow state ----------------
  logic        locked_q;               // a severe event has been observed since reset
  logic [31:0] shadow_seq [5];         // last sequence consumed per requester (from outputs)

  wire hot = (temp0_i > 18'sd90000) || (temp1_i > 18'sd90000) ||
             (temp2_i > 18'sd90000) || (temp3_i > 18'sd90000);
  wire env_fault = physical_fault_i || sentinel_fault_i || hot;
  wire req_ok = requester_i < 3'd5;
  // A request is "consumed" if it was allowed, or denied for policy alone without a
  // severe event (the guard's documented non-destructive authorization failure).
  wire consumed = req_valid_i && req_ok &&
                  (allow || (denied && reason == 8'd2 && !severe));
  c3d_layer_role_t role_sel;
  assign role_sel = roles[layer_i];
  wire privileged_tier = (role_sel != C3D_LAYER_ROLE_EXEC) && (role_sel != C3D_LAYER_ROLE_DATA);

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      locked_q <= 1'b0;
      for (int r = 0; r < 5; r++) shadow_seq[r] <= 32'd0;
    end else begin
      if (severe) locked_q <= 1'b1;
      if (consumed) shadow_seq[requester_i] <= sequence_i;
    end
  end

  // ---------------- safety properties ----------------
  always_comb begin
    if (rst_n && !init_q) begin
      // P1
      if (allow) begin
        assert (req_valid_i);
        assert (auth_ok_i);
        assert (epoch_i == active_epoch_i);
        assert (req_ok);
      end
      // P2
      if (consumed) assert (sequence_i == shadow_seq[requester_i] + 32'd1);
      // P3
      if (locked_q) begin
        assert (!allow);
        assert (lockdown);
        if (req_valid_i) assert (denied && reason == 8'd1);
      end
      // P4
      if (severe) begin
        assert (zeroize);
        assert (lockdown);
      end
      assert (zeroize == severe);
      // P5
      if (env_fault) assert (!allow);
      if (env_fault && !locked_q) assert (severe);
      // P6
      if (allow && privileged_tier) assert (requester_i == 3'd2);
      if (allow && requester_i == 3'd0) assert (!op_write_i);
      if (allow && requester_i == 3'd4) assert (debug_unlocked_i);
      if (allow && (requester_i == 3'd1 || requester_i == 3'd3)) assert (role_sel == C3D_LAYER_ROLE_DATA);
      if (allow && requester_i == 3'd0) assert (role_sel == C3D_LAYER_ROLE_EXEC);
      // P7
      assert (!(allow && denied));
      assert ((reason != 8'd0) == denied);
      if (req_valid_i && !env_fault) assert (allow || denied);
      // P8
      if (req_valid_i && !locked_q && (!auth_ok_i || epoch_i != active_epoch_i || !req_ok))
        assert (severe && !allow);
      if (denied && (reason == 8'd3 || reason == 8'd4 || reason == 8'd5)) assert (severe);
      // P4 converse: severe events are the only way to lock (no spurious lockdown)
      if (!locked_q && !severe) assert (!lockdown);
    end
  end

  // ---------------- cover (non-vacuity) ----------------
  logic allowed_once_q;
  always_ff @(posedge clk)
    if (!rst_n) allowed_once_q <= 1'b0; else if (allow) allowed_once_q <= 1'b1;

  always_comb begin
    if (rst_n && !init_q) begin
      cover (allow);
      cover (allow && requester_i == 3'd2 && privileged_tier && op_write_i);
      cover (allowed_once_q && denied && reason == 8'd4);
      cover (denied && reason == 8'd2 && !severe);
      cover (locked_q && req_valid_i && denied && reason == 8'd1);
      cover (allowed_once_q && allow && sequence_i == 32'd2);
    end
  end
endmodule
