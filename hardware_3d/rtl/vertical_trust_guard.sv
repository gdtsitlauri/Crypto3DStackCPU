// SPDX-License-Identifier: MIT
// Vertical Trust Guard for Crypto3DStackCPU.
//
// Enforces architectural policy around logical 3D-tier transactions:
// role-based access, replay/epoch checks, thermal/fault lockdown, and key-tier
// zeroize signalling. Cryptographic authentication is supplied as auth_ok_i by
// an AES-CMAC authenticator (crypto3d_vtf_system_top / src/vtf_hls.cpp).
//
// FAULT_HARDEN=1 (roadmap 2.3) adds single-fault detection on the guard's own
// state: a dual-rail lockdown latch (a flip of either rail reads as LOCKED,
// never as unlocked) and a parity bit per last_sequence entry. Any mismatch is
// an internal fault: severe event, lockdown, key zeroize, deny reason FAULT.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module vertical_trust_guard #(
  parameter int LAYERS = C3D_LAYERS,
  parameter int REQUESTERS = 5,
  parameter int TEMP_WIDTH = 18,
  parameter int MAX_TEMP_MC = 90000,
  parameter bit FAULT_HARDEN = 1'b0
) (
  input  logic clk,
  input  logic rst_n,

  input  logic req_valid_i,
  input  logic [2:0] requester_i,
  input  logic op_write_i,
  input  logic [C3D_LAYER_WIDTH-1:0] layer_i,
  input  logic [31:0] sequence_i,
  input  logic [31:0] epoch_i,
  input  logic [31:0] active_epoch_i,
  input  logic auth_ok_i,
  input  logic debug_unlocked_i,

  input  c3d_layer_role_t layer_role_i [LAYERS],
  input  logic signed [TEMP_WIDTH-1:0] temperature_mc_i [LAYERS],
  input  logic physical_fault_i,
  input  logic sentinel_fault_i,

  output logic allow_o,
  output logic denied_o,
  output logic lockdown_o,
  output logic severe_event_o,
  output logic key_zeroize_o,
  output logic [7:0] deny_reason_o
);

  localparam logic [2:0] REQ_CPU_FETCH = 3'd0;
  localparam logic [2:0] REQ_CPU_DATA  = 3'd1;
  localparam logic [2:0] REQ_SECURITY  = 3'd2;
  localparam logic [2:0] REQ_DMA       = 3'd3;
  localparam logic [2:0] REQ_DEBUG     = 3'd4;

  localparam logic [7:0] DENY_NONE      = 8'd0;
  localparam logic [7:0] DENY_LOCKDOWN  = 8'd1;
  localparam logic [7:0] DENY_POLICY    = 8'd2;
  localparam logic [7:0] DENY_AUTH      = 8'd3;
  localparam logic [7:0] DENY_REPLAY    = 8'd4;
  localparam logic [7:0] DENY_EPOCH     = 8'd5;
  localparam logic [7:0] DENY_THERMAL   = 8'd6;
  localparam logic [7:0] DENY_PHYSICAL  = 8'd7;
  localparam logic [7:0] DENY_SENTINEL  = 8'd8;
  localparam logic [7:0] DENY_FAULT     = 8'd9;

  localparam logic signed [TEMP_WIDTH-1:0] MAX_TEMP_SIGNED = TEMP_WIDTH'(MAX_TEMP_MC);
  localparam logic [2:0] REQUESTER_COUNT = 3'(REQUESTERS);

  logic [31:0] last_sequence [REQUESTERS];
  logic lockdown_q;
  logic lockdown_n_q;                  // complement rail (FAULT_HARDEN)
  logic [REQUESTERS-1:0] seq_par_q;    // parity of last_sequence (FAULT_HARDEN)
  logic locked;
  logic internal_fault;
  logic thermal_alarm;
  logic policy_ok;
  logic requester_ok;
  logic layer_ok;
  logic request_severe;
  logic environment_severe;
  logic consume_sequence;

  always_comb begin
    thermal_alarm = 1'b0;
    for (int l = 0; l < LAYERS; l++) begin
      if (temperature_mc_i[l] > MAX_TEMP_SIGNED)
        thermal_alarm = 1'b1;
    end
  end

  always_comb begin
    internal_fault = 1'b0;
    locked = lockdown_q;
    if (FAULT_HARDEN) begin
      // fail-safe decoding: either rail indicating "locked" locks
      locked = lockdown_q | ~lockdown_n_q;
      internal_fault = (lockdown_q == lockdown_n_q);
      for (int r = 0; r < REQUESTERS; r++)
        if ((^last_sequence[r]) != seq_par_q[r]) internal_fault = 1'b1;
    end
  end

  always_comb begin
    requester_ok = (requester_i < REQUESTER_COUNT);
    layer_ok = (int'(layer_i) < LAYERS);
    policy_ok = 1'b0;

    if (requester_ok && layer_ok) begin
      unique case (requester_i)
        REQ_CPU_FETCH: policy_ok = !op_write_i &&
                                   (layer_role_i[layer_i] == C3D_LAYER_ROLE_EXEC);
        REQ_CPU_DATA:  policy_ok = (layer_role_i[layer_i] == C3D_LAYER_ROLE_DATA);
        REQ_SECURITY:  policy_ok = 1'b1;
        REQ_DMA:       policy_ok = (layer_role_i[layer_i] == C3D_LAYER_ROLE_DATA);
        REQ_DEBUG:     policy_ok = debug_unlocked_i &&
                                   ((layer_role_i[layer_i] == C3D_LAYER_ROLE_EXEC) ||
                                    (layer_role_i[layer_i] == C3D_LAYER_ROLE_DATA));
        default:       policy_ok = 1'b0;
      endcase
    end
  end

  always_comb begin
    allow_o = 1'b0;
    denied_o = 1'b0;
    deny_reason_o = DENY_NONE;
    request_severe = 1'b0;
    consume_sequence = 1'b0;
    environment_severe = physical_fault_i | sentinel_fault_i | thermal_alarm | internal_fault;

    if (locked) begin
      if (req_valid_i) begin
        denied_o = 1'b1;
        deny_reason_o = DENY_LOCKDOWN;
      end
    end else if (internal_fault) begin
      denied_o = 1'b1;
      deny_reason_o = DENY_FAULT;
    end else if (physical_fault_i) begin
      denied_o = 1'b1;
      deny_reason_o = DENY_PHYSICAL;
    end else if (sentinel_fault_i) begin
      denied_o = 1'b1;
      deny_reason_o = DENY_SENTINEL;
    end else if (thermal_alarm) begin
      denied_o = 1'b1;
      deny_reason_o = DENY_THERMAL;
    end else if (req_valid_i) begin
      if (!requester_ok || !layer_ok) begin
        denied_o = 1'b1;
        deny_reason_o = DENY_POLICY;
        request_severe = 1'b1;
      end else if (epoch_i != active_epoch_i) begin
        denied_o = 1'b1;
        deny_reason_o = DENY_EPOCH;
        request_severe = 1'b1;
      end else if (!auth_ok_i) begin
        denied_o = 1'b1;
        deny_reason_o = DENY_AUTH;
        request_severe = 1'b1;
      end else if (sequence_i != (last_sequence[requester_i] + 32'd1)) begin
        denied_o = 1'b1;
        deny_reason_o = DENY_REPLAY;
        request_severe = 1'b1;
      end else begin
        // Authentication, epoch and freshness all succeeded. Consume the
        // sequence even if authorization denies this request, matching the
        // C++ VTF protocol and preventing requester/receiver desynchronization.
        consume_sequence = 1'b1;
        if (!policy_ok) begin
          // Safe/non-destructive authorization failure.
          denied_o = 1'b1;
          deny_reason_o = DENY_POLICY;
        end else begin
          allow_o = 1'b1;
        end
      end
    end

    severe_event_o = (!locked) && (environment_severe || request_severe);
    key_zeroize_o  = severe_event_o;
    lockdown_o     = locked || severe_event_o;
  end

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      lockdown_q <= 1'b0;
      lockdown_n_q <= 1'b1;
      for (int r = 0; r < REQUESTERS; r++) begin
        last_sequence[r] <= 32'd0;
        seq_par_q[r] <= 1'b0;
      end
    end else begin
      if (severe_event_o) begin
        lockdown_q <= 1'b1;
        lockdown_n_q <= 1'b0;
      end

      if (req_valid_i && consume_sequence && requester_ok) begin
        last_sequence[requester_i] <= sequence_i;
        seq_par_q[requester_i] <= ^sequence_i;
      end
    end
  end

endmodule
