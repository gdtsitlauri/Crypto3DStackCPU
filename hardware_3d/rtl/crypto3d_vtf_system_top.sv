// SPDX-License-Identifier: MIT
// Integrated Vertical Trust Fabric system (roadmap item 1.1).
//
// Closes the gap of crypto3d_secure_stack_top, whose guard took auth_ok as an
// external input. Here every vertical transaction is authenticated in RTL:
//
//   request (fields + AES-CMAC tag) --> vtf authenticator (aes_cmac32, per-
//   requester/epoch key from vtf_key_schedule) --> vertical_trust_guard
//   (policy, epoch, replay, thermal/physical/sentinel) --> stacked memory -->
//   signed response (status, data, AES-CMAC tag with the response key)
//
// The tier sentinel monitor drives the guard's sentinel_fault input, and the
// guard's key_zeroize output wipes the key schedule and the CMAC subkey cache,
// so after a severe event no further tag can verify until secure boot reloads
// the device root.
//
// Message formats are identical to src/vertical_trust_fabric.h (see
// hardware_3d/scripts/vtf_reference.py). Latency per transaction is reported by
// tb_vtf_system (request tag check + guard + memory + response signing).
//
// FAULT_HARDEN=1 (roadmap 2.3) adds single-fault (SEU / glitch) detection:
//   * temporal redundancy: the request tag is computed twice and must agree;
//   * the auth decision is an 8-bit code (A5 = pass, 5A = fail), not one bit;
//   * before the guard/memory act, the latched request fields are re-encoded and
//     compared with the exact message that was authenticated;
//   * dual-rail (true/complement) FSM state;
//   * parity over the response status/data/reason between memory and signing;
//   * the guard's own dual-rail lockdown + last_sequence parity.
// Any detection raises a sticky fault alarm that enters the guard as a physical
// fault: lockdown, key zeroize, and an unsigned denial. Measured by
// tb/tb_fault_campaign.sv (single-bit upsets in every security register).

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module crypto3d_vtf_system_top #(
  parameter int  LAYERS     = C3D_LAYERS,
  parameter int  WORDS      = C3D_WORDS,
  parameter int  REQUESTERS = 5,
  parameter int  SENTINELS  = 8,
  parameter bit  EPOCH_KEYS = 1'b1,
  parameter bit  FAULT_HARDEN = 1'b0
) (
  input  logic clk,
  input  logic rst_n,

  // secure boot: device root (PUF / eFUSE / BBRAM output) and active epoch
  input  logic         root_load_i,
  input  logic [127:0] root_key_i,
  input  logic [31:0]  active_epoch_i,
  output logic         keys_ready_o,

  // request channel
  input  logic         req_valid_i,
  output logic         req_ready_o,
  input  logic [2:0]   req_requester_i,
  input  logic         req_write_i,
  input  logic [7:0]   req_layer_i,
  input  logic [31:0]  req_addr_i,
  input  logic [31:0]  req_data_i,
  input  logic [31:0]  req_sequence_i,
  input  logic [31:0]  req_epoch_i,
  input  logic [31:0]  req_nonce_i,
  input  logic [127:0] req_tag_i,

  // response channel (one-cycle pulse)
  output logic         rsp_valid_o,
  output logic [7:0]   rsp_status_o,     // 1 = executed, 0 = denied
  output logic [31:0]  rsp_data_o,
  output logic [255:0] rsp_msg_o,        // exact bytes that were signed
  output logic [127:0] rsp_tag_o,
  output logic [7:0]   rsp_deny_reason_o,

  // tier configuration and environment
  input  logic            debug_unlocked_i,
  input  c3d_layer_role_t layer_role_i [LAYERS],
  input  logic            layer_access_i [LAYERS],
  input  logic signed [17:0] temperature_mc_i [LAYERS],
  input  logic            physical_fault_i,

  // sentinel bank (values observed by the scrubber / provisioned at boot)
  input  logic         sentinel_provision_i,
  input  logic         sentinel_check_i,
  input  logic [31:0]  sentinel_observed_i [SENTINELS],
  input  logic [31:0]  sentinel_value_i [SENTINELS],

  // physical fault injection on the memory write path (attack model)
  input  logic         fault_inject_i,
  input  logic [31:0]  fault_mask_i,

  output logic         lockdown_o,
  output logic         key_zeroize_o,
  output logic         tamper_o,
  output logic         auth_ok_o,         // last tag check result (observability)
  output logic         fault_alarm_o      // FAULT_HARDEN: internal fault detected (sticky)
);

  localparam logic [7:0] DENY_POLICY = 8'd2;
  localparam logic [7:0] DENY_FAULT  = 8'd9;
  localparam logic [7:0] AUTH_PASS   = 8'hA5;
  localparam logic [7:0] AUTH_FAIL   = 8'h5A;

  typedef enum logic [2:0] {S_IDLE, S_AUTH, S_AUTH2, S_GUARD, S_MEM, S_SIGN, S_RESP} state_t;
  state_t state_q;
  /* verilator lint_off UNUSEDSIGNAL */
  logic [2:0] state_n_q;      // complement rail of state_q (checked when FAULT_HARDEN)
  /* verilator lint_on UNUSEDSIGNAL */

  // ---------------- keys ----------------
  logic [127:0] req_key [REQUESTERS];
  logic [127:0] req_k1  [REQUESTERS];
  logic [127:0] rsp_key, rsp_k1;
  logic         zeroize;

  vtf_key_schedule #(.EPOCH_KEYS(EPOCH_KEYS), .REQUESTERS(REQUESTERS)) keys_i (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load_i), .root_key_i(root_key_i),
    .active_epoch_i(active_epoch_i), .zeroize_i(zeroize), .ready_o(keys_ready_o),
    .req_key_o(req_key), .req_k1_o(req_k1), .rsp_key_o(rsp_key), .rsp_k1_o(rsp_k1)
  );

  // ---------------- CMAC (shared by verify and sign) ----------------
  logic         cmac_start, cmac_busy, cmac_done;
  logic [127:0] cmac_key, cmac_k1, cmac_tag;
  logic [255:0] cmac_msg;

  aes_cmac32 cmac_i (
    .clk(clk), .rst_n(rst_n), .start_i(cmac_start), .clear_i(zeroize), .key_i(cmac_key),
    .k1_valid_i(1'b1), .k1_i(cmac_k1),
    .msg_i(cmac_msg), .busy_o(cmac_busy), .done_o(cmac_done), .tag_o(cmac_tag)
  );

  // ---------------- latched request ----------------
  logic [2:0]   r_requester;
  logic         r_write;
  logic [7:0]   r_layer;
  logic [31:0]  r_addr, r_data, r_seq, r_epoch, r_nonce;
  logic [127:0] r_tag;
  logic         r_auth_ok, r_addr_ok;
  logic [7:0]   r_status, r_reason;
  logic [31:0]  r_rdata;
  // fault-hardening state (only checked when FAULT_HARDEN)
  /* verilator lint_off UNUSEDSIGNAL */
  logic [7:0]   r_auth_code;
  logic [127:0] r_tag1;
  logic         resp_par_q;
  /* verilator lint_on UNUSEDSIGNAL */
  logic         fault_alarm_q;

  function automatic logic [255:0] req_msg(input logic [2:0] rq, input logic wr, input logic [7:0] ly,
                                           input logic [31:0] ad, input logic [31:0] dt, input logic [31:0] sq,
                                           input logic [31:0] ep, input logic [31:0] nc);
    req_msg = {8'hC3, 8'hD1, 5'd0, rq, 7'd0, wr, ly, 24'd0, ad, dt, sq, ep, nc, 32'h56544631};
  endfunction

  function automatic logic [255:0] rsp_msg(input logic [2:0] rq, input logic wr, input logic [7:0] ly,
                                           input logic [7:0] st, input logic [31:0] ad, input logic [31:0] dt,
                                           input logic [31:0] sq, input logic [31:0] ep, input logic [31:0] nc);
    rsp_msg = {8'hC3, 8'hD2, 5'd0, rq, 7'd0, wr, ly, st, 16'd0, ad, dt, sq, ep, nc, 32'h56544632};
  endfunction

  // ---------------- sentinel monitor ----------------
  logic sentinel_fault;
  tier_sentinel_monitor #(.COUNT(SENTINELS), .WORD_WIDTH(32)) sentinel_i (
    .clk(clk), .rst_n(rst_n), .provision_i(sentinel_provision_i), .check_i(sentinel_check_i),
    .observed_i(sentinel_observed_i), .provision_value_i(sentinel_value_i),
    .sentinel_fault_o(sentinel_fault)
  );

  // ---------------- guard ----------------
  logic guard_valid, allow, severe, r_layer_ok;
  logic auth_pass, fields_ok, addr_ok, state_fault, code_fault, resp_par_fault;
  /* verilator lint_off UNUSEDSIGNAL */
  logic guard_denied;   // the deny reason carries the same information
  /* verilator lint_on UNUSEDSIGNAL */
  assign r_layer_ok = (int'(r_layer) < LAYERS);
  logic [7:0] guard_reason;
  logic [C3D_LAYER_WIDTH-1:0] guard_layer;

  // A layer index outside the stack is presented to the guard as an invalid layer
  // (it denies it as a severe policy violation).
  assign guard_layer = (int'(r_layer) < LAYERS) ? r_layer[C3D_LAYER_WIDTH-1:0]
                                                : {C3D_LAYER_WIDTH{1'b1}};
  assign guard_valid = (state_q == S_GUARD);

  // Fault checks (constant-false when FAULT_HARDEN = 0).
  assign fields_ok   = (req_msg(r_requester, r_write, r_layer, r_addr, r_data, r_seq, r_epoch, r_nonce)
                        == cmac_msg);
  assign auth_pass   = FAULT_HARDEN ? ((r_auth_code == AUTH_PASS) && fields_ok) : r_auth_ok;
  assign addr_ok     = FAULT_HARDEN ? (r_addr < 32'(WORDS)) : r_addr_ok;
  assign state_fault = FAULT_HARDEN && (state_n_q != ~state_q);
  assign code_fault  = FAULT_HARDEN && (state_q == S_GUARD) &&
                       (((r_auth_code != AUTH_PASS) && (r_auth_code != AUTH_FAIL)) ||
                        ((r_auth_code == AUTH_PASS) && !fields_ok));
  assign resp_par_fault = FAULT_HARDEN && (state_q == S_SIGN) &&
                          ((^{r_status, r_rdata, r_reason}) != resp_par_q);
  assign fault_alarm_o = fault_alarm_q;

  vertical_trust_guard #(.LAYERS(LAYERS), .REQUESTERS(REQUESTERS), .FAULT_HARDEN(FAULT_HARDEN)) guard_i (
    .clk(clk), .rst_n(rst_n), .req_valid_i(guard_valid), .requester_i(r_requester),
    .op_write_i(r_write), .layer_i(guard_layer), .sequence_i(r_seq), .epoch_i(r_epoch),
    .active_epoch_i(active_epoch_i), .auth_ok_i(auth_pass && r_layer_ok),
    .debug_unlocked_i(debug_unlocked_i), .layer_role_i(layer_role_i),
    .temperature_mc_i(temperature_mc_i), .physical_fault_i(physical_fault_i | fault_alarm_q),
    .sentinel_fault_i(sentinel_fault), .allow_o(allow), .denied_o(guard_denied),
    .lockdown_o(lockdown_o), .severe_event_o(severe), .key_zeroize_o(key_zeroize_o),
    .deny_reason_o(guard_reason)
  );


  assign zeroize = key_zeroize_o;

  // ---------------- memory ----------------
  logic        mem_ren, mem_wen, mem_ready, mem_denied, mem_tamper;
  logic [31:0] mem_rdata;

  assign mem_ren = (state_q == S_GUARD) && allow && addr_ok && !r_write && !code_fault && !state_fault;
  assign mem_wen = (state_q == S_GUARD) && allow && addr_ok &&  r_write && !code_fault && !state_fault;

  stacked_memory_3d_model #(.LAYERS(LAYERS), .WORDS(WORDS)) mem_i (
    .clk(clk), .rst_n(rst_n), .layer_i(guard_layer), .addr_i(r_addr[C3D_ADDR_WIDTH-1:0]),
    .wdata_i(r_data), .ren_i(mem_ren), .wen_i(mem_wen), .layer_access_i(layer_access_i),
    .tamper_clear_i(1'b0), .fault_inject_i(fault_inject_i), .fault_mask_i(fault_mask_i),
    .rdata_o(mem_rdata), .ready_o(mem_ready), .denied_o(mem_denied), .tamper_o(mem_tamper)
  );

  assign tamper_o  = lockdown_o | severe | mem_tamper | fault_alarm_q;
  assign auth_ok_o = r_auth_ok;

  // Requests are accepted when keys are ready, or always during lockdown (they are
  // then denied without authentication, since the keys are gone).
  assign req_ready_o = (state_q == S_IDLE) && !cmac_busy && (keys_ready_o || lockdown_o);

  // ---------------- control ----------------
  always_ff @(posedge clk) begin
    if (!rst_n) begin
      begin state_q      <= S_IDLE; state_n_q <= ~S_IDLE; end
      cmac_start   <= 1'b0;
      cmac_key     <= '0;
      cmac_k1      <= '0;
      cmac_msg     <= '0;
      r_requester  <= '0; r_write <= 1'b0; r_layer <= '0; r_addr <= '0; r_data <= '0;
      r_seq        <= '0; r_epoch <= '0; r_nonce <= '0; r_tag <= '0;
      r_auth_ok    <= 1'b0; r_addr_ok <= 1'b0;
      r_status     <= '0; r_reason <= '0; r_rdata <= '0;
      state_n_q    <= ~S_IDLE;
      r_auth_code  <= AUTH_FAIL; r_tag1 <= '0; resp_par_q <= 1'b0; fault_alarm_q <= 1'b0;
      rsp_valid_o  <= 1'b0; rsp_status_o <= '0; rsp_data_o <= '0; rsp_msg_o <= '0;
      rsp_tag_o    <= '0; rsp_deny_reason_o <= '0;
    end else begin
      cmac_start  <= 1'b0;
      rsp_valid_o <= 1'b0;
      unique case (state_q)
        S_IDLE: if (req_valid_i && req_ready_o) begin
          r_requester <= req_requester_i; r_write <= req_write_i; r_layer <= req_layer_i;
          r_addr <= req_addr_i; r_data <= req_data_i; r_seq <= req_sequence_i;
          r_epoch <= req_epoch_i; r_nonce <= req_nonce_i; r_tag <= req_tag_i;
          r_addr_ok <= (req_addr_i < 32'(WORDS));
          r_auth_ok <= 1'b0;
          r_auth_code <= AUTH_FAIL;
          // no response state survives from the previous transaction
          r_status <= 8'd0; r_rdata <= 32'd0; r_reason <= 8'd0; resp_par_q <= 1'b0;
          if (keys_ready_o && !lockdown_o) begin
            cmac_key   <= (int'(req_requester_i) < REQUESTERS) ? req_key[req_requester_i] : '0;
            cmac_k1    <= (int'(req_requester_i) < REQUESTERS) ? req_k1[req_requester_i] : '0;
            cmac_msg   <= req_msg(req_requester_i, req_write_i, req_layer_i, req_addr_i, req_data_i,
                                  req_sequence_i, req_epoch_i, req_nonce_i);
            cmac_start <= 1'b1;
            begin state_q    <= S_AUTH; state_n_q <= ~S_AUTH; end
          end else begin
            begin state_q    <= S_GUARD; state_n_q <= ~S_GUARD; end      // lockdown: guard denies with DENY_LOCKDOWN
          end
        end
        S_AUTH: if (cmac_done) begin
          // constant-time comparison: OR-reduce the XOR of the full tags
          r_auth_ok <= ~|(cmac_tag ^ r_tag) && (int'(r_requester) < REQUESTERS);
          if (FAULT_HARDEN) begin
            r_tag1     <= cmac_tag;     // recompute once more (temporal redundancy)
            cmac_start <= 1'b1;
            begin state_q    <= S_AUTH2; state_n_q <= ~S_AUTH2; end
          end else begin
            begin state_q   <= S_GUARD; state_n_q <= ~S_GUARD; end
          end
        end else if (zeroize) begin
          begin state_q   <= S_GUARD; state_n_q <= ~S_GUARD; end         // environment event during authentication
        end
        S_AUTH2: if (cmac_done) begin
          if (cmac_tag != r_tag1) begin
            fault_alarm_q <= 1'b1;      // the two computations disagree
            r_auth_ok     <= 1'b0;
            r_auth_code   <= AUTH_FAIL;
          end else begin
            r_auth_ok   <= ~|(cmac_tag ^ r_tag) && ~|(r_tag1 ^ r_tag) && (int'(r_requester) < REQUESTERS);
            r_auth_code <= (~|(cmac_tag ^ r_tag) && ~|(r_tag1 ^ r_tag) && (int'(r_requester) < REQUESTERS))
                           ? AUTH_PASS : AUTH_FAIL;
          end
          begin state_q <= S_GUARD; state_n_q <= ~S_GUARD; end
        end else if (zeroize) begin
          begin state_q <= S_GUARD; state_n_q <= ~S_GUARD; end
        end
        S_GUARD: begin
          if (code_fault) begin
            fault_alarm_q <= 1'b1;
            r_reason <= DENY_FAULT; resp_par_q <= ^DENY_FAULT;
            r_status <= 8'd0; r_rdata <= 32'd0;
            begin state_q  <= S_SIGN; state_n_q <= ~S_SIGN; end
          end else begin
            r_reason <= (allow && !addr_ok) ? DENY_POLICY : guard_reason;
            resp_par_q <= ^((allow && !addr_ok) ? DENY_POLICY : guard_reason);
            r_status <= 8'd0;
            r_rdata  <= 32'd0;
            if (allow && addr_ok) begin state_q <= S_MEM; state_n_q <= ~S_MEM; end
            else                  begin state_q <= S_SIGN; state_n_q <= ~S_SIGN; end
          end
        end
        S_MEM: if (mem_ready && FAULT_HARDEN && !fields_ok) begin
          // latched request fields diverged from the authenticated message during the
          // memory cycle: do not acknowledge (the write echo would be untrustworthy)
          fault_alarm_q <= 1'b1;
          r_status <= 8'd0; r_rdata <= 32'd0; r_reason <= DENY_FAULT; resp_par_q <= ^DENY_FAULT;
          begin state_q  <= S_SIGN; state_n_q <= ~S_SIGN; end
        end else if (mem_ready) begin
          r_status <= mem_denied ? 8'd0 : 8'd1;
          r_rdata  <= mem_denied ? 32'd0 : (r_write ? r_data : mem_rdata);
          resp_par_q <= ^{(mem_denied ? 8'd0 : 8'd1), (mem_denied ? 32'd0 : (r_write ? r_data : mem_rdata)),
                          r_reason};
          begin state_q  <= S_SIGN; state_n_q <= ~S_SIGN; end
        end
        S_SIGN: begin
          if (resp_par_fault) begin
            // response fields were corrupted after the memory stage: refuse to sign them
            fault_alarm_q <= 1'b1;
            r_status <= 8'd0; r_rdata <= 32'd0; r_reason <= DENY_FAULT; resp_par_q <= ^DENY_FAULT;
          end else if (keys_ready_o && !lockdown_o && !cmac_busy) begin
            cmac_key   <= rsp_key;
            cmac_k1    <= rsp_k1;
            cmac_msg   <= rsp_msg(r_requester, r_write, r_layer, r_status, r_addr, r_rdata,
                                  r_seq, r_epoch, r_nonce);
            cmac_start <= 1'b1;
            begin state_q    <= S_RESP; state_n_q <= ~S_RESP; end
          end else if (!keys_ready_o || lockdown_o) begin
            // keys are gone: emit an unsigned (all-zero tag) denial
            rsp_valid_o       <= 1'b1;
            rsp_status_o      <= r_status;
            rsp_data_o        <= r_rdata;
            rsp_msg_o         <= rsp_msg(r_requester, r_write, r_layer, r_status, r_addr, r_rdata,
                                         r_seq, r_epoch, r_nonce);
            rsp_tag_o         <= '0;
            rsp_deny_reason_o <= r_reason;
            begin state_q           <= S_IDLE; state_n_q <= ~S_IDLE; end
          end
        end
        S_RESP: if (cmac_done && FAULT_HARDEN &&
                    (cmac_msg != rsp_msg(r_requester, r_write, r_layer, r_status, r_addr, r_rdata,
                                         r_seq, r_epoch, r_nonce))) begin
          // the signed bytes no longer match the (parity-protected) response fields:
          // an upset hit the message register around signing -> never release it
          fault_alarm_q <= 1'b1;
          r_status <= 8'd0; r_rdata <= 32'd0; r_reason <= DENY_FAULT; resp_par_q <= ^DENY_FAULT;
          begin state_q <= S_SIGN; state_n_q <= ~S_SIGN; end
        end else if (cmac_done) begin
          // status and data are taken from the exact bytes that were signed, so a
          // later upset of r_status / r_rdata cannot detach them from the tag
          rsp_valid_o       <= 1'b1;
          rsp_status_o      <= cmac_msg[215:208];
          rsp_data_o        <= cmac_msg[159:128];
          rsp_msg_o         <= cmac_msg;
          rsp_tag_o         <= cmac_tag;
          rsp_deny_reason_o <= r_reason;
          begin state_q           <= S_IDLE; state_n_q <= ~S_IDLE; end
        end else if (zeroize) begin
          begin state_q <= S_SIGN; state_n_q <= ~S_SIGN; end            // falls through to the unsigned denial
        end
        default: begin state_q <= S_IDLE; state_n_q <= ~S_IDLE; end
      endcase
      if (state_fault) begin
        // corrupted FSM state: abandon the transaction, alarm, unsigned denial
        fault_alarm_q <= 1'b1;
        r_status <= 8'd0; r_rdata <= 32'd0; r_reason <= DENY_FAULT; resp_par_q <= ^DENY_FAULT;
        begin state_q <= S_SIGN; state_n_q <= ~S_SIGN; end
      end
    end
  end

endmodule
