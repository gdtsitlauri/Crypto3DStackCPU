// SPDX-License-Identifier: MIT
// Single-event-upset (SEU) fault-injection campaign for crypto3d_vtf_system_top
// (roadmap 2.3). Run once with FAULT_HARDEN=0 and once with FAULT_HARDEN=1.
//
// Fault model: one bit flip in one security-relevant register at one random
// cycle of a transaction (the flipped value persists until the register is next
// written). Register groups:
//   control  : FSM state (+ complement rail when hardened)
//   authdec  : the authentication decision register(s) that feed the guard
//   reqfields: latched request fields and received tag
//   cmac     : CMAC/AES datapath (AES state, round key, CMAC M2, message, key, K1)
//   guard    : guard lockdown latch(es), last_sequence (+ parity when hardened)
//   response : response status / data / reason (+ parity when hardened)
//   keys     : key-schedule working keys
// Scenarios:
//   forged   : SECURITY write to the key tier with a wrong tag     (golden: denied)
//   replay   : replay of an older authenticated write             (golden: denied)
//   read     : legitimate SECURITY read of the key tier            (golden: executed)
//   write    : legitimate CPU_DATA write                           (golden: executed)
// Outcomes:
//   masked    : identical to the fault-free run
//   detected  : lockdown / fault alarm / denial / response the requester rejects
//   hang      : no response within the timeout (availability loss, fail-safe)
//   VIOLATION : forged or replayed request executed, memory silently changed, or
//               the requester accepts a response with wrong data
//   false_ack : a validly signed "executed" response for a request that had no
//               effect (no memory change) - an integrity lie, but not a bypass
// The forged tag is random (an attacker without the key cannot get within a few
// bit flips of the valid tag).
// Output: FI rows per trial and FISUM rows per (scenario, group).

`timescale 1ns/1ps
import crypto3d_stack_pkg::*;

module tb_fault_campaign #(
  parameter bit FAULT_HARDEN = 1'b0,
  parameter int TRIALS = 200,        // per scenario and group
  parameter int SEED = 2026,
  // MODE 0: random (group, bit, cycle) sampling, TRIALS per scenario and group.
  // MODE 1: exhaustive timed-attacker sweep: every bit x every cycle of the
  //         decision-critical groups (control, authdec, guard of requester 2, response).
  parameter int MODE = 0
);
  `include "vtf_vectors.svh"

  logic clk = 1'b0;
  logic rst_n = 1'b0;
  always #5 clk = ~clk;

  localparam logic [2:0] REQ_CPU_DATA = 3'd1, REQ_SECURITY = 3'd2;
  localparam logic [7:0] L_DATA = 8'd1, L_KEY = 8'd2;
  localparam int NGROUPS = 7;
  localparam int NSCEN = 4;
  localparam int TIMEOUT = 600;

  logic         root_load = 1'b0;
  logic [31:0]  active_epoch = 32'd1;
  logic         keys_ready;
  logic         req_valid = 1'b0, req_ready, req_write;
  logic [2:0]   req_requester;
  logic [7:0]   req_layer;
  logic [31:0]  req_addr, req_data, req_seq, req_epoch, req_nonce;
  logic [127:0] req_tag;
  logic         rsp_valid;
  logic [7:0]   rsp_status, rsp_reason;
  logic [31:0]  rsp_data;
  logic [255:0] rsp_msg;
  logic [127:0] rsp_tag;
  c3d_layer_role_t roles [C3D_LAYERS];
  logic         layer_access [C3D_LAYERS];
  logic signed [17:0] temperature [C3D_LAYERS];
  logic         sent_prov = 1'b0;
  logic [31:0]  sent_obs [8], sent_val [8];
  logic         lockdown, zeroize, tamper, auth_ok, fault_alarm;

  crypto3d_vtf_system_top #(.FAULT_HARDEN(FAULT_HARDEN)) dut (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load), .root_key_i(VEC_ROOT),
    .active_epoch_i(active_epoch), .keys_ready_o(keys_ready),
    .req_valid_i(req_valid), .req_ready_o(req_ready), .req_requester_i(req_requester),
    .req_write_i(req_write), .req_layer_i(req_layer), .req_addr_i(req_addr), .req_data_i(req_data),
    .req_sequence_i(req_seq), .req_epoch_i(req_epoch), .req_nonce_i(req_nonce), .req_tag_i(req_tag),
    .rsp_valid_o(rsp_valid), .rsp_status_o(rsp_status), .rsp_data_o(rsp_data), .rsp_msg_o(rsp_msg),
    .rsp_tag_o(rsp_tag), .rsp_deny_reason_o(rsp_reason),
    .debug_unlocked_i(1'b0), .layer_role_i(roles), .layer_access_i(layer_access),
    .temperature_mc_i(temperature), .physical_fault_i(1'b0),
    .sentinel_provision_i(sent_prov), .sentinel_check_i(1'b0),
    .sentinel_observed_i(sent_obs), .sentinel_value_i(sent_val),
    .fault_inject_i(1'b0), .fault_mask_i(32'h0),
    .lockdown_o(lockdown), .key_zeroize_o(zeroize), .tamper_o(tamper), .auth_ok_o(auth_ok),
    .fault_alarm_o(fault_alarm)
  );

  // ---------------- requester-side signer / verifier ----------------
  logic         s_start = 1'b0;
  logic [127:0] s_key, s_tag;
  logic [255:0] s_msg;
  logic         s_busy, s_done;
  logic s_rst_n = 1'b0;
  initial #22 s_rst_n = 1'b1;
  aes_cmac32 signer (.clk(clk), .rst_n(s_rst_n), .start_i(s_start), .clear_i(1'b0), .key_i(s_key),
                     .k1_valid_i(1'b0), .k1_i(128'h0), .msg_i(s_msg), .busy_o(s_busy),
                     .done_o(s_done), .tag_o(s_tag));

  function automatic logic [127:0] key_req(input logic [2:0] r);
    case (r) 3'd0: return VEC_E1_REQ0; 3'd1: return VEC_E1_REQ1; 3'd2: return VEC_E1_REQ2;
             3'd3: return VEC_E1_REQ3; default: return VEC_E1_REQ4; endcase
  endfunction

  function automatic logic [255:0] mk_req(input logic [2:0] rq, input logic wr, input logic [7:0] ly,
                                          input logic [31:0] ad, input logic [31:0] dt, input logic [31:0] sq);
    return {8'hC3, 8'hD1, 5'd0, rq, 7'd0, wr, ly, 24'd0, ad, dt, sq, 32'd1, 32'h0BADF00D ^ sq, 32'h56544631};
  endfunction

  task automatic sign(input logic [127:0] key, input logic [255:0] msg, output logic [127:0] tag);
    @(negedge clk);
    while (s_busy) @(negedge clk);
    s_key = key; s_msg = msg; s_start = 1'b1;
    @(negedge clk); s_start = 1'b0;
    while (!s_done) @(negedge clk);
    tag = s_tag;
  endtask

  // ---------------- boot / transaction helpers ----------------
  task automatic boot();
    rst_n = 1'b0; req_valid = 1'b0; root_load = 1'b0;
    for (int l = 0; l < C3D_LAYERS; l++) begin layer_access[l] = 1'b1; temperature[l] = 18'sd25000; end
    roles[0] = C3D_LAYER_ROLE_EXEC; roles[1] = C3D_LAYER_ROLE_DATA;
    roles[2] = C3D_LAYER_ROLE_KEY_HIDE; roles[3] = C3D_LAYER_ROLE_SENTINEL;
    for (int i = 0; i < 8; i++) begin sent_val[i] = 32'h5E000000 + i; sent_obs[i] = 32'h5E000000 + i; end
    for (int i = 0; i < C3D_LAYERS * C3D_WORDS; i++) dut.mem_i.mem[i] = 32'h0;
    repeat (2) @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk); root_load = 1'b1; sent_prov = 1'b1;
    @(negedge clk); root_load = 1'b0; sent_prov = 1'b0;
    while (!keys_ready) @(negedge clk);
  endtask

  // Present a request; returns at the negedge after acceptance.
  task automatic present(input logic [2:0] rq, input logic wr, input logic [7:0] ly, input logic [31:0] ad,
                         input logic [31:0] dt, input logic [31:0] sq, input logic [127:0] tag);
    @(negedge clk);
    while (!req_ready) @(negedge clk);
    req_requester = rq; req_write = wr; req_layer = ly; req_addr = ad; req_data = dt;
    req_seq = sq; req_epoch = 32'd1; req_nonce = 32'h0BADF00D ^ sq; req_tag = tag; req_valid = 1'b1;
    @(negedge clk); req_valid = 1'b0;
  endtask

  task automatic wait_rsp(output bit got, output int cycles);
    cycles = 1; got = 1'b0;
    while (!rsp_valid && cycles < TIMEOUT) begin @(negedge clk); cycles++; end
    got = rsp_valid;
  endtask

  function automatic longint mem_sum();
    longint s = 0;
    for (int i = 0; i < C3D_LAYERS * C3D_WORDS; i++) s += longint'(dut.mem_i.mem[i]) * (i + 1);
    return s;
  endfunction

  // ---------------- fault injection ----------------
  int seed = SEED;

  function automatic int group_bits(input int g);
    case (g)
      0: return FAULT_HARDEN ? 6 : 3;
      1: return FAULT_HARDEN ? 8 : 1;
      2: return 3 + 1 + 8 + 32 + 32 + 32 + 32 + 128;
      3: return 128 * 7;
      4: return FAULT_HARDEN ? (2 + 160 + 5) : (1 + 160);
      5: return FAULT_HARDEN ? 49 : 48;
      default: return 128 * 6;
    endcase
  endfunction

  // Exhaustive mode: bits per group and their mapping onto flip() indices.
  function automatic int exh_bits(input int g);
    case (g)
      0: return group_bits(0);
      1: return group_bits(1);
      4: return FAULT_HARDEN ? 35 : 33;    // lockdown, last_sequence[2], (+ lockdown_n, seq_par[2])
      5: return group_bits(5);
      default: return 0;
    endcase
  endfunction

  function automatic int exh_map(input int g, input int b);
    if (g != 4) return b;
    if (b == 0) return 0;
    if (b <= 32) return 1 + 2 * 32 + (b - 1);
    if (b == 33) return 161;
    return 162 + 2;
  endfunction

  function automatic string group_name(input int g);
    case (g) 0: return "control"; 1: return "authdec"; 2: return "reqfields"; 3: return "cmac";
             4: return "guard"; 5: return "response"; default: return "keys"; endcase
  endfunction

  function automatic string scen_name(input int s);
    case (s) 0: return "forged"; 1: return "replay"; 2: return "read"; default: return "write"; endcase
  endfunction

  task automatic flip(input int g, input int b);
    case (g)
      0: begin
        if (b < 3) dut.state_q[b] = ~dut.state_q[b];
        else       dut.state_n_q[b - 3] = ~dut.state_n_q[b - 3];
      end
      1: begin
        if (FAULT_HARDEN) dut.r_auth_code[b] = ~dut.r_auth_code[b];
        else              dut.r_auth_ok = ~dut.r_auth_ok;
      end
      2: begin
        if (b < 3)        dut.r_requester[b] = ~dut.r_requester[b];
        else if (b < 4)   dut.r_write = ~dut.r_write;
        else if (b < 12)  dut.r_layer[b - 4] = ~dut.r_layer[b - 4];
        else if (b < 44)  dut.r_addr[b - 12] = ~dut.r_addr[b - 12];
        else if (b < 76)  dut.r_data[b - 44] = ~dut.r_data[b - 44];
        else if (b < 108) dut.r_seq[b - 76] = ~dut.r_seq[b - 76];
        else if (b < 140) dut.r_epoch[b - 108] = ~dut.r_epoch[b - 108];
        else              dut.r_tag[b - 140] = ~dut.r_tag[b - 140];
      end
      3: begin
        case (b / 128)
          0: dut.cmac_i.aes_i.state_q[b % 128] = ~dut.cmac_i.aes_i.state_q[b % 128];
          1: dut.cmac_i.aes_i.round_key_q[b % 128] = ~dut.cmac_i.aes_i.round_key_q[b % 128];
          2: dut.cmac_i.m2_q[b % 128] = ~dut.cmac_i.m2_q[b % 128];
          3: dut.cmac_msg[b % 128] = ~dut.cmac_msg[b % 128];
          4: dut.cmac_msg[128 + b % 128] = ~dut.cmac_msg[128 + b % 128];
          5: dut.cmac_key[b % 128] = ~dut.cmac_key[b % 128];
          default: dut.cmac_k1[b % 128] = ~dut.cmac_k1[b % 128];
        endcase
      end
      4: begin
        if (b == 0) dut.guard_i.lockdown_q = ~dut.guard_i.lockdown_q;
        else if (b < 161) begin
          int r, k;
          r = (b - 1) / 32; k = (b - 1) % 32;
          dut.guard_i.last_sequence[r][k] = ~dut.guard_i.last_sequence[r][k];
        end else if (b == 161) dut.guard_i.lockdown_n_q = ~dut.guard_i.lockdown_n_q;
        else dut.guard_i.seq_par_q[b - 162] = ~dut.guard_i.seq_par_q[b - 162];
      end
      5: begin
        if (b < 8)       dut.r_status[b] = ~dut.r_status[b];
        else if (b < 40) dut.r_rdata[b - 8] = ~dut.r_rdata[b - 8];
        else if (b < 48) dut.r_reason[b - 40] = ~dut.r_reason[b - 40];
        else             dut.resp_par_q = ~dut.resp_par_q;
      end
      default: begin
        int k;
        k = b / 128;
        dut.keys_i.key_q[k][b % 128] = ~dut.keys_i.key_q[k][b % 128];
      end
    endcase
  endtask

  // ---------------- one scenario run (optionally with a fault) ----------------
  // Returns the response observation; the golden run uses inject = 0.
  bit          o_got;
  logic [7:0]  o_status;
  logic [31:0] o_data;
  logic [255:0] o_msg;
  logic [127:0] o_tag;
  bit          o_alarm;
  longint      o_mem;
  int          o_cycles;

  logic [127:0] t_setup1, t_setup2, t_main;
  logic [255:0] m_main;

  task automatic run(input int scen, input bit inject, input int g, input int b, input int at);
    int c;
    boot();
    // setup (fault-free)
    case (scen)
      1: begin   // replay: write X (seq 1), write Y (seq 2), then replay seq 1
        present(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h11111111, 32'd1, t_setup1); wait_rsp(o_got, c);
        present(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h22222222, 32'd2, t_setup2); wait_rsp(o_got, c);
      end
      2: begin   // read: provision the word first
        present(REQ_SECURITY, 1'b1, L_KEY, 32'h10, 32'hA5A55A5A, 32'd1, t_setup1); wait_rsp(o_got, c);
      end
      default: ;
    endcase
    // main transaction
    case (scen)
      0: present(REQ_SECURITY, 1'b1, L_KEY, 32'h10, 32'hDEADBEEF, 32'd1, t_main);
      1: present(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h11111111, 32'd1, t_setup1);
      2: present(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, 32'd2, t_main);
      default: present(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h12345678, 32'd1, t_main);
    endcase
    if (inject) begin
      repeat (at) @(negedge clk);
      if (!rsp_valid) flip(g, b);
    end
    wait_rsp(o_got, o_cycles);
    o_status = rsp_status; o_data = rsp_data; o_msg = rsp_msg; o_tag = rsp_tag;
    repeat (3) @(negedge clk);
    o_alarm = lockdown || fault_alarm;
    o_mem = mem_sum();
  endtask

  // ---------------- campaign ----------------
  int counts [NSCEN][NGROUPS][5];   // masked, detected, hang, violation, false_ack
  bit          g_got;
  logic [7:0]  g_status;
  logic [31:0] g_data;
  logic [255:0] g_msg;
  logic [127:0] g_tag;
  bit          g_alarm;
  longint      g_mem;
  int          g_cycles;

  initial begin
    int outcome, bit_i, at, total_viol, total_det, total_nonmasked, total_fack;
    bit tag_ok, fields_ok, accepted;
    logic [127:0] vt;

    wait (s_rst_n);
    // Pre-sign every request once (keys are fixed for epoch 1).
    sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h11111111, 32'd1), t_setup1);
    sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h22222222, 32'd2), t_setup2);

    $display("FI_HEADER,hardened,scenario,group,bit,cycle,outcome");
    for (int s = 0; s < NSCEN; s++) begin
      case (s)
        0: t_main = {32'h8BADF00D, 32'h0DDBA11, 32'hFEEDFACE, 32'h1BADB002};   // forged (random) tag
        2: begin sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h10, 32'hA5A55A5A, 32'd1), t_setup1);
                 sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, 32'd2), t_main); end
        3: sign(VEC_E1_REQ1, mk_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h12345678, 32'd1), t_main);
        default: begin
          sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h11111111, 32'd1), t_setup1);
          sign(VEC_E1_REQ2, mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h40, 32'h22222222, 32'd2), t_setup2);
        end
      endcase
      run(s, 1'b0, 0, 0, 0);
      g_got = o_got; g_status = o_status; g_data = o_data; g_msg = o_msg; g_tag = o_tag;
      g_alarm = o_alarm; g_mem = o_mem; g_cycles = o_cycles;
      $display("GOLDEN,%0d,%s,status=%0d,alarm=%0d,cycles=%0d", FAULT_HARDEN, scen_name(s), g_status, g_alarm, g_cycles);

      for (int g = 0; g < NGROUPS; g++) begin
        int ntrials;
        ntrials = (MODE == 0) ? TRIALS : exh_bits(g) * g_cycles;
        for (int t = 0; t < ntrials; t++) begin
          if (MODE == 0) begin
            bit_i = $unsigned($random(seed)) % group_bits(g);
            at = $unsigned($random(seed)) % g_cycles;
          end else begin
            bit_i = exh_map(g, t / g_cycles);
            at = t % g_cycles;
          end
          run(s, 1'b1, g, bit_i, at);
          // requester-side acceptance: valid response tag and matching fields
          tag_ok = 1'b0; fields_ok = 1'b0;
          if (o_got && o_tag != '0) begin
            sign(VEC_E1_RSP, o_msg, vt);
            tag_ok = (vt == o_tag);
          end
          fields_ok = (o_msg[255:208] == g_msg[255:208]) && (o_msg[199:192] == g_msg[199:192]) &&
                      (o_msg[191:160] == g_msg[191:160]) && (o_msg[127:0] == g_msg[127:0]);
          // a requester (like crypto3d_vtf_cpu_bridge) only trusts status/data that are
          // inside the signed message
          accepted = o_got && tag_ok && fields_ok && (o_status == 8'd1) &&
                     (o_msg[215:208] == o_status) && (o_msg[159:128] == o_data) &&
                     (s != 3 || o_data == 32'h12345678);   // a write must echo the written word
          if (!o_got) outcome = 2;
          else if (o_status == g_status && o_data == g_data && o_tag == g_tag && o_alarm == g_alarm &&
                   o_mem == g_mem) outcome = 0;
          else if (s < 2) begin
            // attacks: executed or memory changed = bypass
            outcome = (o_mem != g_mem) ? 3 : ((o_status == 8'd1 && tag_ok) ? 4 : 1);
          end else begin
            // legitimate: silent corruption accepted by the requester, or silent memory change
            if (accepted && (o_data != g_data || o_mem != g_mem)) outcome = 3;
            else if (!o_alarm && !accepted && o_mem != g_mem) outcome = 3;
            else if (!o_alarm && o_status == 8'd1 && o_mem != g_mem) outcome = 3;
            else outcome = 1;
          end
          counts[s][g][outcome]++;
          if (outcome == 3)
            $display("FI,%0d,%s,%s,%0d,%0d,VIOLATION", FAULT_HARDEN, scen_name(s), group_name(g), bit_i, at);
          if (outcome == 4)
            $display("FI,%0d,%s,%s,%0d,%0d,FALSE_ACK", FAULT_HARDEN, scen_name(s), group_name(g), bit_i, at);
        end
      end
    end

    $display("FISUM_HEADER,hardened,mode,scenario,group,trials,masked,detected,hang,violation,false_ack");
    total_viol = 0; total_det = 0; total_nonmasked = 0; total_fack = 0;
    for (int s = 0; s < NSCEN; s++)
      for (int g = 0; g < NGROUPS; g++) begin
        if (counts[s][g][0] + counts[s][g][1] + counts[s][g][2] + counts[s][g][3] + counts[s][g][4] > 0)
          $display("FISUM,%0d,%0d,%s,%s,%0d,%0d,%0d,%0d,%0d,%0d", FAULT_HARDEN, MODE, scen_name(s), group_name(g),
                   counts[s][g][0] + counts[s][g][1] + counts[s][g][2] + counts[s][g][3] + counts[s][g][4],
                   counts[s][g][0], counts[s][g][1], counts[s][g][2], counts[s][g][3], counts[s][g][4]);
        total_viol += counts[s][g][3];
        total_fack += counts[s][g][4];
        total_det += counts[s][g][1] + counts[s][g][2];
        total_nonmasked += counts[s][g][1] + counts[s][g][2] + counts[s][g][3] + counts[s][g][4];
      end
    $display("FITOTAL,%0d,mode=%0d,nonmasked=%0d,detected_or_failsafe=%0d,violations=%0d,false_acks=%0d",
             FAULT_HARDEN, MODE, total_nonmasked, total_det, total_viol, total_fack);
    $display("[FI CAMPAIGN DONE] hardened=%0d", FAULT_HARDEN);
    $finish;
  end
endmodule
