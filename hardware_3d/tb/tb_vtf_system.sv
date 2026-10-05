// SPDX-License-Identifier: MIT
// End-to-end test and attack campaign for the integrated VTF system
// (crypto3d_vtf_system_top): real AES-CMAC authentication in RTL, epoch/role key
// hierarchy, guard, sentinel monitor, memory and signed responses.
//
// Golden keys and tags come from the independent Python model
// (hardware_3d/scripts/vtf_reference.py -> tb/vtf_vectors.svh). The testbench
// signs requests with its own aes_cmac32 instance and the golden keys, so the
// DUT's key schedule is checked independently.
//
// Output: CAMPAIGN rows (scenario, expected, observed, detected, lockdown) and
// METRIC rows (latency in cycles). Prints [SV TEST PASS] on success.

`timescale 1ns/1ps
import crypto3d_stack_pkg::*;

module tb_vtf_system #(parameter bit FAULT_HARDEN = 1'b0);
  `include "vtf_vectors.svh"

  logic clk = 1'b0;
  logic rst_n = 1'b0;
  always #5 clk = ~clk;

  localparam logic [2:0] REQ_CPU_FETCH = 3'd0, REQ_CPU_DATA = 3'd1, REQ_SECURITY = 3'd2,
                         REQ_DMA = 3'd3, REQ_DEBUG = 3'd4;
  localparam logic [7:0] DENY_NONE = 8'd0, DENY_LOCKDOWN = 8'd1, DENY_POLICY = 8'd2, DENY_AUTH = 8'd3,
                         DENY_REPLAY = 8'd4, DENY_EPOCH = 8'd5, DENY_THERMAL = 8'd6,
                         DENY_PHYSICAL = 8'd7, DENY_SENTINEL = 8'd8;
  localparam logic [7:0] L_EXEC = 8'd0, L_DATA = 8'd1, L_KEY = 8'd2, L_SENT = 8'd3;

  // ---------------- DUT ----------------
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
  logic         debug_unlocked = 1'b0;
  c3d_layer_role_t roles [C3D_LAYERS];
  logic         layer_access [C3D_LAYERS];
  logic signed [17:0] temperature [C3D_LAYERS];
  logic         physical_fault = 1'b0;
  logic         sent_prov = 1'b0, sent_check = 1'b0;
  logic [31:0]  sent_obs [8], sent_val [8];
  logic         fault_inject = 1'b0;
  logic [31:0]  fault_mask = 32'h0;
  logic         lockdown, zeroize, tamper, auth_ok;

  logic fault_alarm;
  crypto3d_vtf_system_top #(.FAULT_HARDEN(FAULT_HARDEN)) dut (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load), .root_key_i(VEC_ROOT),
    .active_epoch_i(active_epoch), .keys_ready_o(keys_ready),
    .req_valid_i(req_valid), .req_ready_o(req_ready), .req_requester_i(req_requester),
    .req_write_i(req_write), .req_layer_i(req_layer), .req_addr_i(req_addr), .req_data_i(req_data),
    .req_sequence_i(req_seq), .req_epoch_i(req_epoch), .req_nonce_i(req_nonce), .req_tag_i(req_tag),
    .rsp_valid_o(rsp_valid), .rsp_status_o(rsp_status), .rsp_data_o(rsp_data), .rsp_msg_o(rsp_msg),
    .rsp_tag_o(rsp_tag), .rsp_deny_reason_o(rsp_reason),
    .debug_unlocked_i(debug_unlocked), .layer_role_i(roles), .layer_access_i(layer_access),
    .temperature_mc_i(temperature), .physical_fault_i(physical_fault),
    .sentinel_provision_i(sent_prov), .sentinel_check_i(sent_check),
    .sentinel_observed_i(sent_obs), .sentinel_value_i(sent_val),
    .fault_inject_i(fault_inject), .fault_mask_i(fault_mask),
    .lockdown_o(lockdown), .key_zeroize_o(zeroize), .tamper_o(tamper), .auth_ok_o(auth_ok), .fault_alarm_o(fault_alarm)
  );

  // ---------------- testbench signer ----------------
  logic         s_start = 1'b0;
  logic [127:0] s_key, s_tag;
  logic [255:0] s_msg;
  logic         s_busy, s_done;
  aes_cmac32 signer (.clk(clk), .rst_n(rst_n), .start_i(s_start), .clear_i(1'b0), .key_i(s_key), .k1_valid_i(1'b0), .k1_i(128'h0),
                     .msg_i(s_msg), .busy_o(s_busy), .done_o(s_done), .tag_o(s_tag));

  function automatic logic [127:0] key_req(input int r, input int e);
    if (e == 1) begin
      case (r) 0: return VEC_E1_REQ0; 1: return VEC_E1_REQ1; 2: return VEC_E1_REQ2;
               3: return VEC_E1_REQ3; default: return VEC_E1_REQ4; endcase
    end
    case (r) 0: return VEC_E2_REQ0; 1: return VEC_E2_REQ1; 2: return VEC_E2_REQ2;
             3: return VEC_E2_REQ3; default: return VEC_E2_REQ4; endcase
  endfunction

  function automatic logic [255:0] mk_req(input logic [2:0] rq, input logic wr, input logic [7:0] ly,
                                          input logic [31:0] ad, input logic [31:0] dt, input logic [31:0] sq,
                                          input logic [31:0] ep, input logic [31:0] nc);
    return {8'hC3, 8'hD1, 5'd0, rq, 7'd0, wr, ly, 24'd0, ad, dt, sq, ep, nc, 32'h56544631};
  endfunction

  task automatic sign(input logic [127:0] key, input logic [255:0] msg, output logic [127:0] tag);
    @(negedge clk);
    while (s_busy) @(negedge clk);
    s_key = key; s_msg = msg; s_start = 1'b1;
    @(negedge clk); s_start = 1'b0;
    while (!s_done) @(negedge clk);
    tag = s_tag;
  endtask

  // ---------------- helpers ----------------
  int failures = 0;
  logic [31:0] next_seq [5];
  int lat;

  task automatic boot(input logic [31:0] epoch);
    rst_n = 1'b0; req_valid = 1'b0; root_load = 1'b0; physical_fault = 1'b0;
    fault_inject = 1'b0; fault_mask = '0; debug_unlocked = 1'b0; active_epoch = epoch;
    for (int l = 0; l < C3D_LAYERS; l++) begin layer_access[l] = 1'b1; temperature[l] = 18'sd25000; end
    roles[0] = C3D_LAYER_ROLE_EXEC; roles[1] = C3D_LAYER_ROLE_DATA;
    roles[2] = C3D_LAYER_ROLE_KEY_HIDE; roles[3] = C3D_LAYER_ROLE_SENTINEL;
    for (int i = 0; i < 8; i++) begin sent_val[i] = 32'h5E000000 + i; sent_obs[i] = 32'h5E000000 + i; end
    for (int r = 0; r < 5; r++) next_seq[r] = 32'd1;
    repeat (3) @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk); root_load = 1'b1; sent_prov = 1'b1;
    @(negedge clk); root_load = 1'b0; sent_prov = 1'b0;
    while (!keys_ready) @(negedge clk);
  endtask

  // Send one request (already signed) and wait for the response.
  task automatic send(input logic [2:0] rq, input logic wr, input logic [7:0] ly, input logic [31:0] ad,
                      input logic [31:0] dt, input logic [31:0] sq, input logic [31:0] ep,
                      input logic [127:0] tag, output int cycles);
    @(negedge clk);
    while (!req_ready) @(negedge clk);
    req_requester = rq; req_write = wr; req_layer = ly; req_addr = ad; req_data = dt;
    req_seq = sq; req_epoch = ep; req_nonce = 32'h0BADF00D ^ sq; req_tag = tag; req_valid = 1'b1;
    @(negedge clk); req_valid = 1'b0;
    cycles = 1;
    while (!rsp_valid) begin @(negedge clk); cycles++; end
  endtask

  // Sign with the requester's own key and send; consumes a fresh sequence number.
  task automatic do_req(input logic [2:0] rq, input logic wr, input logic [7:0] ly, input logic [31:0] ad,
                        input logic [31:0] dt, output int cycles);
    logic [127:0] t;
    sign(key_req(rq, active_epoch), mk_req(rq, wr, ly, ad, dt, next_seq[rq], active_epoch, 32'h0BADF00D ^ next_seq[rq]), t);
    send(rq, wr, ly, ad, dt, next_seq[rq], active_epoch, t, cycles);
    next_seq[rq] = next_seq[rq] + 1;
  endtask

  task automatic expect_rsp(input string scenario, input logic [7:0] exp_reason, input logic exp_lock);
    logic detected;
    detected = (rsp_status == 8'd0);
    $display("CAMPAIGN,%s,%0d,%0d,%0d,%0d", scenario, exp_reason, rsp_reason, detected, lockdown);
    if (rsp_reason !== exp_reason || lockdown !== exp_lock || (exp_reason != DENY_NONE && !detected)) begin
      $display("[FAIL] %s reason=%0d (exp %0d) lockdown=%0d (exp %0d) status=%0d",
               scenario, rsp_reason, exp_reason, lockdown, exp_lock, rsp_status);
      failures++;
    end
  endtask

  // Response authenticity is checked by the requester with the response key.
  task automatic check_rsp_sig(input string name, input logic [31:0] epoch);
    logic [127:0] t;
    sign((epoch == 1) ? VEC_E1_RSP : VEC_E2_RSP, rsp_msg, t);
    if (t !== rsp_tag) begin $display("[FAIL] %s response tag invalid", name); failures++; end
  endtask

  logic [127:0] tag, tag2;
  logic [255:0] m;
  int c_cold, c_warm;

  initial begin
    $display("CAMPAIGN_HEADER,scenario,expected_reason,observed_reason,detected,lockdown");

    // ---- 0. key schedule equals the independent Python model ----
    boot(32'd1);
    for (int r = 0; r < 5; r++)
      if (dut.req_key[r] !== key_req(r, 1)) begin $display("[FAIL] epoch-1 key r%0d", r); failures++; end
    if (dut.rsp_key !== VEC_E1_RSP) begin $display("[FAIL] epoch-1 rsp key"); failures++; end
    // the testbench message format equals the reference format
    m = mk_req(REQ_SECURITY, 1'b1, L_KEY, 32'h10, 32'hA5A55A5A, 32'd1, 32'd1, VEC_NONCE_2_1_2_1);
    if (m !== VEC_REQ_MSG) begin $display("[FAIL] request serialization"); failures++; end
    sign(VEC_E1_REQ2, m, tag);
    if (tag !== VEC_REQ_TAG) begin $display("[FAIL] request tag vs reference"); failures++; end

    // ---- 1. legitimate security-tier write + read back, signed responses ----
    do_req(REQ_SECURITY, 1'b1, L_KEY, 32'h10, 32'hA5A55A5A, c_cold);
    expect_rsp("legit_security_write", DENY_NONE, 1'b0);
    check_rsp_sig("legit_security_write", 1);
    do_req(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, c_warm);
    expect_rsp("legit_security_read", DENY_NONE, 1'b0);
    check_rsp_sig("legit_security_read", 1);
    if (rsp_data !== 32'hA5A55A5A) begin $display("[FAIL] read-back data %08h", rsp_data); failures++; end
    do_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h12345678, lat);
    expect_rsp("legit_cpu_data_write", DENY_NONE, 1'b0);
    $display("METRIC,latency_cycles_first_transaction,%0d", c_cold);
    $display("METRIC,latency_cycles_steady_state,%0d", c_warm);

    // ---- 2. policy (non-severe): sequence consumed, no lockdown ----
    do_req(REQ_DMA, 1'b0, L_KEY, 32'h10, 32'h0, lat);
    expect_rsp("dma_reads_key_tier", DENY_POLICY, 1'b0);
    do_req(REQ_CPU_FETCH, 1'b1, L_EXEC, 32'h0, 32'h1, lat);
    expect_rsp("fetch_attempts_write", DENY_POLICY, 1'b0);
    do_req(REQ_DEBUG, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    expect_rsp("debug_while_locked", DENY_POLICY, 1'b0);
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h400, 32'h0, lat);   // WORDS = 1024
    expect_rsp("address_out_of_range", DENY_POLICY, 1'b0);
    do_req(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, lat);     // still operational
    expect_rsp("still_operational_after_policy_denials", DENY_NONE, 1'b0);

    // ---- 3. forged tag -> AUTH, lockdown, zeroize; keys wiped; later valid request denied ----
    send(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'hBAD, next_seq[REQ_CPU_DATA], 32'd1, 128'hDEADBEEF, lat);
    expect_rsp("forged_tag", DENY_AUTH, 1'b1);
    if (keys_ready !== 1'b0 || dut.req_key[1] !== '0) begin $display("[FAIL] keys not wiped"); failures++; end
    if (rsp_tag !== '0) begin $display("[FAIL] response signed after zeroize"); failures++; end
    do_req(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, lat);
    expect_rsp("valid_request_after_lockdown", DENY_LOCKDOWN, 1'b1);
    // secure boot reloads the root, but the guard stays locked until reset (fail-closed)
    @(negedge clk); root_load = 1'b1; @(negedge clk); root_load = 1'b0;
    repeat (120) @(negedge clk);
    do_req(REQ_SECURITY, 1'b0, L_KEY, 32'h10, 32'h0, lat);
    expect_rsp("lockdown_persists_after_root_reload", DENY_LOCKDOWN, 1'b1);

    // ---- 4. TSV bit flip on a signed request (data and address) ----
    boot(32'd1);
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h11111111, 32'd1, 32'd1, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h11111111 ^ 32'h00000100, 32'd1, 32'd1, tag, lat);
    expect_rsp("tsv_bitflip_data", DENY_AUTH, 1'b1);
    boot(32'd1);
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h11111111, 32'd1, 32'd1, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20 ^ 32'h1, 32'h11111111, 32'd1, 32'd1, tag, lat);
    expect_rsp("tsv_bitflip_address", DENY_AUTH, 1'b1);

    // ---- 5. replay of an accepted request ----
    boot(32'd1);
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h22222222, 32'd1, 32'd1, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h22222222, 32'd1, 32'd1, tag, lat);
    expect_rsp("original_before_replay", DENY_NONE, 1'b0);
    send(REQ_CPU_DATA, 1'b1, L_DATA, 32'h20, 32'h22222222, 32'd1, 32'd1, tag, lat);
    expect_rsp("replay", DENY_REPLAY, 1'b1);

    // ---- 6. stale epoch and epoch-key binding ----
    boot(32'd2);
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, 32'd1, 32'd1, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, 32'd1, 32'd1, tag, lat);
    expect_rsp("stale_epoch_field", DENY_EPOCH, 1'b1);
    boot(32'd2);
    // correct epoch field but tag made with the epoch-1 key: rejected by the key hierarchy
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, 32'd1, 32'd2, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, 32'd1, 32'd2, tag, lat);
    expect_rsp("old_epoch_key_new_epoch_field", DENY_AUTH, 1'b1);
    boot(32'd2);
    for (int r = 0; r < 5; r++)
      if (dut.req_key[r] !== key_req(r, 2)) begin $display("[FAIL] epoch-2 key r%0d", r); failures++; end
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    expect_rsp("legit_epoch2", DENY_NONE, 1'b0);
    check_rsp_sig("legit_epoch2", 2);

    // ---- 7. requester impersonation: DMA request signed with the CPU-data key ----
    boot(32'd1);
    sign(key_req(REQ_CPU_DATA, 1), mk_req(REQ_DMA, 1'b1, L_DATA, 32'h20, 32'h33, 32'd1, 32'd1, 32'h0BADF00D ^ 32'd1), tag);
    send(REQ_DMA, 1'b1, L_DATA, 32'h20, 32'h33, 32'd1, 32'd1, tag, lat);
    expect_rsp("requester_impersonation", DENY_AUTH, 1'b1);

    // ---- 8. environment: thermal, physical fault, sentinel ----
    boot(32'd1);
    temperature[1] = 18'sd95000;
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    expect_rsp("thermal_trip", DENY_LOCKDOWN, 1'b1);   // lockdown latched as soon as the alarm rises
    boot(32'd1);
    physical_fault = 1'b1;
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    expect_rsp("physical_fault", DENY_LOCKDOWN, 1'b1);
    boot(32'd1);
    sent_obs[3] = 32'hFFFFFFFF;
    @(negedge clk); sent_check = 1'b1; @(negedge clk); sent_check = 1'b0;
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    expect_rsp("sentinel_mismatch", DENY_LOCKDOWN, 1'b1);

    // ---- 9. fault injection on the memory write path -> tamper ----
    boot(32'd1);
    fault_inject = 1'b1; fault_mask = 32'h0000FF00;
    do_req(REQ_CPU_DATA, 1'b1, L_DATA, 32'h30, 32'h44444444, lat);
    fault_inject = 1'b0;
    $display("CAMPAIGN,fault_injection_write,tamper,%0d,%0d,%0d", rsp_reason, tamper, lockdown);
    if (tamper !== 1'b1) begin $display("[FAIL] fault injection not flagged"); failures++; end

    // ---- 10. tampered response is detected by the requester ----
    boot(32'd1);
    do_req(REQ_CPU_DATA, 1'b0, L_DATA, 32'h20, 32'h0, lat);
    m = rsp_msg; m[100] = ~m[100];
    sign(VEC_E1_RSP, m, tag2);
    $display("CAMPAIGN,response_tamper,tag_mismatch,%0d,%0d,%0d", 0, (tag2 !== rsp_tag), lockdown);
    if (tag2 === rsp_tag) begin $display("[FAIL] tampered response verified"); failures++; end

    if (failures == 0) $display("[SV TEST PASS] tb_vtf_system");
    else               $display("[SV TEST FAIL] tb_vtf_system failures=%0d", failures);
    $finish;
  end

  initial begin
    #20000000;
    $display("[SV TEST FAIL] tb_vtf_system timeout");
    $finish;
  end
endmodule
