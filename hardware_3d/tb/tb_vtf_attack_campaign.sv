// SPDX-License-Identifier: MIT
// Controlled attack campaign on the RTL (research gate step 4).
//
// The same stimulus drives the VTF-protected top and the unprotected baseline
// in lock-step. Each scenario resets both, provisions memory with valid
// security-tier writes, injects one attack, and records for each variant:
//   detected      denied_o or tamper_o asserted on the attack transaction
//   reason        deny_reason_o (protected only; 0 for the baseline)
//   lockdown/zeroize outputs
//   integrity     whether the provisioned word survived the attack
// One CSV row per (scenario, variant) is printed with the prefix "CAMPAIGN,".
// The run fails ($fatal) if the protected top misses any attack or allows a
// write that should have been blocked.

`timescale 1ns/1ps
import crypto3d_stack_pkg::*;

module tb_vtf_attack_campaign;
  logic clk = 0;
  logic rst_n = 0;
  always #5 clk = ~clk;

  localparam logic [2:0] REQ_CPU_FETCH = 3'd0;
  localparam logic [2:0] REQ_CPU_DATA  = 3'd1;
  localparam logic [2:0] REQ_SECURITY  = 3'd2;
  localparam logic [2:0] REQ_DMA       = 3'd3;
  localparam logic [2:0] REQ_DEBUG     = 3'd4;

  localparam logic [7:0] DENY_LOCKDOWN = 8'd1;
  localparam logic [7:0] DENY_POLICY   = 8'd2;
  localparam logic [7:0] DENY_AUTH     = 8'd3;
  localparam logic [7:0] DENY_REPLAY   = 8'd4;
  localparam logic [7:0] DENY_EPOCH    = 8'd5;
  localparam logic [7:0] DENY_THERMAL  = 8'd6;
  localparam logic [7:0] DENY_PHYSICAL = 8'd7;
  localparam logic [7:0] DENY_SENTINEL = 8'd8;
  localparam logic [7:0] TAMPER_ONLY   = 8'hFF;  // detected via tamper_o, not a deny reason

  // Shared stimulus.
  logic req_valid, op_write, auth_ok, debug_unlocked;
  logic [2:0] requester;
  logic [C3D_LAYER_WIDTH-1:0] layer;
  logic [C3D_ADDR_WIDTH-1:0] addr;
  logic [31:0] wdata, seq_num, epoch, active_epoch, fault_mask;
  c3d_layer_role_t roles [C3D_LAYERS];
  logic layer_access [C3D_LAYERS];
  logic signed [17:0] temperature_mc [C3D_LAYERS];
  logic physical_fault, sentinel_fault, fault_inject;

  // Per-variant observations: index 0 = protected, 1 = unprotected.
  logic [31:0] rdata [2];
  logic ready [2], denied [2], tamper [2], lockdown [2], zeroize [2];
  logic [7:0] reason [2];

  crypto3d_secure_stack_top prot (
    .clk, .rst_n, .req_valid_i(req_valid), .requester_i(requester), .op_write_i(op_write),
    .layer_i(layer), .addr_i(addr), .wdata_i(wdata), .sequence_i(seq_num), .epoch_i(epoch),
    .active_epoch_i(active_epoch), .auth_ok_i(auth_ok), .debug_unlocked_i(debug_unlocked),
    .layer_role_i(roles), .layer_access_i(layer_access), .temperature_mc_i(temperature_mc),
    .physical_fault_i(physical_fault), .sentinel_fault_i(sentinel_fault),
    .fault_inject_i(fault_inject), .fault_mask_i(fault_mask),
    .rdata_o(rdata[0]), .ready_o(ready[0]), .denied_o(denied[0]), .tamper_o(tamper[0]),
    .lockdown_o(lockdown[0]), .key_zeroize_o(zeroize[0]), .deny_reason_o(reason[0])
  );

  crypto3d_unprotected_stack_top base (
    .clk, .rst_n, .req_valid_i(req_valid), .requester_i(requester), .op_write_i(op_write),
    .layer_i(layer), .addr_i(addr), .wdata_i(wdata), .sequence_i(seq_num), .epoch_i(epoch),
    .active_epoch_i(active_epoch), .auth_ok_i(auth_ok), .debug_unlocked_i(debug_unlocked),
    .layer_role_i(roles), .layer_access_i(layer_access), .temperature_mc_i(temperature_mc),
    .physical_fault_i(physical_fault), .sentinel_fault_i(sentinel_fault),
    .fault_inject_i(fault_inject), .fault_mask_i(fault_mask),
    .rdata_o(rdata[1]), .ready_o(ready[1]), .denied_o(denied[1]), .tamper_o(tamper[1]),
    .lockdown_o(lockdown[1]), .key_zeroize_o(zeroize[1]), .deny_reason_o(reason[1])
  );

  logic [31:0] next_seq [5];
  int failures = 0;
  int scenarios = 0;

  // Captured result of the most recent transaction, per variant.
  logic got_detect [2], got_lock [2], got_zero [2];
  logic [7:0] got_reason [2];
  logic [31:0] got_rdata [2];

  task automatic cycle; begin @(posedge clk); #1; end endtask

  task automatic idle_inputs;
    begin
      req_valid = 0; op_write = 0; requester = REQ_SECURITY; layer = 0; addr = 0;
      wdata = 0; seq_num = 0; auth_ok = 1; debug_unlocked = 0;
      physical_fault = 0; sentinel_fault = 0; fault_inject = 0; fault_mask = 32'h0000_0001;
      for (int i = 0; i < C3D_LAYERS; i++) begin
        temperature_mc[i] = 18'sd25000;
        layer_access[i] = 1'b1;
      end
    end
  endtask

  task automatic reset_all;
    begin
      idle_inputs();
      epoch = 32'd7; active_epoch = 32'd7;
      for (int r = 0; r < 5; r++) next_seq[r] = 32'd1;
      rst_n = 0; repeat (2) cycle(); rst_n = 1; cycle();
    end
  endtask

  // One transaction. Combinational guard outputs are sampled before the clock
  // edge; registered memory responses in the following cycle.
  task automatic transact(input logic [2:0] req, input logic wr, input int lyr, input int a,
                          input logic [31:0] d, input logic [31:0] seq);
    begin
      requester = req; op_write = wr; layer = lyr[C3D_LAYER_WIDTH-1:0];
      addr = a[C3D_ADDR_WIDTH-1:0]; wdata = d; seq_num = seq; req_valid = 1;
      #1;
      for (int v = 0; v < 2; v++) begin
        got_detect[v] = denied[v] | tamper[v];
        got_lock[v] = lockdown[v];
        got_zero[v] = zeroize[v];
        got_reason[v] = reason[v];
      end
      cycle();
      // Drop the request and let combinational guard outputs settle before
      // sampling the registered memory response (avoids judging the guard on
      // its already-advanced sequence state).
      req_valid = 0;
      #1;
      for (int v = 0; v < 2; v++) begin
        got_detect[v] = got_detect[v] | denied[v] | tamper[v];
        got_rdata[v] = rdata[v];
      end
    end
  endtask

  task automatic valid_op(input logic [2:0] req, input logic wr, input int lyr, input int a,
                          input logic [31:0] d);
    begin
      transact(req, wr, lyr, a, d, next_seq[req]);
      next_seq[req] = next_seq[req] + 1;
    end
  endtask

  // Read back a word with a fresh reset so lockdown does not hide memory state.
  // BRAM contents are not reset, so this observes what the attack did.
  task automatic probe(input int lyr, input int a, output logic [31:0] w0, output logic [31:0] w1);
    begin
      reset_all();
      valid_op(REQ_SECURITY, 1'b0, lyr, a, 32'd0);
      w0 = got_rdata[0];
      w1 = got_rdata[1];
    end
  endtask

  // expect_preserved=0 marks attacks the architecture can detect but not
  // prevent (e.g. a fault that corrupts data while it is being written).
  task automatic report(input string name, input logic [7:0] expect_reason,
                        input logic expect_lockdown, input int lyr, input int a,
                        input logic [31:0] golden, input logic expect_preserved);
    logic [7:0] r [2];
    logic d [2], l [2], z [2];
    logic [31:0] w [2];
    logic ok;
    string variant;
    begin
      for (int v = 0; v < 2; v++) begin
        d[v] = got_detect[v]; l[v] = got_lock[v]; z[v] = got_zero[v]; r[v] = got_reason[v];
      end
      probe(lyr, a, w[0], w[1]);
      scenarios++;
      for (int v = 0; v < 2; v++) begin
        if (v == 0) variant = "protected"; else variant = "unprotected";
        $display("CAMPAIGN,%s,%s,%0d,%0d,%0d,%0d,%0d",
                 name, variant, d[v], r[v], l[v], z[v], (w[v] == golden));
      end
      ok = d[0] && (expect_reason == TAMPER_ONLY || r[0] == expect_reason) &&
           (l[0] == expect_lockdown) && ((w[0] == golden) == expect_preserved);
      if (!ok) begin
        failures++;
        $display("CAMPAIGN_FAIL,%s,expected reason=%0d lockdown=%0d", name, expect_reason, expect_lockdown);
      end
    end
  endtask

  task automatic provision(input int lyr, input int a, input logic [31:0] d);
    begin
      reset_all();
      valid_op(REQ_SECURITY, 1'b1, lyr, a, d);
    end
  endtask

  localparam logic [31:0] GOLD = 32'hC0DE_5EED;
  localparam logic [31:0] EVIL = 32'hBAD0_BAD0;

  initial begin
    roles[0] = C3D_LAYER_ROLE_EXEC;
    roles[1] = C3D_LAYER_ROLE_DATA;
    roles[2] = C3D_LAYER_ROLE_KEY_HIDE;
    roles[3] = C3D_LAYER_ROLE_SENTINEL;
    $display("CAMPAIGN_HEADER,scenario,variant,detected,deny_reason,lockdown,zeroize,integrity_preserved");

    // 0. Baseline: a valid data write must succeed on both variants.
    provision(1, 5, GOLD);
    valid_op(REQ_CPU_DATA, 1'b1, 1, 6, 32'h1234_5678);
    if (got_detect[0] || got_detect[1] || got_lock[0]) begin
      failures++; $display("CAMPAIGN_FAIL,valid_write,false positive");
    end
    $display("CAMPAIGN,valid_write,protected,%0d,%0d,%0d,%0d,1",
             got_detect[0], got_reason[0], got_lock[0], got_zero[0]);
    $display("CAMPAIGN,valid_write,unprotected,%0d,0,0,0,1", got_detect[1]);

    // 1. Replay of an already-consumed authenticated write.
    provision(1, 5, GOLD);
    valid_op(REQ_CPU_DATA, 1'b1, 1, 9, 32'h0000_0001);
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA] - 1);
    report("replay", DENY_REPLAY, 1'b1, 1, 5, GOLD, 1'b1);

    // 2. Sequence gap (skipped/forged counter).
    provision(1, 5, GOLD);
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA] + 3);
    report("sequence_gap", DENY_REPLAY, 1'b1, 1, 5, GOLD, 1'b1);

    // 3. Request bound to a stale epoch.
    provision(1, 5, GOLD);
    epoch = active_epoch - 1;
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA]);
    report("stale_epoch", DENY_EPOCH, 1'b1, 1, 5, GOLD, 1'b1);

    // 4. Forged transaction: AES-CMAC tag mismatch reported by the authenticator.
    provision(1, 5, GOLD);
    auth_ok = 0;
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA]);
    report("cmac_forgery", DENY_AUTH, 1'b1, 1, 5, GOLD, 1'b1);

    // 5. Layer spoof: CPU data port writing the key/metadata tier.
    provision(2, 3, GOLD);
    transact(REQ_CPU_DATA, 1'b1, 2, 3, EVIL, next_seq[REQ_CPU_DATA]);
    report("key_tier_write", DENY_POLICY, 1'b0, 2, 3, GOLD, 1'b1);

    // 6. CPU fetch port writing executable code.
    provision(0, 4, GOLD);
    transact(REQ_CPU_FETCH, 1'b1, 0, 4, EVIL, next_seq[REQ_CPU_FETCH]);
    report("fetch_port_code_write", DENY_POLICY, 1'b0, 0, 4, GOLD, 1'b1);

    // 7. DMA overwriting executable code.
    provision(0, 4, GOLD);
    transact(REQ_DMA, 1'b1, 0, 4, EVIL, next_seq[REQ_DMA]);
    report("dma_code_overwrite", DENY_POLICY, 1'b0, 0, 4, GOLD, 1'b1);

    // 8. Locked debug port writing data.
    provision(1, 5, GOLD);
    transact(REQ_DEBUG, 1'b1, 1, 5, EVIL, next_seq[REQ_DEBUG]);
    report("locked_debug_write", DENY_POLICY, 1'b0, 1, 5, GOLD, 1'b1);

    // 9. Unknown requester identity (5..7).
    provision(1, 5, GOLD);
    transact(3'd6, 1'b1, 1, 5, EVIL, 32'd1);
    report("unknown_requester", DENY_POLICY, 1'b1, 1, 5, GOLD, 1'b1);

    // 10. Thermal attack/over-temperature on one tier.
    provision(1, 5, GOLD);
    temperature_mc[3] = 18'sd95000;
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA]);
    report("thermal_trip", DENY_THERMAL, 1'b1, 1, 5, GOLD, 1'b1);

    // 11. Physical/TSV fault sensor.
    provision(1, 5, GOLD);
    physical_fault = 1;
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA]);
    report("physical_fault", DENY_PHYSICAL, 1'b1, 1, 5, GOLD, 1'b1);

    // 12. Sentinel-tier canary corruption.
    provision(1, 5, GOLD);
    sentinel_fault = 1;
    transact(REQ_CPU_DATA, 1'b1, 1, 5, EVIL, next_seq[REQ_CPU_DATA]);
    report("sentinel_fault", DENY_SENTINEL, 1'b1, 1, 5, GOLD, 1'b1);

    // 13. TSV bit-flip on an otherwise valid read: detection by tamper only.
    provision(1, 5, GOLD);
    fault_inject = 1; fault_mask = 32'h0000_0100;
    valid_op(REQ_CPU_DATA, 1'b0, 1, 5, 32'd0);
    fault_inject = 0;
    report("tsv_bitflip_read", TAMPER_ONLY, 1'b0, 1, 5, GOLD, 1'b1);

    // 13b. TSV bit-flip while an authorized write is stored: detected (tamper
    // latches) but NOT prevented -- the stored word is corrupted on both
    // variants. Reported honestly as detection-only.
    provision(1, 5, 32'h0);
    fault_inject = 1; fault_mask = 32'h0000_0100;
    valid_op(REQ_CPU_DATA, 1'b1, 1, 5, GOLD);
    fault_inject = 0;
    report("tsv_bitflip_write", TAMPER_ONLY, 1'b0, 1, 5, GOLD, 1'b0);

    // 14. Any request after lockdown is refused, even a well-formed one.
    provision(1, 5, GOLD);
    auth_ok = 0;
    transact(REQ_CPU_DATA, 1'b1, 1, 9, EVIL, next_seq[REQ_CPU_DATA]);
    auth_ok = 1;
    valid_op(REQ_CPU_DATA, 1'b1, 1, 5, EVIL);
    report("post_lockdown_write", DENY_LOCKDOWN, 1'b1, 1, 5, GOLD, 1'b1);

    $display("CAMPAIGN_SUMMARY,scenarios=%0d,protected_failures=%0d", scenarios, failures);
    if (failures != 0) $fatal(1, "VTF attack campaign: %0d protected-variant failures", failures);
    $display("[SV TEST PASS] tb_vtf_attack_campaign");
    $finish;
  end
endmodule
