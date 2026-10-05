// SPDX-License-Identifier: MIT
// Testbench for memory encryption + integrity tree (roadmap 2.1).
// Expected values come from the independent Python reference
// (hardware_3d/scripts/mem_integrity_reference.py -> tb/mit_vectors.svh).
// Attacks edit the untrusted store directly (bit flip, splicing, counter
// rollback, full replay of an old snapshot, tree-node and sibling tampering).

`timescale 1ns/1ps

module tb_memory_integrity;
  `include "mit_vectors.svh"

  localparam int BLOCKS = 16;
  localparam int BW = 4;
  localparam int NODES = BLOCKS - 2;
  localparam int NW = $clog2(NODES);

  logic clk = 1'b0;
  always #5 clk = ~clk;
  logic rst_n, init, zeroize;
  logic req_valid, req_ready, req_write;
  logic [BW-1:0] req_blk;
  logic [127:0] req_wdata;
  logic rsp_valid, tamper;
  logic [1:0] rsp_status;
  logic [127:0] rsp_rdata, root;

  logic [BW-1:0] st_blk, st_sib;
  logic [127:0] st_ct, st_mac, st_node_a, st_node_b, w_ct, w_mac, w_node;
  logic [31:0] st_ctr, st_sib_ctr, w_ctr;
  logic [NW-1:0] st_na, st_nb, w_naddr;
  logic st_clear, st_dwe, st_nwe;

  memory_integrity_tree #(.BLOCKS(BLOCKS)) dut (
    .clk(clk), .rst_n(rst_n), .init_i(init), .zeroize_i(zeroize),
    .key_enc_i(MIT_K_ENC), .key_mac_i(MIT_K_MAC), .key_tree_i(MIT_K_TREE),
    .req_valid_i(req_valid), .req_ready_o(req_ready), .req_write_i(req_write),
    .req_blk_i(req_blk), .req_wdata_i(req_wdata),
    .rsp_valid_o(rsp_valid), .rsp_status_o(rsp_status), .rsp_rdata_o(rsp_rdata),
    .tamper_o(tamper), .root_o(root),
    .st_blk_o(st_blk), .st_sib_o(st_sib), .st_ct_i(st_ct), .st_mac_i(st_mac),
    .st_ctr_i(st_ctr), .st_sib_ctr_i(st_sib_ctr),
    .st_node_a_o(st_na), .st_node_b_o(st_nb), .st_node_a_i(st_node_a), .st_node_b_i(st_node_b),
    .st_clear_o(st_clear), .st_data_we_o(st_dwe), .st_ct_o(w_ct), .st_mac_o(w_mac), .st_ctr_o(w_ctr),
    .st_node_we_o(st_nwe), .st_node_waddr_o(w_naddr), .st_node_wdata_o(w_node)
  );

  mit_untrusted_store #(.BLOCKS(BLOCKS)) store (
    .clk(clk), .blk_i(st_blk), .sib_i(st_sib), .ct_o(st_ct), .mac_o(st_mac), .ctr_o(st_ctr),
    .sib_ctr_o(st_sib_ctr), .node_a_i(st_na), .node_b_i(st_nb), .node_a_o(st_node_a),
    .node_b_o(st_node_b), .clear_i(st_clear), .data_we_i(st_dwe), .ct_i(w_ct), .mac_i(w_mac),
    .ctr_i(w_ctr), .node_we_i(st_nwe), .node_waddr_i(w_naddr), .node_wdata_i(w_node)
  );

  int fails = 0;
  int last_cycles;
  logic [1:0] last_status;
  logic [127:0] last_data;

  task automatic check(input bit cond, input string name);
    if (cond) $display("[PASS] %s", name);
    else begin $display("[FAIL] %s", name); fails++; end
  endtask

  task automatic do_init();
    rst_n = 1'b0; init = 1'b0; zeroize = 1'b0; req_valid = 1'b0; req_write = 1'b0;
    req_blk = '0; req_wdata = '0;
    repeat (3) @(posedge clk);
    #1 rst_n = 1'b1;
    @(posedge clk); #1 init = 1'b1;
    @(posedge clk); #1 init = 1'b0;
    while (!req_ready) @(posedge clk);
  endtask

  task automatic op(input bit write, input logic [BW-1:0] blk, input logic [127:0] data);
    int c;
    while (!req_ready) @(posedge clk);
    #1 req_valid = 1'b1; req_write = write; req_blk = blk; req_wdata = data;
    @(posedge clk);
    #1 req_valid = 1'b0;
    c = 1;
    while (!rsp_valid) begin @(posedge clk); c++; end
    last_cycles = c; last_status = rsp_status; last_data = rsp_rdata;
    @(posedge clk);
  endtask

  task automatic run_script(output bit roots_ok);
    roots_ok = 1'b1;
    for (int k = 0; k < MIT_NSCRIPT; k++) begin
      op(1'b1, MIT_SCRIPT_BLK[k], MIT_SCRIPT_PT[k]);
      roots_ok &= (last_status == 2'd0) && (root == MIT_SCRIPT_ROOT[k]);
    end
  endtask

  task automatic campaign(input string name, input bit detected);
    $display("CAMPAIGN,%s,%0d,%0d", name, detected, tamper);
    check(detected, {"attack detected: ", name});
  endtask

  logic [127:0] snap_ct, snap_mac, ct_before;
  logic [31:0] snap_ctr;
  logic [127:0] snap_node [NODES];
  bit ok_roots;
  int read_cycles, write_cycles;

  initial begin
    $display("== tb_memory_integrity (BLOCKS=%0d)", BLOCKS);
    do_init();
    check(root == MIT_ROOT_INIT, "initial tree root matches Python reference");
    run_script(ok_roots);
    write_cycles = last_cycles;
    check(ok_roots, "root after each scripted write matches Python reference");
    check(store.ct[2] == MIT_CT2 && store.mac[2] == MIT_MAC2,
          "stored ciphertext and data MAC of block 2 match Python reference");
    check(store.ct[2] != MIT_SCRIPT_PT[2], "untrusted storage holds ciphertext, not plaintext");
    op(1'b0, 4'd2, '0);
    read_cycles = last_cycles;
    check(last_status == 0 && last_data == MIT_SCRIPT_PT[2], "read block 2 returns latest plaintext");
    op(1'b0, 4'd5, '0);
    check(last_status == 0 && last_data == MIT_SCRIPT_PT[1], "read block 5 returns its plaintext");
    op(1'b0, 4'd15, '0);
    check(last_status == 0 && last_data == MIT_SCRIPT_PT[3], "read block 15 returns its plaintext");
    op(1'b0, 4'd0, '0);
    check(last_status == 0 && last_data == '0 && !tamper, "never-written block reads as zero");
    ct_before = store.ct[5];
    op(1'b1, 4'd5, MIT_SCRIPT_PT[1]);
    check(store.ct[5] != ct_before, "rewriting identical plaintext yields fresh ciphertext (counter)");
    op(1'b0, 4'd5, '0);
    check(last_status == 0 && last_data == MIT_SCRIPT_PT[1], "re-read after rewrite");
    $display("METRIC,read_latency_cycles,%0d", read_cycles);
    $display("METRIC,write_latency_cycles,%0d", write_cycles);

    $display("CAMPAIGN_HEADER,attack,detected,tamper_flag");

    do_init(); run_script(ok_roots);
    store.ct[5][0] = ~store.ct[5][0];
    op(1'b0, 4'd5, '0);
    campaign("ciphertext_bit_flip", last_status == 2'd1 && tamper);

    do_init(); run_script(ok_roots);
    store.mac[5][77] = ~store.mac[5][77];
    op(1'b0, 4'd5, '0);
    campaign("data_mac_bit_flip", last_status == 2'd1 && tamper);

    do_init(); run_script(ok_roots);
    store.ct[15] = store.ct[5]; store.mac[15] = store.mac[5];
    op(1'b0, 4'd15, '0);
    campaign("splice_ct_mac_from_other_block", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    store.ct[15] = store.ct[5]; store.mac[15] = store.mac[5]; store.ctr[15] = store.ctr[5];
    op(1'b0, 4'd15, '0);
    campaign("splice_ct_mac_ctr_from_other_block", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    store.ctr[2] = 32'd1;
    op(1'b0, 4'd2, '0);
    campaign("counter_rollback", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    snap_ct = store.ct[2]; snap_mac = store.mac[2]; snap_ctr = store.ctr[2];
    for (int i = 0; i < NODES; i++) snap_node[i] = store.node[i];
    op(1'b1, 4'd2, 128'h0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    store.ct[2] = snap_ct; store.mac[2] = snap_mac; store.ctr[2] = snap_ctr;
    for (int i = 0; i < NODES; i++) store.node[i] = snap_node[i];
    op(1'b0, 4'd2, '0);
    campaign("full_replay_of_old_snapshot", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    store.ctr[3] = store.ctr[3] + 32'd1;               // sibling leaf of block 2
    op(1'b0, 4'd2, '0);
    campaign("sibling_counter_tamper", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    store.node[8 + 1] = store.node[8 + 1] ^ 128'h1;    // level-2 sibling on block 2's path
    ct_before = store.ct[2];
    op(1'b1, 4'd2, 128'hfeed);
    campaign("tree_node_tamper_blocks_write", last_status == 2'd1 && store.ct[2] == ct_before);

    do_init(); run_script(ok_roots);
    store.ctr[9] = 32'd7;                               // not on block 2's path
    op(1'b0, 4'd2, '0);
    check(last_status == 2'd0, "tamper off the verified path does not affect an unrelated read");
    op(1'b0, 4'd9, '0);
    campaign("tamper_detected_on_first_use", last_status == 2'd1);

    do_init(); run_script(ok_roots);
    @(posedge clk); #1 zeroize = 1'b1; @(posedge clk); #1 zeroize = 1'b0; @(posedge clk);
    check(!req_ready && root == '0 && !tamper, "zeroize wipes root and keys, engine refuses requests");

    if (fails == 0) $display("[SV TEST PASS] tb_memory_integrity");
    else $display("[SV TEST FAIL] tb_memory_integrity (%0d failures)", fails);
    $finish;
  end

  initial begin
    #20_000_000;
    $display("[SV TEST FAIL] timeout");
    $finish;
  end
endmodule
