// SPDX-License-Identifier: MIT
// PUF fuzzy extractor (roadmap 2.4): a noisy hot re-read (85 C) reconstructs
// the enrolled key; another device's response does not; the secret is wiped.
// Vectors: hardware_3d/scripts/puf_fuzzy_extractor.py --emit-sv tb/puf_vectors.svh

`timescale 1ns/1ps

module tb_puf_fuzzy_extractor;
  `include "puf_vectors.svh"
  localparam int NB = 128 * PUF_REP;

  logic clk = 1'b0;
  always #5 clk = ~clk;
  logic rst_n = 1'b0, start = 1'b0, key_valid, busy;
  logic [NB-1:0] resp;
  logic [127:0] key;
  int fails = 0;

  puf_fuzzy_extractor #(.REP(PUF_REP)) dut (
    .clk(clk), .rst_n(rst_n), .start_i(start), .response_i(resp), .helper_i(PUF_HELPER),
    .key_valid_o(key_valid), .key_o(key), .busy_o(busy)
  );

  task automatic derive(input logic [NB-1:0] r, output logic [127:0] k);
    @(negedge clk); resp = r; start = 1'b1;
    @(negedge clk); start = 1'b0;
    while (!key_valid) @(negedge clk);
    k = key;
  endtask

  initial begin
    logic [127:0] k;
    resp = '0;
    repeat (3) @(negedge clk);
    rst_n = 1'b1;
    derive(PUF_NOISY, k);
    if (k === PUF_KEY) $display("[PASS] noisy 85C re-read reconstructs the enrolled root key");
    else begin $display("[FAIL] key %h exp %h", k, PUF_KEY); fails++; end
    @(negedge clk);
    if (dut.secret_q === '0) $display("[PASS] reconstructed secret wiped after key derivation");
    else begin $display("[FAIL] secret not wiped"); fails++; end
    derive(PUF_OTHER, k);
    if (k === PUF_KEY_OTHER && k !== PUF_KEY) $display("[PASS] another device's PUF does not yield the key");
    else begin $display("[FAIL] other-device key %h", k); fails++; end
    if (fails == 0) $display("[SV TEST PASS] tb_puf_fuzzy_extractor");
    else $display("[SV TEST FAIL] tb_puf_fuzzy_extractor");
    $finish;
  end
endmodule
