// SPDX-License-Identifier: MIT
// Known-answer tests for aes128_core and aes_cmac32.
//  * FIPS-197 Appendix C.1 AES-128 vector
//  * the three AES-CMAC vectors of src/vtf_hls_tb.cpp (32-byte messages; reference
//    values from the Python `cryptography` package, checked against SP 800-38B)
//  * subkey-cache behaviour (same key twice, then a new key, then zeroize)
//  * single-bit message/key changes must change the tag
// Prints [SV TEST PASS] on success.

`timescale 1ns/1ps

module tb_aes_cmac32;
  logic clk = 1'b0;
  logic rst_n = 1'b0;
  always #5 clk = ~clk;

  // ---------------- AES core ----------------
  logic         a_start = 1'b0;
  logic [127:0] a_key, a_block, a_out;
  logic         a_busy, a_done;
  aes128_core aes_i (.clk(clk), .rst_n(rst_n), .start_i(a_start), .key_i(a_key), .block_i(a_block),
                     .busy_o(a_busy), .done_o(a_done), .result_o(a_out));

  // ---------------- CMAC ----------------
  logic         c_start = 1'b0, c_clear = 1'b0;
  logic [127:0] c_key, c_tag;
  logic [255:0] c_msg;
  logic         c_busy, c_done;
  aes_cmac32 cmac_i (.clk(clk), .rst_n(rst_n), .start_i(c_start), .clear_i(c_clear), .key_i(c_key), .k1_valid_i(1'b0), .k1_i(128'h0),
                     .msg_i(c_msg), .busy_o(c_busy), .done_o(c_done), .tag_o(c_tag));

  int failures = 0;
  int cycles;

  task automatic run_aes(input logic [127:0] key, input logic [127:0] blk, output logic [127:0] out, output int n);
    @(negedge clk); a_key = key; a_block = blk; a_start = 1'b1;
    @(negedge clk); a_start = 1'b0;
    n = 1;
    while (!a_done) begin @(negedge clk); n++; end
    out = a_out;
  endtask

  task automatic run_cmac(input logic [127:0] key, input logic [255:0] msg, output logic [127:0] tag, output int n);
    @(negedge clk);
    while (c_busy) @(negedge clk);
    c_key = key; c_msg = msg; c_start = 1'b1;
    @(negedge clk); c_start = 1'b0;
    n = 1;
    while (!c_done) begin @(negedge clk); n++; end
    tag = c_tag;
  endtask

  task automatic check(input string name, input logic [127:0] got, input logic [127:0] exp);
    if (got !== exp) begin
      $display("[FAIL] %s got=%032h exp=%032h", name, got, exp);
      failures++;
    end else begin
      $display("[PASS] %s %032h", name, got);
    end
  endtask

  logic [127:0] r, r2;
  int n1, n2;

  initial begin
    repeat (3) @(negedge clk);
    rst_n = 1'b1;

    // FIPS-197 Appendix C.1
    run_aes(128'h000102030405060708090a0b0c0d0e0f, 128'h00112233445566778899aabbccddeeff, r, cycles);
    check("aes_fips197_c1", r, 128'h69c4e0d86a7b0430d8cdb78070b4c55a);
    $display("METRIC,aes_cycles,%0d", cycles);
    // FIPS-197 Appendix B (key 2b7e..., input 3243f6a8...)
    run_aes(128'h2b7e151628aed2a6abf7158809cf4f3c, 128'h3243f6a8885a308d313198a2e0370734, r, cycles);
    check("aes_fips197_b", r, 128'h3925841d02dc09fbdc118597196a0b32);

    // vtf_hls_tb.cpp vectors (cold cache, then warm cache)
    run_cmac(128'h2b7e151628aed2a6abf7158809cf4f3c,
             256'h6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51, r, n1);
    check("cmac_nist_key_nist_msg32", r, 128'hce0cbf1738f4df6428b1d93bf12081c9);
    run_cmac(128'h2b7e151628aed2a6abf7158809cf4f3c,
             256'h6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51, r2, n2);
    check("cmac_cached_subkey_same_tag", r2, 128'hce0cbf1738f4df6428b1d93bf12081c9);
    $display("METRIC,cmac_cycles_cold,%0d", n1);
    $display("METRIC,cmac_cycles_warm,%0d", n2);
    if (!(n2 < n1)) begin $display("[FAIL] subkey cache did not shorten latency"); failures++; end

    run_cmac(128'h0, 256'h0, r, n1);
    check("cmac_zero_key_zero_msg", r, 128'h3437d43a23ac3ce2025ceaf9c237ab53);
    run_cmac(128'h000102030405060708090a0b0c0d0e0f,
             256'h00000001_00000002_c3d00005_00000001_00000007_00000009_deadbeef_a5a5a5a5, r, n1);
    check("cmac_vtf_transaction", r, 128'h9b44fbf8f1137357e8e1c6b6d384a8ba);

    // single-bit changes must change the tag
    for (int bit_i = 0; bit_i < 256; bit_i += 37) begin
      logic [255:0] m;
      m = 256'h00000001_00000002_c3d00005_00000001_00000007_00000009_deadbeef_a5a5a5a5;
      m[bit_i] = ~m[bit_i];
      run_cmac(128'h000102030405060708090a0b0c0d0e0f, m, r2, n1);
      if (r2 == r) begin $display("[FAIL] msg bit %0d not detected", bit_i); failures++; end
    end
    for (int bit_i = 0; bit_i < 128; bit_i += 29) begin
      logic [127:0] k;
      k = 128'h000102030405060708090a0b0c0d0e0f;
      k[bit_i] = ~k[bit_i];
      run_cmac(k, 256'h00000001_00000002_c3d00005_00000001_00000007_00000009_deadbeef_a5a5a5a5, r2, n1);
      if (r2 == r) begin $display("[FAIL] key bit %0d not detected", bit_i); failures++; end
    end

    // zeroize clears the subkey cache: next tag is a cold computation but still correct
    @(negedge clk); c_clear = 1'b1; @(negedge clk); c_clear = 1'b0;
    run_cmac(128'h000102030405060708090a0b0c0d0e0f,
             256'h00000001_00000002_c3d00005_00000001_00000007_00000009_deadbeef_a5a5a5a5, r2, n2);
    check("cmac_after_zeroize", r2, 128'h9b44fbf8f1137357e8e1c6b6d384a8ba);
    if (n2 != n1 && n2 < 30) begin $display("[FAIL] zeroize did not clear subkey cache"); failures++; end

    if (failures == 0) $display("[SV TEST PASS] tb_aes_cmac32");
    else               $display("[SV TEST FAIL] tb_aes_cmac32 failures=%0d", failures);
    $finish;
  end
endmodule
