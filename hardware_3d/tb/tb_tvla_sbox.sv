// SPDX-License-Identifier: MIT
// Masked AES S-box (roadmap 2.2): functional check + simulated TVLA traces.
//
// 1. Functional: all 256 inputs x 8 random maskings equal an independent
//    reference S-box (brute-force GF(2^8) inverse + affine map).
// 2. Simulated TVLA (fixed-vs-random, randomly interleaved): for every trace the
//    leakage sample at cycle k is the Hamming weight of ALL pipeline registers
//    (register-value / precharge leakage model). The same is recorded for an
//    unmasked reference pipeline (input register -> S-box -> output register).
//    Rows "T,class,m0..m9,u0..u9" are analysed by scripts/tvla.py (Welch t-test,
//    first and second order). This is a simulation model: no glitches, no
//    coupling, no measurement noise.

`timescale 1ns/1ps

module tb_tvla_sbox #(parameter int TRACES = 20000, parameter int SEED = 7);
  logic clk = 1'b0;
  always #5 clk = ~clk;
  logic rst_n = 1'b0;

  logic valid, valid_o;
  logic [7:0] x0, x1, y0, y1;
  logic [63:0] rnd;

  aes_sbox_masked dut (.clk(clk), .rst_n(rst_n), .valid_i(valid), .x0_i(x0), .x1_i(x1), .rnd_i(rnd),
                       .valid_o(valid_o), .y0_o(y0), .y1_o(y1));

  // ---------------- independent reference ----------------
  function automatic logic [7:0] g_mul(input logic [7:0] a, input logic [7:0] b);
    logic [7:0] p = 0;
    for (int i = 0; i < 8; i++) begin
      if (b[i]) p ^= a;
      a = {a[6:0], 1'b0} ^ (a[7] ? 8'h1B : 8'h00);
    end
    return p;
  endfunction

  function automatic logic [7:0] ref_sbox(input logic [7:0] x);
    logic [7:0] inv = 0, s;
    if (x != 0)
      for (int y = 1; y < 256; y++) if (g_mul(x, 8'(y)) == 8'h01) inv = 8'(y);
    for (int i = 0; i < 8; i++)
      s[i] = inv[i] ^ inv[(i + 4) % 8] ^ inv[(i + 5) % 8] ^ inv[(i + 6) % 8] ^ inv[(i + 7) % 8];
    return s ^ 8'h63;
  endfunction

  logic [7:0] sbox_tab [256];

  // ---------------- unmasked reference pipeline ----------------
  logic [7:0] u_in_q = 0, u_out_q = 0, u_x;
  always_ff @(posedge clk) begin
    u_in_q <= u_x;
    u_out_q <= sbox_tab[u_in_q];
  end

  int seed = SEED;
  function automatic logic [7:0] rb();   return 8'($random(seed)); endfunction
  function automatic logic [63:0] r64(); return {32'($random(seed)), 32'($random(seed))}; endfunction

  function automatic int leak_masked();
    return $countones({dut.s1_x0, dut.s1_x1, dut.s1_z0, dut.s1_z1,
                       dut.s2_p00, dut.s2_p11, dut.s2_c01, dut.s2_c10, dut.s2_z0, dut.s2_z1,
                       dut.s3_y0, dut.s3_y1, dut.s3_w0, dut.s3_w1, dut.s3_z0, dut.s3_z1,
                       dut.s4_p00, dut.s4_p11, dut.s4_c01, dut.s4_c10, dut.s4_w0, dut.s4_w1, dut.s4_z0, dut.s4_z1,
                       dut.s5_y0, dut.s5_y1, dut.s5_w0, dut.s5_w1, dut.s5_z0, dut.s5_z1,
                       dut.s6_p00, dut.s6_p11, dut.s6_c01, dut.s6_c10, dut.s6_z0, dut.s6_z1,
                       dut.s7_y0, dut.s7_y1, dut.s7_z0, dut.s7_z1,
                       dut.s8_p00, dut.s8_p11, dut.s8_c01, dut.s8_c10, dut.s9_y0, dut.s9_y1});
  endfunction

  localparam logic [7:0] FIXED = 8'h3C;
  int fails = 0;
  int m [10], u [10];
  string line;

  initial begin
    logic [7:0] x, mask;
    bit cls;
    for (int i = 0; i < 256; i++) sbox_tab[i] = ref_sbox(8'(i));
    if (sbox_tab[0] != 8'h63 || sbox_tab[8'h53] != 8'hED) begin
      $display("[FAIL] reference S-box self-check"); fails++;
    end
    valid = 0; x0 = 0; x1 = 0; rnd = 0; u_x = 0;
    repeat (3) @(negedge clk);
    rst_n = 1'b1;

    // ---- functional: every input, 8 maskings, pipelined back-to-back ----
    fork
      begin
        for (int i = 0; i < 256 * 8; i++) begin
          @(negedge clk);
          mask = rb();
          valid = 1'b1; x0 = mask; x1 = 8'(i % 256) ^ mask; rnd = r64();
        end
        @(negedge clk); valid = 1'b0; x0 = 0; x1 = 0;
      end
      begin
        int n;
        n = 0;
        while (n < 256 * 8) begin
          @(negedge clk);
          if (valid_o) begin
            if ((y0 ^ y1) != sbox_tab[n % 256]) begin
              if (fails < 5) $display("[FAIL] x=%02h got %02h exp %02h", n % 256, y0 ^ y1, sbox_tab[n % 256]);
              fails++;
            end
            n++;
          end
        end
      end
    join
    if (fails == 0) $display("[PASS] masked S-box equals reference for all 256 inputs x 8 maskings");

    // ---- simulated TVLA traces ----
    $display("TVLA_HEADER,class,m0..m9,u0..u9");
    repeat (12) @(negedge clk);
    for (int t = 0; t < TRACES; t++) begin
      cls = $random(seed) & 1;
      x = cls ? rb() : FIXED;
      mask = rb();
      @(negedge clk);
      valid = 1'b1; x0 = mask; x1 = x ^ mask; rnd = r64(); u_x = x;
      for (int k = 0; k < 10; k++) begin
        @(posedge clk); #1;
        m[k] = leak_masked();
        u[k] = $countones({u_in_q, u_out_q});
        @(negedge clk);
        valid = 1'b0; x0 = 8'h00; x1 = 8'h00; rnd = r64(); u_x = 8'h00;
      end
      $display("T,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d,%0d",
               cls ? 1 : 0, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9],
               u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9]);
    end
    if (fails == 0) $display("[SV TEST PASS] tb_tvla_sbox");
    else $display("[SV TEST FAIL] tb_tvla_sbox (%0d)", fails);
    $finish;
  end
endmodule
