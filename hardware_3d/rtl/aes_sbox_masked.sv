// SPDX-License-Identifier: MIT
// First-order masked AES S-box (roadmap 2.2): 2 Boolean shares, Domain-Oriented
// Masking (DOM-indep) GF(2^8) multipliers, inversion as x^254 by the
// Rivain-Prouff chain, every multiplication operand pair separated by a fresh
// mask refresh (avoids the known RP dependent-operand flaw), affine map applied
// share-wise. Fully pipelined: one S-box per cycle, latency 9 cycles,
// 64 fresh random bits per S-box (r_i = 8 x 8 bits).
//
//   x^2 -(refresh)-> x^3 = x * x^2
//   x^12 = (x^3)^4 -(refresh)-> x^15 = x^3 * x^12
//   x^240 = (x^15)^16 -(refresh)-> x^252 = x^240 * x^12
//   x^2 -(refresh)-> x^254 = x^252 * x^2,  S(x) = A(x^254) ^ 0x63
//
// Security claim (simulated, see tb/tb_tvla_sbox.sv + scripts/tvla.py): no
// first-order leakage in a register-value (Hamming weight) model. Glitches,
// coupling and higher-order leakage are NOT covered; real evidence requires a
// board-level TVLA (roadmap phase 3). Verification with maskVerif/SILVER is
// future work.

`timescale 1ns/1ps

module aes_sbox_masked (
  input  logic        clk,
  input  logic        rst_n,
  input  logic        valid_i,
  input  logic [7:0]  x0_i,          // share 0
  input  logic [7:0]  x1_i,          // share 1   (x = x0 ^ x1)
  input  logic [63:0] rnd_i,         // fresh randomness, every cycle
  output logic        valid_o,
  output logic [7:0]  y0_o,
  output logic [7:0]  y1_o           // S(x) = y0 ^ y1
);
  function automatic logic [7:0] xt(input logic [7:0] a);
    xt = {a[6:0], 1'b0} ^ (a[7] ? 8'h1B : 8'h00);
  endfunction

  function automatic logic [7:0] gmul(input logic [7:0] a, input logic [7:0] b);
    logic [7:0] p, aa;
    p = 8'h00; aa = a;
    for (int i = 0; i < 8; i++) begin
      if (b[i]) p ^= aa;
      aa = xt(aa);
    end
    gmul = p;
  endfunction

  function automatic logic [7:0] sq(input logic [7:0] a);    // linear over GF(2)
    sq = gmul(a, a);
  endfunction

  function automatic logic [7:0] pow4(input logic [7:0] a);  pow4 = sq(sq(a)); endfunction
  function automatic logic [7:0] pow16(input logic [7:0] a); pow16 = sq(sq(sq(sq(a)))); endfunction

  function automatic logic [7:0] affine_lin(input logic [7:0] b);  // linear part of the AES affine map
    for (int i = 0; i < 8; i++)
      affine_lin[i] = b[i] ^ b[(i + 4) % 8] ^ b[(i + 5) % 8] ^ b[(i + 6) % 8] ^ b[(i + 7) % 8];
  endfunction

  wire [7:0] r1 = rnd_i[7:0],   r2 = rnd_i[15:8],  r3 = rnd_i[23:16], r4 = rnd_i[31:24];
  wire [7:0] r5 = rnd_i[39:32], r6 = rnd_i[47:40], r7 = rnd_i[55:48], r8 = rnd_i[63:56];

  // ---- pipeline registers (all security-relevant state is here) ----
  logic [8:0] v_q;                                  // valid shift register
  logic [7:0] s1_x0, s1_x1, s1_z0, s1_z1;           // x, refreshed x^2
  logic [7:0] s2_p00, s2_p11, s2_c01, s2_c10, s2_z0, s2_z1;   // x*x^2 terms, x^2
  logic [7:0] s3_y0, s3_y1, s3_w0, s3_w1, s3_z0, s3_z1;       // x^3, refreshed x^12, x^2
  logic [7:0] s4_p00, s4_p11, s4_c01, s4_c10, s4_w0, s4_w1, s4_z0, s4_z1;
  logic [7:0] s5_y0, s5_y1, s5_w0, s5_w1, s5_z0, s5_z1;       // refreshed x^240, x^12, x^2
  logic [7:0] s6_p00, s6_p11, s6_c01, s6_c10, s6_z0, s6_z1;
  logic [7:0] s7_y0, s7_y1, s7_z0, s7_z1;                     // x^252, refreshed x^2
  logic [7:0] s8_p00, s8_p11, s8_c01, s8_c10;
  logic [7:0] s9_y0, s9_y1;                                   // S-box output shares

  // DOM: inner-domain products and cross-domain products blinded by fresh r, all registered.
  always_ff @(posedge clk) begin
    if (!rst_n) begin
      v_q <= '0;
      {s1_x0, s1_x1, s1_z0, s1_z1} <= '0;
      {s2_p00, s2_p11, s2_c01, s2_c10, s2_z0, s2_z1} <= '0;
      {s3_y0, s3_y1, s3_w0, s3_w1, s3_z0, s3_z1} <= '0;
      {s4_p00, s4_p11, s4_c01, s4_c10, s4_w0, s4_w1, s4_z0, s4_z1} <= '0;
      {s5_y0, s5_y1, s5_w0, s5_w1, s5_z0, s5_z1} <= '0;
      {s6_p00, s6_p11, s6_c01, s6_c10, s6_z0, s6_z1} <= '0;
      {s7_y0, s7_y1, s7_z0, s7_z1} <= '0;
      {s8_p00, s8_p11, s8_c01, s8_c10} <= '0;
      {s9_y0, s9_y1} <= '0;
    end else begin
      v_q <= {v_q[7:0], valid_i};
      // stage 1: x^2 share-wise + refresh
      s1_x0 <= x0_i;              s1_x1 <= x1_i;
      s1_z0 <= sq(x0_i) ^ r1;     s1_z1 <= sq(x1_i) ^ r1;
      // stage 2: DOM multiply x * x^2
      s2_p00 <= gmul(s1_x0, s1_z0);        s2_p11 <= gmul(s1_x1, s1_z1);
      s2_c01 <= gmul(s1_x0, s1_z1) ^ r2;   s2_c10 <= gmul(s1_x1, s1_z0) ^ r2;
      s2_z0 <= s1_z0;                      s2_z1 <= s1_z1;
      // stage 3: compress -> x^3; x^12 = (x^3)^4 refreshed
      s3_y0 <= s2_p00 ^ s2_c01;            s3_y1 <= s2_p11 ^ s2_c10;
      s3_w0 <= pow4(s2_p00 ^ s2_c01) ^ r3; s3_w1 <= pow4(s2_p11 ^ s2_c10) ^ r3;
      s3_z0 <= s2_z0;                      s3_z1 <= s2_z1;
      // stage 4: DOM multiply x^3 * x^12
      s4_p00 <= gmul(s3_y0, s3_w0);        s4_p11 <= gmul(s3_y1, s3_w1);
      s4_c01 <= gmul(s3_y0, s3_w1) ^ r4;   s4_c10 <= gmul(s3_y1, s3_w0) ^ r4;
      s4_w0 <= s3_w0;                      s4_w1 <= s3_w1;
      s4_z0 <= s3_z0;                      s4_z1 <= s3_z1;
      // stage 5: x^15 -> x^240 refreshed
      s5_y0 <= pow16(s4_p00 ^ s4_c01) ^ r5; s5_y1 <= pow16(s4_p11 ^ s4_c10) ^ r5;
      s5_w0 <= s4_w0;                      s5_w1 <= s4_w1;
      s5_z0 <= s4_z0;                      s5_z1 <= s4_z1;
      // stage 6: DOM multiply x^240 * x^12
      s6_p00 <= gmul(s5_y0, s5_w0);        s6_p11 <= gmul(s5_y1, s5_w1);
      s6_c01 <= gmul(s5_y0, s5_w1) ^ r6;   s6_c10 <= gmul(s5_y1, s5_w0) ^ r6;
      s6_z0 <= s5_z0;                      s6_z1 <= s5_z1;
      // stage 7: x^252; x^2 refreshed again
      s7_y0 <= s6_p00 ^ s6_c01;            s7_y1 <= s6_p11 ^ s6_c10;
      s7_z0 <= s6_z0 ^ r7;                 s7_z1 <= s6_z1 ^ r7;
      // stage 8: DOM multiply x^252 * x^2
      s8_p00 <= gmul(s7_y0, s7_z0);        s8_p11 <= gmul(s7_y1, s7_z1);
      s8_c01 <= gmul(s7_y0, s7_z1) ^ r8;   s8_c10 <= gmul(s7_y1, s7_z0) ^ r8;
      // stage 9: x^254, affine share-wise (constant only on share 0)
      s9_y0 <= affine_lin(s8_p00 ^ s8_c01) ^ 8'h63;
      s9_y1 <= affine_lin(s8_p11 ^ s8_c10);
    end
  end

  assign valid_o = v_q[8];
  assign y0_o = s9_y0;
  assign y1_o = s9_y1;
endmodule
