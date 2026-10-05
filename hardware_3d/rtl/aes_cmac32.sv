// SPDX-License-Identifier: MIT
// AES-CMAC (NIST SP 800-38B) over exactly 32-byte messages, matching the
// Vertical Trust Fabric transaction format (src/vertical_trust_fabric.h,
// src/vtf_hls.cpp).
//
// A 32-byte message is two complete blocks, so tag = AES_K(AES_K(M1) ^ M2 ^ K1)
// with K1 derived from L = AES_K(0^128). K1 can be supplied precomputed (k1_valid_i,
// as vtf_key_schedule does for every working key); otherwise it is cached per key.
// A tag costs two AES operations (~25 cycles) with a known K1, three otherwise.
// clear_i (key-tier zeroize) wipes the cached subkey.

`timescale 1ns/1ps

module aes_cmac32 (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         start_i,
  input  logic         clear_i,
  input  logic [127:0] key_i,
  input  logic         k1_valid_i,  // k1_i is the precomputed subkey K1 of key_i
  input  logic [127:0] k1_i,
  input  logic [255:0] msg_i,     // byte 0 = bits [255:248]
  output logic         busy_o,
  output logic         done_o,    // one-cycle pulse
  output logic [127:0] tag_o
);

  typedef enum logic [1:0] {S_IDLE, S_L, S_M1, S_LAST} state_t;
  state_t state_q;

  logic         aes_start, aes_busy, aes_done;
  logic [127:0] aes_key, aes_in, aes_out;

  logic [127:0] key_q, m2_q, k1_q, cached_key_q;
  logic         cached_valid_q;

  aes128_core aes_i (
    .clk(clk), .rst_n(rst_n), .start_i(aes_start), .key_i(aes_key), .block_i(aes_in),
    .busy_o(aes_busy), .done_o(aes_done), .result_o(aes_out)
  );

  function automatic logic [127:0] dbl(input logic [127:0] x);
    dbl = {x[126:0], 1'b0} ^ (x[127] ? 128'h87 : 128'h0);
  endfunction

  assign aes_key = key_q;
  assign busy_o  = (state_q != S_IDLE) || aes_busy;

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_q        <= S_IDLE;
      aes_start      <= 1'b0;
      aes_in         <= '0;
      key_q          <= '0;
      m2_q           <= '0;
      k1_q           <= '0;
      cached_key_q   <= '0;
      cached_valid_q <= 1'b0;
      done_o         <= 1'b0;
      tag_o          <= '0;
    end else begin
      aes_start <= 1'b0;
      done_o    <= 1'b0;
      if (clear_i) begin
        cached_valid_q <= 1'b0;
        cached_key_q   <= '0;
        k1_q           <= '0;
      end
      unique case (state_q)
        S_IDLE: begin
          if (start_i && !clear_i && !aes_busy) begin
            key_q <= key_i;
            m2_q  <= msg_i[127:0];
            if (k1_valid_i || (cached_valid_q && cached_key_q == key_i)) begin
              aes_in    <= msg_i[255:128];
              aes_start <= 1'b1;
              state_q   <= S_M1;
            end else begin
              aes_in    <= '0;
              aes_start <= 1'b1;
              state_q   <= S_L;
            end
            // stash M1 for the cache-miss path
            k1_q <= k1_valid_i ? k1_i
                  : (cached_valid_q && cached_key_q == key_i) ? k1_q : msg_i[255:128];
          end
        end
        S_L: if (aes_done) begin
          // k1_q temporarily holds M1 on this path
          aes_in         <= k1_q;
          k1_q           <= dbl(aes_out);
          cached_key_q   <= key_q;
          cached_valid_q <= 1'b1;
          aes_start      <= 1'b1;
          state_q        <= S_M1;
        end
        S_M1: if (aes_done) begin
          aes_in    <= aes_out ^ m2_q ^ k1_q;
          aes_start <= 1'b1;
          state_q   <= S_LAST;
        end
        S_LAST: if (aes_done) begin
          tag_o   <= aes_out;
          done_o  <= 1'b1;
          m2_q    <= '0;
          state_q <= S_IDLE;
        end
        default: state_q <= S_IDLE;
      endcase
      if (clear_i && state_q != S_IDLE) begin
        // abort an in-flight computation on zeroize
        state_q <= S_IDLE;
        m2_q    <= '0;
        key_q   <= '0;
      end
    end
  end

endmodule
