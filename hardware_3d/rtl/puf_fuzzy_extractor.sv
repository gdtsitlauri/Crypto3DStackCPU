// SPDX-License-Identifier: MIT
// Fuzzy-extractor key reconstruction for a PUF-derived device root (roadmap 2.4).
//
// Code-offset construction with a REP-fold repetition code, identical to
// hardware_3d/scripts/puf_fuzzy_extractor.py:
//   s'     = MajorityDecode(response XOR helper)          (128 blocks of REP bits)
//   K_root = AES-CMAC_{0^128}(s' || "VTFPUFKEYDERIVE1")
// The helper data is public (NVM); the PUF response and s' never leave the
// module, and s' is wiped as soon as the key is derived. key_o/key_valid_o
// connect to root_key_i/root_load_i of crypto3d_vtf_system_top, so the root key
// is never stored in the bitstream or in memory.
//
// The PUF itself (ring oscillators with placement constraints) is
// technology-specific and is NOT modelled here; see the Python model for the
// reliability/uniqueness study and roadmap phase 3 for board measurements.

`timescale 1ns/1ps

module puf_fuzzy_extractor #(
  parameter int REP = 11,                  // odd; corrects (REP-1)/2 errors per block
  localparam int KEY_BITS = 128,
  localparam int NB = KEY_BITS * REP
) (
  input  logic          clk,
  input  logic          rst_n,
  input  logic          start_i,           // response_i and helper_i valid
  input  logic [NB-1:0] response_i,        // noisy PUF re-read
  input  logic [NB-1:0] helper_i,          // public helper data from enrolment
  output logic          key_valid_o,       // one-cycle pulse with key_o
  output logic [127:0]  key_o,
  output logic          busy_o
);
  localparam logic [127:0] LABEL = 128'h5654_4650_5546_4B45_5944_4552_4956_4531; // "VTFPUFKEYDERIVE1"
  localparam int CW = $clog2(REP + 1);

  // majority decoding (block i = list bits i*REP .. i*REP+REP-1, MSB first)
  logic [127:0] secret_c;
  always_comb begin
    for (int i = 0; i < KEY_BITS; i++) begin
      logic [REP-1:0] blk;
      logic [CW-1:0] ones;
      blk = response_i[NB - 1 - i * REP -: REP] ^ helper_i[NB - 1 - i * REP -: REP];
      ones = '0;
      for (int k = 0; k < REP; k++) ones = ones + CW'(blk[k]);
      secret_c[KEY_BITS - 1 - i] = (int'(ones) * 2 > REP);
    end
  end

  logic         cm_start, cm_busy, cm_done;
  logic [127:0] cm_tag;
  logic [127:0] secret_q;
  logic         run_q;

  aes_cmac32 kdf_i (
    .clk(clk), .rst_n(rst_n), .start_i(cm_start), .clear_i(1'b0), .key_i(128'h0),
    .k1_valid_i(1'b0), .k1_i(128'h0), .msg_i({secret_q, LABEL}),
    .busy_o(cm_busy), .done_o(cm_done), .tag_o(cm_tag)
  );

  assign busy_o = run_q;

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      secret_q <= '0; run_q <= 1'b0; cm_start <= 1'b0; key_valid_o <= 1'b0; key_o <= '0;
    end else begin
      cm_start <= 1'b0;
      key_valid_o <= 1'b0;
      if (start_i && !run_q && !cm_busy) begin
        secret_q <= secret_c;
        cm_start <= 1'b1;
        run_q <= 1'b1;
      end else if (run_q && cm_done) begin
        key_o <= cm_tag;
        key_valid_o <= 1'b1;
        secret_q <= '0;                    // wipe the reconstructed secret
        run_q <= 1'b0;
      end
    end
  end
endmodule
