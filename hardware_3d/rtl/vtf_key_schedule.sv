// SPDX-License-Identifier: MIT
// Vertical Trust Fabric key schedule.
//
// Base domain keys (identical to src/vertical_trust_fabric.h deriveDomainKeys):
//   K_req = AES_root("VTFREQUESTK1" || 00000001)
//   K_rsp = AES_root("VTFRESPONSEK" || 00000001)
//
// Optional epoch / role hierarchy (EPOCH_KEYS = 1, roadmap item 1.3):
//   K_req[r, e] = AES_Kreq("VTFE" || e || 0x000000r || "KDF1")   one key per requester r
//   K_rsp[e]    = AES_Krsp("VTFE" || e || "RSP0"     || "KDF1")
// Advancing the epoch re-derives all keys, so every tag of an older epoch becomes
// invalid even if the epoch field check were bypassed. The same derivation is
// implemented in src/vertical_trust_fabric.h (setEpochKeyHierarchy) and in
// hardware_3d/scripts/vtf_reference.py.
//
// For every working key the CMAC subkey K1 = dbl(AES_K(0^128)) is precomputed
// once, so each transaction tag costs exactly two AES operations.
//
// zeroize_i wipes the root copy and every derived key and subkey; keys stay
// invalid (ready_o = 0) until the device root is loaded again by secure boot.

`timescale 1ns/1ps

module vtf_key_schedule #(
  parameter bit EPOCH_KEYS = 1'b1,
  parameter int REQUESTERS = 5
) (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         root_load_i,          // pulse: load root_key_i (secure boot / PUF output)
  input  logic [127:0] root_key_i,
  input  logic [31:0]  active_epoch_i,
  input  logic         zeroize_i,
  output logic         ready_o,
  output logic [127:0] req_key_o [REQUESTERS],
  output logic [127:0] req_k1_o  [REQUESTERS],
  output logic [127:0] rsp_key_o,
  output logic [127:0] rsp_k1_o
);

  localparam logic [127:0] REQ_DOMAIN = 128'h56544652_45515545_53544B31_00000001;
  localparam logic [127:0] RSP_DOMAIN = 128'h56544652_4553504F_4E53454B_00000001;
  localparam logic [31:0]  TAG_VTFE   = 32'h56544645;  // "VTFE"
  localparam logic [31:0]  TAG_KDF1   = 32'h4B444631;  // "KDF1"
  localparam logic [31:0]  TAG_RSP0   = 32'h52535030;  // "RSP0"
  localparam int           NKEYS      = REQUESTERS + 1;  // index REQUESTERS = response key

  typedef enum logic [2:0] {K_EMPTY, K_BASE_REQ, K_BASE_RSP, K_DERIVE, K_SUBKEY, K_READY} kstate_t;
  kstate_t kstate_q;

  logic [127:0] base_req_q, base_rsp_q;
  logic [127:0] key_q [NKEYS];
  logic [127:0] k1_q  [NKEYS];
  logic [31:0]  derived_epoch_q;
  logic [3:0]   idx_q;

  logic         aes_start, aes_busy, aes_done;
  logic [127:0] aes_key, aes_in, aes_out;

  aes128_core aes_i (
    .clk(clk), .rst_n(rst_n), .start_i(aes_start), .key_i(aes_key), .block_i(aes_in),
    .busy_o(aes_busy), .done_o(aes_done), .result_o(aes_out)
  );

  function automatic logic [127:0] dbl(input logic [127:0] x);
    dbl = {x[126:0], 1'b0} ^ (x[127] ? 128'h87 : 128'h0);
  endfunction

  // derivation input for key index i (only used when EPOCH_KEYS)
  function automatic logic [127:0] kdf_block(input logic [3:0] i, input logic [31:0] e);
    if (int'(i) < REQUESTERS) kdf_block = {TAG_VTFE, e, 28'd0, i, TAG_KDF1};
    else                      kdf_block = {TAG_VTFE, e, TAG_RSP0, TAG_KDF1};
  endfunction

  assign ready_o = (kstate_q == K_READY) && (!EPOCH_KEYS || derived_epoch_q == active_epoch_i);
  for (genvar r = 0; r < REQUESTERS; r++) begin : g_out
    assign req_key_o[r] = ready_o ? key_q[r] : '0;
    assign req_k1_o[r]  = ready_o ? k1_q[r]  : '0;
  end
  assign rsp_key_o = ready_o ? key_q[REQUESTERS] : '0;
  assign rsp_k1_o  = ready_o ? k1_q[REQUESTERS]  : '0;

  // start deriving working key 0 (or, without the epoch hierarchy, take it from the base keys)
  task automatic begin_derive(input logic [31:0] epoch);
    derived_epoch_q <= epoch;
    idx_q <= 4'd0;
    if (EPOCH_KEYS) begin
      aes_key   <= base_req_q;
      aes_in    <= kdf_block(4'd0, epoch);
      aes_start <= 1'b1;
      kstate_q  <= K_DERIVE;
    end
  endtask

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      kstate_q        <= K_EMPTY;
      base_req_q      <= '0;
      base_rsp_q      <= '0;
      derived_epoch_q <= '0;
      idx_q           <= '0;
      aes_start       <= 1'b0;
      aes_key         <= '0;
      aes_in          <= '0;
      for (int k = 0; k < NKEYS; k++) begin key_q[k] <= '0; k1_q[k] <= '0; end
    end else begin
      aes_start <= 1'b0;
      if (zeroize_i) begin
        kstate_q   <= K_EMPTY;
        base_req_q <= '0;
        base_rsp_q <= '0;
        aes_key    <= '0;
        aes_in     <= '0;
        for (int k = 0; k < NKEYS; k++) begin key_q[k] <= '0; k1_q[k] <= '0; end
      end else begin
        unique case (kstate_q)
          K_EMPTY: if (root_load_i && !aes_busy) begin
            aes_key   <= root_key_i;      // the root is never stored beyond this operation
            aes_in    <= REQ_DOMAIN;
            aes_start <= 1'b1;
            kstate_q  <= K_BASE_REQ;
          end
          K_BASE_REQ: if (aes_done) begin
            base_req_q <= aes_out;
            aes_in     <= RSP_DOMAIN;     // aes_key still holds the root
            aes_start  <= 1'b1;
            kstate_q   <= K_BASE_RSP;
          end
          K_BASE_RSP: if (aes_done) begin
            base_rsp_q <= aes_out;
            if (EPOCH_KEYS) begin
              derived_epoch_q <= active_epoch_i;
              idx_q     <= 4'd0;
              aes_key   <= base_req_q;
              aes_in    <= kdf_block(4'd0, active_epoch_i);
              aes_start <= 1'b1;
              kstate_q  <= K_DERIVE;
            end else begin
              for (int r = 0; r < REQUESTERS; r++) key_q[r] <= base_req_q;
              key_q[REQUESTERS] <= aes_out;
              derived_epoch_q   <= active_epoch_i;
              // subkeys: base request key (shared by all requesters), then response key
              idx_q     <= 4'd0;
              aes_key   <= base_req_q;
              aes_in    <= '0;
              aes_start <= 1'b1;
              kstate_q  <= K_SUBKEY;
            end
          end
          K_DERIVE: if (aes_done) begin
            key_q[idx_q[2:0]] <= aes_out;
            aes_key      <= aes_out;      // L = AES_K(0) for this working key
            aes_in       <= '0;
            aes_start    <= 1'b1;
            kstate_q     <= K_SUBKEY;
          end
          K_SUBKEY: if (aes_done) begin
            if (EPOCH_KEYS) begin
              k1_q[idx_q[2:0]] <= dbl(aes_out);
              if (int'(idx_q) == REQUESTERS) begin
                kstate_q <= K_READY;
              end else begin
                idx_q     <= idx_q + 4'd1;
                aes_key   <= (int'(idx_q) + 1 < REQUESTERS) ? base_req_q : base_rsp_q;
                aes_in    <= kdf_block(idx_q + 4'd1, derived_epoch_q);
                aes_start <= 1'b1;
                kstate_q  <= K_DERIVE;
              end
            end else begin
              if (idx_q == 4'd0) begin
                for (int r = 0; r < REQUESTERS; r++) k1_q[r] <= dbl(aes_out);
                idx_q     <= 4'd1;
                aes_key   <= base_rsp_q;
                aes_in    <= '0;
                aes_start <= 1'b1;
              end else begin
                k1_q[REQUESTERS] <= dbl(aes_out);
                kstate_q <= K_READY;
              end
            end
          end
          K_READY: if (EPOCH_KEYS && active_epoch_i != derived_epoch_q && !aes_busy) begin
            // epoch advanced: old keys are dropped before any new tag is checked
            for (int k = 0; k < NKEYS; k++) begin key_q[k] <= '0; k1_q[k] <= '0; end
            begin_derive(active_epoch_i);
          end
          default: kstate_q <= K_EMPTY;
        endcase
      end
    end
  end

endmodule
