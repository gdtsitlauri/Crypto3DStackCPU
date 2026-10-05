// SPDX-License-Identifier: MIT
// Memory encryption + integrity tree engine (roadmap 2.1).
//
// Protects data AT REST in untrusted storage (mit_untrusted_store), not only
// vertical transfers. Bonsai-style construction, identical to the independent
// reference hardware_3d/scripts/mem_integrity_reference.py:
//
//   keystream = AES_{K_enc}(blk || ctr || "CTRK" || "VTF3")       (AES-CTR, ctr bumps per write)
//   ct        = pt ^ keystream
//   mac       = CMAC_{K_mac}(ct || blk || ctr || "DMAC" || "VTF3") (binds address: anti-splicing)
//   leaf      = ctr || blk || "CTR0" || "LEAF"
//   node      = CMAC_{K_tree}(left || right)                       (tree over counters)
//   root      : ON-CHIP register only (anti-replay / anti-rollback)
//
// Read : verify counter path -> verify data MAC -> decrypt.
// Write: verify old path (siblings cached on chip, no TOCTOU) -> encrypt with
//        ctr+1 -> MAC -> recompute path from cached siblings -> commit nodes + root.
// The keystream AES runs in parallel with the path verification.
//
// Status: 0 OK, 1 TAMPER (sticky tamper_o, should feed the guard's
// physical_fault_i), 2 COUNTER EXHAUSTED (re-key needed). zeroize_i wipes keys,
// subkeys and root; init_i (re)loads keys and builds a fresh tree.

`timescale 1ns/1ps

module memory_integrity_tree #(
  parameter int BLOCKS = 16,                 // power of two, >= 4
  localparam int BW = $clog2(BLOCKS),
  localparam int NODES = BLOCKS - 2          // stored nodes (root kept on chip)
) (
  input  logic          clk,
  input  logic          rst_n,
  input  logic          init_i,
  input  logic          zeroize_i,
  input  logic [127:0]  key_enc_i,
  input  logic [127:0]  key_mac_i,
  input  logic [127:0]  key_tree_i,

  input  logic          req_valid_i,
  output logic          req_ready_o,
  input  logic          req_write_i,
  input  logic [BW-1:0] req_blk_i,
  input  logic [127:0]  req_wdata_i,

  output logic          rsp_valid_o,       // one-cycle pulse
  output logic [1:0]    rsp_status_o,
  output logic [127:0]  rsp_rdata_o,
  output logic          tamper_o,          // sticky until init/reset
  output logic [127:0]  root_o,            // for verification only

  // ---- untrusted storage port (mit_untrusted_store) ----
  output logic [BW-1:0] st_blk_o,
  output logic [BW-1:0] st_sib_o,
  input  logic [127:0]  st_ct_i,
  input  logic [127:0]  st_mac_i,
  input  logic [31:0]   st_ctr_i,
  input  logic [31:0]   st_sib_ctr_i,
  output logic [$clog2(NODES)-1:0] st_node_a_o,
  output logic [$clog2(NODES)-1:0] st_node_b_o,
  input  logic [127:0]  st_node_a_i,
  input  logic [127:0]  st_node_b_i,
  output logic          st_clear_o,
  output logic          st_data_we_o,
  output logic [127:0]  st_ct_o,
  output logic [127:0]  st_mac_o,
  output logic [31:0]   st_ctr_o,
  output logic          st_node_we_o,
  output logic [$clog2(NODES)-1:0] st_node_waddr_o,
  output logic [127:0]  st_node_wdata_o
);
  localparam int D = BW;
  localparam int NW = $clog2(NODES);
  localparam int LW = $clog2(D);          // index into per-level arrays (D entries)
  localparam logic [31:0] C_CTR0 = 32'h43545230;
  localparam logic [31:0] C_LEAF = 32'h4C454146;
  localparam logic [31:0] C_DMAC = 32'h444D4143;
  localparam logic [31:0] C_VTF3 = 32'h56544633;
  localparam logic [31:0] C_CTRK = 32'h4354524B;
  localparam logic [1:0]  ST_OK = 2'd0, ST_TAMPER = 2'd1, ST_EXHAUSTED = 2'd2;

  typedef enum logic [3:0] {
    S_EMPTY, S_K1T, S_K1M, S_BUILD, S_BUILD_W, S_IDLE,
    S_PATH, S_PATH_W, S_DMAC, S_DMAC_W, S_COMMIT, S_RESP
  } state_t;
  state_t state_q;

  // ---------------- crypto engines ----------------
  logic         cm_start, cm_busy, cm_done;
  logic [127:0] cm_key, cm_k1, cm_tag;
  logic [255:0] cm_msg;
  aes_cmac32 cmac_i (
    .clk(clk), .rst_n(rst_n), .start_i(cm_start), .clear_i(zeroize_i), .key_i(cm_key),
    .k1_valid_i(1'b1), .k1_i(cm_k1), .msg_i(cm_msg),
    .busy_o(cm_busy), .done_o(cm_done), .tag_o(cm_tag)
  );

  logic         aes_start, aes_busy, aes_done;
  logic [127:0] aes_key, aes_in, aes_out;
  aes128_core aes_i (
    .clk(clk), .rst_n(rst_n), .start_i(aes_start), .key_i(aes_key), .block_i(aes_in),
    .busy_o(aes_busy), .done_o(aes_done), .result_o(aes_out)
  );

  // ---------------- trusted state ----------------
  logic [127:0] k_enc_q, k_mac_q, k_tree_q, k1_tree_q, k1_mac_q, root_q;
  logic         tamper_q;
  logic         op_write_q;
  logic [BW-1:0] blk_q;
  logic [127:0] wdata_q, ct_q, mac_q, ks_q, h_q, new_ct_q, new_mac_q;
  logic [31:0]  ctr_q;          // counter used for the current pass
  logic [31:0]  old_ctr_q;
  logic         pass2_q;        // 0 = verify old path, 1 = recompute new path
  logic         ks_valid_q;
  logic [BW-1:0] idx_q;
  logic [$clog2(D+1)-1:0] lvl_q;
  logic [127:0] sib_q [D];
  logic [127:0] newnode_q [D];
  logic [BW-1:0] bj_q;          // build: node index inside level
  logic [1:0]   rsp_status_q;
  logic [127:0] rsp_rdata_q;

  function automatic logic [127:0] dbl(input logic [127:0] l);
    dbl = {l[126:0], 1'b0} ^ (l[127] ? 128'h87 : 128'h0);
  endfunction

  function automatic logic [127:0] leaf(input logic [BW-1:0] i, input logic [31:0] c);
    leaf = {c, 32'(i), C_CTR0, C_LEAF};
  endfunction

  // offset of level l (>=1) in the stored node array
  function automatic logic [NW-1:0] off(input int l);
    off = (l < 1) ? '0 : NW'(BLOCKS - (BLOCKS >> (l - 1)));
  endfunction

  // ---------------- storage addressing (combinational reads) ----------------
  always_comb begin
    // While idle, address the incoming request so its counter/ct/mac are latched
    // in the accept cycle (and the keystream uses that same counter).
    st_blk_o    = (state_q == S_IDLE) ? req_blk_i : blk_q;
    st_sib_o    = idx_q ^ BW'(1);
    st_node_a_o = '0;
    st_node_b_o = '0;
    if (state_q == S_BUILD && lvl_q > 1) begin
      st_node_a_o = off(int'(lvl_q) - 1) + NW'({bj_q, 1'b0});
      st_node_b_o = off(int'(lvl_q) - 1) + NW'({bj_q, 1'b1});
    end else begin
      st_node_a_o = off(int'(lvl_q)) + NW'(idx_q ^ BW'(1));
    end
  end

  wire [127:0] path_sib = pass2_q ? sib_q[lvl_q[LW-1:0]] :
                          (lvl_q == 0) ? leaf(idx_q ^ BW'(1), st_sib_ctr_i) : st_node_a_i;

  assign req_ready_o  = (state_q == S_IDLE);
  assign rsp_valid_o  = (state_q == S_RESP);
  assign rsp_status_o = rsp_status_q;
  assign rsp_rdata_o  = rsp_rdata_q;
  assign tamper_o     = tamper_q;
  assign root_o       = root_q;

  // ---------------- engine control (combinational) ----------------
  always_comb begin
    cm_start = 1'b0; cm_key = k_tree_q; cm_k1 = k1_tree_q; cm_msg = '0;
    aes_start = 1'b0; aes_key = k_enc_q; aes_in = '0;
    st_clear_o = 1'b0;
    st_data_we_o = 1'b0; st_ct_o = new_ct_q; st_mac_o = new_mac_q; st_ctr_o = ctr_q;
    st_node_we_o = 1'b0; st_node_waddr_o = '0; st_node_wdata_o = '0;

    unique case (state_q)
      S_K1T: begin aes_key = k_tree_q; aes_in = '0; aes_start = !aes_busy && !aes_done; end
      S_K1M: begin aes_key = k_mac_q;  aes_in = '0; aes_start = !aes_busy && !aes_done; end
      S_BUILD: begin
        cm_start = !cm_busy;
        cm_msg = (lvl_q == 1) ? {leaf({bj_q[BW-2:0], 1'b0}, 32'd0), leaf({bj_q[BW-2:0], 1'b1}, 32'd0)}
                              : {st_node_a_i, st_node_b_i};
      end
      S_PATH: begin
        cm_start = !cm_busy;
        cm_msg = idx_q[0] ? {path_sib, h_q} : {h_q, path_sib};
      end
      S_DMAC: begin
        cm_start = !cm_busy; cm_key = k_mac_q; cm_k1 = k1_mac_q;
        cm_msg = op_write_q ? {wdata_q ^ ks_q, 32'(blk_q), ctr_q, C_DMAC, C_VTF3}
                            : {ct_q, 32'(blk_q), ctr_q, C_DMAC, C_VTF3};
      end
      S_BUILD_W: begin
        // every finished non-root node of the initial tree goes to untrusted storage
        st_node_we_o = cm_done && (int'(lvl_q) < D);
        st_node_waddr_o = off(int'(lvl_q)) + NW'(bj_q);
        st_node_wdata_o = cm_tag;
      end
      S_COMMIT: begin
        // lvl_q walks 1 .. D-1 writing the recomputed path nodes; data written with level 1.
        st_node_we_o = 1'b1;
        st_node_waddr_o = off(int'(lvl_q)) + NW'(blk_q >> lvl_q);
        st_node_wdata_o = newnode_q[LW'(lvl_q - 1'b1)];
        st_data_we_o = (lvl_q == 1);
      end
      default: ;
    endcase
    if (state_q == S_IDLE && req_valid_i) begin
      // Keystream for (blk, ctr) of a read, or (blk, ctr+1) of a write, in parallel with the path.
      aes_start = 1'b1;
      aes_in = {32'(req_blk_i), st_ctr_i + (req_write_i ? 32'd1 : 32'd0), C_CTRK, C_VTF3};
    end
    if (init_i && (state_q == S_EMPTY || state_q == S_IDLE)) st_clear_o = 1'b1;
  end

  always_ff @(posedge clk) begin
    if (!rst_n || zeroize_i) begin
      state_q <= S_EMPTY;
      k_enc_q <= '0; k_mac_q <= '0; k_tree_q <= '0; k1_tree_q <= '0; k1_mac_q <= '0;
      root_q <= '0; tamper_q <= 1'b0; ks_q <= '0; ks_valid_q <= 1'b0;
      h_q <= '0; ct_q <= '0; mac_q <= '0; wdata_q <= '0; new_ct_q <= '0; new_mac_q <= '0;
      ctr_q <= '0; old_ctr_q <= '0; blk_q <= '0; idx_q <= '0; lvl_q <= '0; bj_q <= '0;
      pass2_q <= 1'b0; op_write_q <= 1'b0; rsp_status_q <= ST_OK; rsp_rdata_q <= '0;
      for (int i = 0; i < D; i++) begin sib_q[i] <= '0; newnode_q[i] <= '0; end
    end else begin
      if (aes_done && (state_q != S_K1T) && (state_q != S_K1M)) begin
        ks_q <= aes_out; ks_valid_q <= 1'b1;
      end
      if (init_i && state_q != S_EMPTY && state_q != S_IDLE) begin
        // ignore re-init while busy
      end else if (init_i) begin
        k_enc_q <= key_enc_i; k_mac_q <= key_mac_i; k_tree_q <= key_tree_i;
        tamper_q <= 1'b0; state_q <= S_K1T;
      end else begin
        unique case (state_q)
          S_EMPTY: ;
          S_K1T: if (aes_done) begin k1_tree_q <= dbl(aes_out); state_q <= S_K1M; end
          S_K1M: if (aes_done) begin
            k1_mac_q <= dbl(aes_out); lvl_q <= 1; bj_q <= '0; state_q <= S_BUILD;
          end
          S_BUILD: if (!cm_busy) state_q <= S_BUILD_W;
          S_BUILD_W: if (cm_done) begin
            if (int'(lvl_q) == D) begin
              root_q <= cm_tag; state_q <= S_IDLE;
            end else begin
              // stored by the storage write port below (same cycle)
              if (int'(bj_q) == (BLOCKS >> lvl_q) - 1) begin
                bj_q <= '0; lvl_q <= lvl_q + 1'b1;
              end else begin
                bj_q <= bj_q + 1'b1;
              end
              state_q <= S_BUILD;
            end
          end
          S_IDLE: begin
            if (req_valid_i) begin
              blk_q <= req_blk_i;
              op_write_q <= req_write_i; wdata_q <= req_wdata_i;
              ct_q <= st_ct_i; mac_q <= st_mac_i;
              ctr_q <= st_ctr_i; old_ctr_q <= st_ctr_i;
              h_q <= leaf(req_blk_i, st_ctr_i);
              idx_q <= req_blk_i; lvl_q <= '0; pass2_q <= 1'b0; ks_valid_q <= 1'b0;
              state_q <= S_PATH;
            end
          end
          S_PATH: if (!cm_busy) begin
            if (!pass2_q) sib_q[lvl_q[LW-1:0]] <= path_sib;
            state_q <= S_PATH_W;
          end
          S_PATH_W: if (cm_done) begin
            h_q <= cm_tag;
            if (pass2_q) newnode_q[lvl_q[LW-1:0]] <= cm_tag;
            idx_q <= idx_q >> 1;
            if (int'(lvl_q) == D - 1) begin
              lvl_q <= '0;
              if (!pass2_q) begin
                if (cm_tag != root_q) begin
                  tamper_q <= 1'b1; rsp_status_q <= ST_TAMPER; rsp_rdata_q <= '0; state_q <= S_RESP;
                end else if (op_write_q && old_ctr_q == 32'hFFFF_FFFF) begin
                  rsp_status_q <= ST_EXHAUSTED; rsp_rdata_q <= '0; state_q <= S_RESP;
                end else if (op_write_q) begin
                  ctr_q <= old_ctr_q + 32'd1; state_q <= S_DMAC;
                end else if (old_ctr_q == 32'd0) begin
                  rsp_status_q <= ST_OK; rsp_rdata_q <= '0; state_q <= S_RESP;   // never written
                end else begin
                  state_q <= S_DMAC;
                end
              end else begin
                root_q <= cm_tag; lvl_q <= 1; state_q <= S_COMMIT;
              end
            end else begin
              lvl_q <= lvl_q + 1'b1;
              state_q <= S_PATH;
            end
          end
          S_DMAC: if (!cm_busy && ks_valid_q) begin
            if (op_write_q) new_ct_q <= wdata_q ^ ks_q;
            state_q <= S_DMAC_W;
          end
          S_DMAC_W: if (cm_done) begin
            if (op_write_q) begin
              new_mac_q <= cm_tag;
              h_q <= leaf(blk_q, ctr_q); idx_q <= blk_q; lvl_q <= '0; pass2_q <= 1'b1;
              state_q <= S_PATH;
            end else if (cm_tag != mac_q) begin
              tamper_q <= 1'b1; rsp_status_q <= ST_TAMPER; rsp_rdata_q <= '0; state_q <= S_RESP;
            end else begin
              rsp_status_q <= ST_OK; rsp_rdata_q <= ct_q ^ ks_q; state_q <= S_RESP;
            end
          end
          S_COMMIT: begin
            if (int'(lvl_q) == D - 1) begin
              rsp_status_q <= ST_OK; rsp_rdata_q <= '0; state_q <= S_RESP;
            end else begin
              lvl_q <= lvl_q + 1'b1;
            end
          end
          S_RESP: state_q <= S_IDLE;
          default: state_q <= S_EMPTY;
        endcase
      end
    end
  end

endmodule
