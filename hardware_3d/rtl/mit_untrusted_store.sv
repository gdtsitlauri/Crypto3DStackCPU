// SPDX-License-Identifier: MIT
// Untrusted off-chip storage for memory_integrity_tree (roadmap 2.1).
// Behavioural model of DRAM/stacked-memory contents OUTSIDE the trust boundary:
// ciphertext, data MACs, write counters and the non-root tree nodes. The
// attacker may read or overwrite any of it (testbenches poke these arrays
// directly). Combinational reads keep the engine model simple; a real memory
// port would add latency, not change the security argument.

`timescale 1ns/1ps

module mit_untrusted_store #(
  parameter int BLOCKS = 16,
  localparam int BW = $clog2(BLOCKS),
  localparam int NODES = BLOCKS - 2,
  localparam int NW = $clog2(NODES)
) (
  input  logic          clk,
  input  logic [BW-1:0] blk_i,
  input  logic [BW-1:0] sib_i,
  output logic [127:0]  ct_o,
  output logic [127:0]  mac_o,
  output logic [31:0]   ctr_o,
  output logic [31:0]   sib_ctr_o,
  input  logic [NW-1:0] node_a_i,
  input  logic [NW-1:0] node_b_i,
  output logic [127:0]  node_a_o,
  output logic [127:0]  node_b_o,
  input  logic          clear_i,
  input  logic          data_we_i,
  input  logic [127:0]  ct_i,
  input  logic [127:0]  mac_i,
  input  logic [31:0]   ctr_i,
  input  logic          node_we_i,
  input  logic [NW-1:0] node_waddr_i,
  input  logic [127:0]  node_wdata_i
);
  logic [127:0] ct  [BLOCKS];
  logic [127:0] mac [BLOCKS];
  logic [31:0]  ctr [BLOCKS];
  logic [127:0] node [NODES];

  assign ct_o      = ct[blk_i];
  assign mac_o     = mac[blk_i];
  assign ctr_o     = ctr[blk_i];
  assign sib_ctr_o = ctr[sib_i];
  assign node_a_o  = node[node_a_i];
  assign node_b_o  = node[node_b_i];

  always_ff @(posedge clk) begin
    if (clear_i) begin
      for (int i = 0; i < BLOCKS; i++) begin ct[i] <= '0; mac[i] <= '0; ctr[i] <= '0; end
      for (int i = 0; i < NODES; i++) node[i] <= '0;
    end else begin
      if (data_we_i) begin ct[blk_i] <= ct_i; mac[blk_i] <= mac_i; ctr[blk_i] <= ctr_i; end
      if (node_we_i) node[node_waddr_i] <= node_wdata_i;
    end
  end
endmodule
