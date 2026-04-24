// SPDX-License-Identifier: MIT
// Bridge stub for connecting Crypto3DStackCPU HLS IP to a future 3D stacked memory.
// This is a specification/stub, not a complete AXI production bridge.

`timescale 1ns/1ps

module crypto3d_memory_bridge_stub #(
  parameter int WORD_WIDTH  = 32,
  parameter int ADDR_WIDTH  = 10,
  parameter int LAYER_WIDTH = 2
) (
  input  logic clk,
  input  logic rst_n,

  // Simplified CPU/HLS-side memory request.
  input  logic [LAYER_WIDTH-1:0] layer_i,
  input  logic [ADDR_WIDTH-1:0]  addr_i,
  input  logic [WORD_WIDTH-1:0]  wdata_i,
  input  logic                  ren_i,
  input  logic                  wen_i,
  output logic [WORD_WIDTH-1:0]  rdata_o,
  output logic                  ready_o,
  output logic                  denied_o,
  output logic                  tamper_o,

  // TSV-side signals.
  tsv_channel_if.master         tsv
);

  assign tsv.layer = layer_i;
  assign tsv.addr  = addr_i;
  assign tsv.wdata = wdata_i;
  assign tsv.ren   = ren_i;
  assign tsv.wen   = wen_i;

  assign rdata_o  = tsv.rdata;
  assign ready_o  = tsv.ready;
  assign denied_o = tsv.denied;
  assign tamper_o = tsv.tamper;

endmodule
