// SPDX-License-Identifier: MIT
// Abstract TSV interconnect model.
// Routes a logical CPU memory request to the 3D stack model through TSV-like signals.

`timescale 1ns/1ps

module tsv_interconnect_model #(
  parameter int WORD_WIDTH  = 32,
  parameter int ADDR_WIDTH  = 10,
  parameter int LAYER_WIDTH = 2
) (
  input  logic clk,
  input  logic rst_n,

  input  logic [LAYER_WIDTH-1:0] cpu_layer_i,
  input  logic [ADDR_WIDTH-1:0]  cpu_addr_i,
  input  logic [WORD_WIDTH-1:0]  cpu_wdata_i,
  input  logic                  cpu_ren_i,
  input  logic                  cpu_wen_i,
  output logic [WORD_WIDTH-1:0]  cpu_rdata_o,
  output logic                  cpu_ready_o,
  output logic                  cpu_denied_o,
  output logic                  cpu_tamper_o,

  tsv_channel_if.master         tsv
);

  always_comb begin
    tsv.layer = cpu_layer_i;
    tsv.addr  = cpu_addr_i;
    tsv.wdata = cpu_wdata_i;
    tsv.ren   = cpu_ren_i;
    tsv.wen   = cpu_wen_i;

    cpu_rdata_o = tsv.rdata;
    cpu_ready_o = tsv.ready;
    cpu_denied_o = tsv.denied;
    cpu_tamper_o = tsv.tamper;
  end

endmodule
