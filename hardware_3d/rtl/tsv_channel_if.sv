// SPDX-License-Identifier: MIT
// TSV channel abstraction for Crypto3DStackCPU 3D stacked memory.
// This interface models logical TSV bundles, not physical TSV cells.

interface tsv_channel_if #(
  parameter int WORD_WIDTH  = 32,
  parameter int ADDR_WIDTH  = 10,
  parameter int LAYER_WIDTH = 2
) (
  input logic clk,
  input logic rst_n
);

  logic [LAYER_WIDTH-1:0] layer;
  logic [ADDR_WIDTH-1:0]  addr;
  logic [WORD_WIDTH-1:0]  wdata;
  logic [WORD_WIDTH-1:0]  rdata;
  logic                  ren;
  logic                  wen;
  logic                  ready;
  logic                  denied;
  logic                  tamper;

  // Abstract TSV fault injection lines for verification.
  logic                  fault_inject;
  logic [WORD_WIDTH-1:0] fault_mask;

  modport master (
    input  clk, rst_n,
    output layer, addr, wdata, ren, wen, fault_inject, fault_mask,
    input  rdata, ready, denied, tamper
  );

  modport slave (
    input  clk, rst_n,
    input  layer, addr, wdata, ren, wen, fault_inject, fault_mask,
    output rdata, ready, denied, tamper
  );

endinterface
