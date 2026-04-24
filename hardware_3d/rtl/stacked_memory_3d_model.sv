// SPDX-License-Identifier: MIT
// Behavioral multi-layer 3D stacked-memory RTL model.
// This module is suitable for simulation/integration planning.
// It is NOT a PDK-bound SRAM/HBM/TSV macro.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module stacked_memory_3d_model #(
  parameter int LAYERS     = C3D_LAYERS,
  parameter int WORDS      = C3D_WORDS,
  parameter int WORD_WIDTH = C3D_WORD_WIDTH,
  parameter int ADDR_WIDTH = C3D_ADDR_WIDTH,
  parameter int LAYER_WIDTH = C3D_LAYER_WIDTH
) (
  input  logic clk,
  input  logic rst_n,

  input  logic [LAYER_WIDTH-1:0] layer_i,
  input  logic [ADDR_WIDTH-1:0]  addr_i,
  input  logic [WORD_WIDTH-1:0]  wdata_i,
  input  logic                  ren_i,
  input  logic                  wen_i,

  input  logic                  layer_access_i [LAYERS],
  input  logic                  tamper_clear_i,
  input  logic                  fault_inject_i,
  input  logic [WORD_WIDTH-1:0] fault_mask_i,

  output logic [WORD_WIDTH-1:0]  rdata_o,
  output logic                  ready_o,
  output logic                  denied_o,
  output logic                  tamper_o
);

  logic [WORD_WIDTH-1:0] mem [LAYERS][WORDS];
  logic tamper_latched;

  assign tamper_o = tamper_latched;

  integer l;
  integer a;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rdata_o <= '0;
      ready_o <= 1'b0;
      denied_o <= 1'b0;
      tamper_latched <= 1'b0;

      for (l = 0; l < LAYERS; l = l + 1) begin
        for (a = 0; a < WORDS; a = a + 1) begin
          mem[l][a] <= '0;
        end
      end
    end else begin
      ready_o <= 1'b0;
      denied_o <= 1'b0;

      if (tamper_clear_i) begin
        tamper_latched <= 1'b0;
      end

      if ((ren_i || wen_i) && (layer_i >= LAYERS || addr_i >= WORDS)) begin
        denied_o <= 1'b1;
        ready_o <= 1'b1;
        tamper_latched <= 1'b1;
      end else if ((ren_i || wen_i) && !layer_access_i[layer_i]) begin
        denied_o <= 1'b1;
        ready_o <= 1'b1;
      end else begin
        if (wen_i) begin
          mem[layer_i][addr_i] <= fault_inject_i ? (wdata_i ^ fault_mask_i) : wdata_i;
          ready_o <= 1'b1;
          if (fault_inject_i) begin
            tamper_latched <= 1'b1;
          end
        end

        if (ren_i) begin
          rdata_o <= fault_inject_i ? (mem[layer_i][addr_i] ^ fault_mask_i) : mem[layer_i][addr_i];
          ready_o <= 1'b1;
          if (fault_inject_i) begin
            tamper_latched <= 1'b1;
          end
        end
      end
    end
  end

endmodule
