// SPDX-License-Identifier: MIT
// Behavioral multi-layer 3D stacked-memory RTL model.
// Suitable for simulation and Vivado/Artix-7 BRAM inference.
// It is NOT a PDK-bound SRAM/HBM/TSV macro.
//
// Synthesis notes for Vivado on Artix-7:
//   * The unpacked array `mem` is intentionally NOT reset, so that Vivado
//     infers block RAM (BRAM) rather than distributed LUT RAM. Initializing
//     4 layers x 1024 words through a synchronous reset would defeat BRAM
//     inference. Block RAMs are not reset by bitstream-style content loads
//     on Artix-7; they should instead be initialized by explicit writes
//     from the secure loader / HLS top function.
//   * `ram_style = "block"` is a strong hint to keep the memory in BRAM.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module stacked_memory_3d_model #(
  parameter int LAYERS      = C3D_LAYERS,
  parameter int WORDS       = C3D_WORDS,
  parameter int WORD_WIDTH  = C3D_WORD_WIDTH,
  parameter int ADDR_WIDTH  = C3D_ADDR_WIDTH,
  parameter int LAYER_WIDTH = C3D_LAYER_WIDTH
) (
  input  logic clk,
  input  logic rst_n,

  input  logic [LAYER_WIDTH-1:0] layer_i,
  input  logic [ADDR_WIDTH-1:0]  addr_i,
  input  logic [WORD_WIDTH-1:0]  wdata_i,
  input  logic                   ren_i,
  input  logic                   wen_i,

  input  logic                   layer_access_i [LAYERS],
  input  logic                   tamper_clear_i,
  input  logic                   fault_inject_i,
  input  logic [WORD_WIDTH-1:0]  fault_mask_i,

  output logic [WORD_WIDTH-1:0]  rdata_o,
  output logic                   ready_o,
  output logic                   denied_o,
  output logic                   tamper_o
);

  // BRAM-inferable 3D memory. Deliberately not reset so Vivado can map
  // this to block RAM primitives on Artix-7.
  (* ram_style = "block" *)
  logic [WORD_WIDTH-1:0] mem [LAYERS][WORDS];

  logic tamper_latched;

  assign tamper_o = tamper_latched;

  // Control registers use synchronous reset (BRAM-independent).
  always_ff @(posedge clk) begin
    if (!rst_n) begin
      rdata_o        <= '0;
      ready_o        <= 1'b0;
      denied_o       <= 1'b0;
      tamper_latched <= 1'b0;
    end else begin
      ready_o  <= 1'b0;
      denied_o <= 1'b0;

      if (tamper_clear_i) begin
        tamper_latched <= 1'b0;
      end

      if ((ren_i || wen_i) && ((int'(layer_i) >= LAYERS) ||
                               (int'(addr_i)  >= WORDS))) begin
        // Out-of-range transaction: latched tamper, denied, no RAM access.
        denied_o       <= 1'b1;
        ready_o        <= 1'b1;
        tamper_latched <= 1'b1;
      end else if ((ren_i || wen_i) && !layer_access_i[layer_i]) begin
        // Layer-level access control: denied but not a tamper event.
        denied_o <= 1'b1;
        ready_o  <= 1'b1;
      end else begin
        if (wen_i) begin
          mem[layer_i][addr_i] <= fault_inject_i ? (wdata_i ^ fault_mask_i) : wdata_i;
          ready_o              <= 1'b1;
          if (fault_inject_i) begin
            tamper_latched <= 1'b1;
          end
        end

        if (ren_i) begin
          rdata_o <= fault_inject_i ? (mem[layer_i][addr_i] ^ fault_mask_i)
                                    :  mem[layer_i][addr_i];
          ready_o <= 1'b1;
          if (fault_inject_i) begin
            tamper_latched <= 1'b1;
          end
        end
      end
    end
  end

endmodule
