// SPDX-License-Identifier: MIT
// Simple sentinel-bank monitor for the logical security tier.
// The expected values are provisioned by secure boot logic. This block is a
// synthesizable architectural monitor; physical active-mesh and sensor design
// still require target technology support.

`timescale 1ns/1ps

module tier_sentinel_monitor #(
  parameter int COUNT = 8,
  parameter int WORD_WIDTH = 32
) (
  input  logic clk,
  input  logic rst_n,
  input  logic provision_i,
  input  logic check_i,
  input  logic [WORD_WIDTH-1:0] observed_i [COUNT],
  input  logic [WORD_WIDTH-1:0] provision_value_i [COUNT],
  output logic sentinel_fault_o
);

  logic [WORD_WIDTH-1:0] expected [COUNT];

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      sentinel_fault_o <= 1'b0;
      for (int i = 0; i < COUNT; i++) expected[i] <= '0;
    end else begin
      if (provision_i) begin
        for (int i = 0; i < COUNT; i++) expected[i] <= provision_value_i[i];
      end
      if (check_i) begin
        for (int i = 0; i < COUNT; i++) begin
          if (observed_i[i] != expected[i]) sentinel_fault_o <= 1'b1;
        end
      end
    end
  end

endmodule
