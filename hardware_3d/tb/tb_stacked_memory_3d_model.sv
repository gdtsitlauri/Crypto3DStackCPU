// SPDX-License-Identifier: MIT
// Basic simulation testbench for the 3D stacked memory RTL model.

`timescale 1ns/1ps

import crypto3d_stack_pkg::*;

module tb_stacked_memory_3d_model;

  logic clk = 0;
  logic rst_n = 0;

  always #5 clk = ~clk;

  logic [C3D_LAYER_WIDTH-1:0] layer;
  logic [C3D_ADDR_WIDTH-1:0]  addr;
  logic [C3D_WORD_WIDTH-1:0]  wdata;
  logic ren;
  logic wen;
  logic [C3D_WORD_WIDTH-1:0] rdata;
  logic ready;
  logic denied;
  logic tamper;

  logic layer_access [C3D_LAYERS];
  logic tamper_clear;
  logic fault_inject;
  logic [C3D_WORD_WIDTH-1:0] fault_mask;

  stacked_memory_3d_model dut (
    .clk(clk),
    .rst_n(rst_n),
    .layer_i(layer),
    .addr_i(addr),
    .wdata_i(wdata),
    .ren_i(ren),
    .wen_i(wen),
    .layer_access_i(layer_access),
    .tamper_clear_i(tamper_clear),
    .fault_inject_i(fault_inject),
    .fault_mask_i(fault_mask),
    .rdata_o(rdata),
    .ready_o(ready),
    .denied_o(denied),
    .tamper_o(tamper)
  );

  task automatic cycle;
    begin
      @(posedge clk);
      #1;
    end
  endtask

  task automatic write_word(input int l, input int a, input logic [31:0] d);
    begin
      layer = l[C3D_LAYER_WIDTH-1:0];
      addr = a[C3D_ADDR_WIDTH-1:0];
      wdata = d;
      wen = 1'b1;
      ren = 1'b0;
      cycle();
      wen = 1'b0;
      cycle();
    end
  endtask

  task automatic read_word(input int l, input int a);
    begin
      layer = l[C3D_LAYER_WIDTH-1:0];
      addr = a[C3D_ADDR_WIDTH-1:0];
      wen = 1'b0;
      ren = 1'b1;
      cycle();
      ren = 1'b0;
      cycle();
    end
  endtask

  initial begin
    for (int i = 0; i < C3D_LAYERS; i++) begin
      layer_access[i] = 1'b1;
    end

    layer = '0;
    addr = '0;
    wdata = '0;
    ren = 1'b0;
    wen = 1'b0;
    tamper_clear = 1'b0;
    fault_inject = 1'b0;
    fault_mask = 32'h0000_0001;

    repeat (3) cycle();
    rst_n = 1'b1;
    cycle();

    write_word(0, 0, 32'h1111_1111);
    write_word(1, 0, 32'h2222_2222);
    write_word(2, 0, 32'h3333_3333);
    write_word(3, 0, 32'h4444_4444);

    read_word(0, 0);
    if (rdata !== 32'h1111_1111) $fatal(1, "Layer 0 mismatch");

    read_word(1, 0);
    if (rdata !== 32'h2222_2222) $fatal(1, "Layer 1 mismatch");

    layer_access[2] = 1'b0;
    read_word(2, 0);
    if (!denied) $fatal(1, "Access disable did not deny layer 2");

    layer_access[2] = 1'b1;
    fault_inject = 1'b1;
    read_word(3, 0);
    if (!tamper) $fatal(1, "Fault injection did not latch tamper");

    $display("[SV TEST PASS] stacked_memory_3d_model");
    $finish;
  end

endmodule
