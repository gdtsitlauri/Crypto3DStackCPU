// SPDX-License-Identifier: MIT
// Trace-driven CPU + VTF system test (roadmap 2.6).
//
// Replays a vertical-transaction trace recorded from the C++ CPU running a
// program (C3D_VTF_TRACE, see src/3d.cpp):
//   F layer addr        instruction-cache line fill word -> CPU_FETCH read of the EXEC tier
//   R layer addr        data-cache miss                  -> CPU_DATA read of the DATA tier
//   W layer addr value  write-through store              -> CPU_DATA write of the DATA tier
// Instruction and data accesses are mapped onto the EXEC (layer 0) and DATA
// (layer 1) tiers, as in the 3D tier plan. Each access goes CPU -> bridge (sign)
// -> VTF system (verify, guard, memory, sign) -> bridge (verify) -> CPU.
// Checks: every access is authorised and authenticated, loads return the last
// stored value (TB shadow memory), no tamper/lockdown. Reports the measured
// cycles per vertical transaction (METRIC rows).
//
//   vvp tb_vtf_soc.vvp +TRACE=path/to/program.trace

`timescale 1ns/1ps
import crypto3d_stack_pkg::*;

module tb_vtf_soc #(parameter bit FAULT_HARDEN = 1'b0, parameter int MAX_TX = 4000);
  `include "vtf_vectors.svh"

  logic clk = 1'b0;
  always #5 clk = ~clk;
  logic rst_n = 1'b0, root_load = 1'b0, ready;
  logic cpu_valid = 1'b0, cpu_ready, cpu_fetch, cpu_write, rsp_valid, rsp_ok;
  logic [7:0] cpu_layer;
  logic [31:0] cpu_addr, cpu_wdata, rsp_rdata;
  c3d_layer_role_t roles [C3D_LAYERS];
  logic layer_access [C3D_LAYERS];
  logic signed [17:0] temps [C3D_LAYERS];
  logic [31:0] sobs [8], sval [8];
  logic lockdown, tamper, fault_alarm;

  crypto3d_vtf_soc_top #(.FAULT_HARDEN(FAULT_HARDEN)) dut (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load), .root_key_i(VEC_ROOT), .active_epoch_i(32'd1),
    .ready_o(ready), .cpu_valid_i(cpu_valid), .cpu_ready_o(cpu_ready), .cpu_fetch_i(cpu_fetch),
    .cpu_write_i(cpu_write), .cpu_layer_i(cpu_layer), .cpu_addr_i(cpu_addr), .cpu_wdata_i(cpu_wdata),
    .cpu_rsp_valid_o(rsp_valid), .cpu_rsp_ok_o(rsp_ok), .cpu_rsp_rdata_o(rsp_rdata),
    .layer_role_i(roles), .layer_access_i(layer_access), .temperature_mc_i(temps),
    .physical_fault_i(1'b0), .sentinel_provision_i(root_load), .sentinel_check_i(1'b0),
    .sentinel_observed_i(sobs), .sentinel_value_i(sval),
    .lockdown_o(lockdown), .tamper_o(tamper), .fault_alarm_o(fault_alarm)
  );

  logic [31:0] shadow [2][C3D_WORDS];
  int fails = 0;

  task automatic access(input bit fetch, input bit write, input logic [7:0] layer, input logic [31:0] addr,
                        input logic [31:0] wdata, output int cycles, output bit ok, output logic [31:0] rdata);
    @(negedge clk);
    while (!cpu_ready) @(negedge clk);
    cpu_valid = 1'b1; cpu_fetch = fetch; cpu_write = write; cpu_layer = layer; cpu_addr = addr; cpu_wdata = wdata;
    @(negedge clk); cpu_valid = 1'b0;
    cycles = 1;
    while (!rsp_valid) begin @(negedge clk); cycles++; end
    ok = rsp_ok; rdata = rsp_rdata;
  endtask

  initial begin
    string path;
    int fd, n, cyc, sum_f, sum_r, sum_w, nf, nr, nw, code;
    bit ok;
    logic [31:0] rd, a, v;
    byte kind;
    int layer;
    if (!$value$plusargs("TRACE=%s", path)) path = "program.trace";
    roles[0] = C3D_LAYER_ROLE_EXEC; roles[1] = C3D_LAYER_ROLE_DATA;
    roles[2] = C3D_LAYER_ROLE_KEY_HIDE; roles[3] = C3D_LAYER_ROLE_SENTINEL;
    for (int l = 0; l < C3D_LAYERS; l++) begin layer_access[l] = 1'b1; temps[l] = 18'sd30000; end
    for (int i = 0; i < 8; i++) begin sval[i] = 32'h5E000000 + i; sobs[i] = 32'h5E000000 + i; end
    for (int i = 0; i < C3D_LAYERS * C3D_WORDS; i++) dut.vtf_i.mem_i.mem[i] = 32'h0;
    for (int t = 0; t < 2; t++) for (int i = 0; i < C3D_WORDS; i++) shadow[t][i] = 32'h0;
    repeat (3) @(negedge clk);
    rst_n = 1'b1;
    @(negedge clk); root_load = 1'b1;
    @(negedge clk); root_load = 1'b0;
    while (!ready) @(negedge clk);

    fd = $fopen(path, "r");
    if (fd == 0) begin $display("[SV TEST FAIL] cannot open trace %s", path); $finish; end
    n = 0; sum_f = 0; sum_r = 0; sum_w = 0; nf = 0; nr = 0; nw = 0;
    while (!$feof(fd) && n < MAX_TX) begin
      code = $fscanf(fd, "%c %d %d", kind, layer, a);
      if (code != 3) continue;
      if (kind == "W") code = $fscanf(fd, " %h", v);
      a = a % C3D_WORDS;
      if (kind == "F") begin
        access(1'b1, 1'b0, 8'd0, a, 32'h0, cyc, ok, rd);
        if (!ok || rd !== shadow[0][a]) begin fails++; if (fails < 5) $display("[FAIL] fetch %0d", a); end
        sum_f += cyc; nf++;
      end else if (kind == "R") begin
        access(1'b0, 1'b0, 8'd1, a, 32'h0, cyc, ok, rd);
        if (!ok || rd !== shadow[1][a]) begin fails++; if (fails < 5) $display("[FAIL] load %0d", a); end
        sum_r += cyc; nr++;
      end else if (kind == "W") begin
        access(1'b0, 1'b1, 8'd1, a, v, cyc, ok, rd);
        if (!ok) begin fails++; if (fails < 5) $display("[FAIL] store %0d", a); end
        shadow[1][a] = v;
        sum_w += cyc; nw++;
      end else continue;
      n++;
    end
    $fclose(fd);
    if (tamper || lockdown) begin fails++; $display("[FAIL] tamper=%0d lockdown=%0d", tamper, lockdown); end
    $display("METRIC,transactions,%0d", n);
    $display("METRIC,fetch_count,%0d", nf);
    $display("METRIC,load_count,%0d", nr);
    $display("METRIC,store_count,%0d", nw);
    if (nf) $display("METRIC,fetch_cycles_avg,%0.2f", real'(sum_f) / nf);
    if (nr) $display("METRIC,load_cycles_avg,%0.2f", real'(sum_r) / nr);
    if (nw) $display("METRIC,store_cycles_avg,%0.2f", real'(sum_w) / nw);
    if (fails == 0 && n > 0) $display("[SV TEST PASS] tb_vtf_soc (%0d transactions)", n);
    else $display("[SV TEST FAIL] tb_vtf_soc (%0d failures, %0d transactions)", fails, n);
    $finish;
  end
endmodule
