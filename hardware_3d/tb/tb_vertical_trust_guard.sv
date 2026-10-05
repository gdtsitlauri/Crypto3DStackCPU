// SPDX-License-Identifier: MIT
// Directed validation for vertical_trust_guard policy/replay/fault behavior.
// Requires a SystemVerilog simulator (Icarus/Verilator/Questa/etc.).

`timescale 1ns/1ps
import crypto3d_stack_pkg::*;

module tb_vertical_trust_guard;
  logic clk = 0;
  logic rst_n = 0;
  always #5 clk = ~clk;

  logic req_valid;
  logic [2:0] requester;
  logic op_write;
  logic [C3D_LAYER_WIDTH-1:0] layer;
  logic [31:0] seq_num;
  logic [31:0] epoch;
  logic [31:0] active_epoch;
  logic auth_ok;
  logic debug_unlocked;
  c3d_layer_role_t roles[C3D_LAYERS];
  logic signed [17:0] temperature_mc[C3D_LAYERS];
  logic physical_fault;
  logic sentinel_fault;
  logic allow, denied, lockdown, severe, key_zeroize;
  logic [7:0] deny_reason;

  vertical_trust_guard dut (
    .clk(clk), .rst_n(rst_n), .req_valid_i(req_valid),
    .requester_i(requester), .op_write_i(op_write), .layer_i(layer),
    .sequence_i(seq_num), .epoch_i(epoch), .active_epoch_i(active_epoch),
    .auth_ok_i(auth_ok), .debug_unlocked_i(debug_unlocked),
    .layer_role_i(roles), .temperature_mc_i(temperature_mc),
    .physical_fault_i(physical_fault), .sentinel_fault_i(sentinel_fault),
    .allow_o(allow), .denied_o(denied), .lockdown_o(lockdown),
    .severe_event_o(severe), .key_zeroize_o(key_zeroize),
    .deny_reason_o(deny_reason)
  );

  task automatic cycle; begin @(posedge clk); #1; end endtask

  initial begin
    roles[0] = C3D_LAYER_ROLE_EXEC;
    roles[1] = C3D_LAYER_ROLE_DATA;
    roles[2] = C3D_LAYER_ROLE_KEY_HIDE;
    roles[3] = C3D_LAYER_ROLE_SENTINEL;
    for (int i = 0; i < C3D_LAYERS; i++) temperature_mc[i] = 18'sd25000;
    req_valid = 0; requester = 0; op_write = 0; layer = 0;
    seq_num = 0; epoch = 1; active_epoch = 1; auth_ok = 1;
    debug_unlocked = 0; physical_fault = 0; sentinel_fault = 0;
    repeat (2) cycle(); rst_n = 1; cycle();

    // Valid CPU fetch.
    requester = 3'd0; layer = 0; op_write = 0; seq_num = 1; req_valid = 1;
    #1; if (!allow || denied) $fatal(1, "CPU fetch was not allowed");
    cycle(); req_valid = 0; #1;

    // CPU data request to key tier: denied but not destructive.
    requester = 3'd1; layer = 2; seq_num = 1; req_valid = 1;
    #1; if (!denied || lockdown) $fatal(1, "Policy denial behavior mismatch");
    cycle(); req_valid = 0; #1;

    // The authenticated policy denial consumed sequence number 1. A valid CPU
    // data request therefore uses 2; replaying 2 must trigger lockdown.
    // (`sequence` is a SystemVerilog keyword, hence the seq_num signal name.)
    requester = 3'd1; layer = 1; seq_num = 2; req_valid = 1;
    #1; if (!allow || denied) $fatal(1, "CPU data request was not allowed");
    cycle(); req_valid = 0; #1;

    req_valid = 1; seq_num = 2; #1;
    if (!lockdown || !key_zeroize || !denied) $fatal(1, "Replay did not lock/zeroize");
    cycle(); req_valid = 0; #1;
    if (!lockdown) $fatal(1, "Lockdown did not latch");

    $display("[SV TEST PASS] vertical_trust_guard");
    $finish;
  end
endmodule
