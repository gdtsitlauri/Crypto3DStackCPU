// SPDX-License-Identifier: MIT
// CPU <-> Vertical Trust Fabric bridge (roadmap 2.6). Replaces the
// pass-through crypto3d_memory_bridge_stub on the CPU side.
//
// The CPU issues plain memory accesses (instruction fetch, load, store). The
// bridge turns each into an authenticated VTF transaction:
//   requester = CPU_FETCH for fetches, CPU_DATA for loads/stores
//   sequence  = per-requester counter, epoch = active epoch, nonce = counter-derived
//   tag       = AES-CMAC with the requester's epoch key
// and checks every response before the CPU sees it: response tag (response
// key), and requester/op/layer/addr/seq/epoch/nonce equal to the request. A bad
// response tag raises a sticky tamper flag; denied requests return error.
//
// Keys come from a vtf_key_schedule instance fed by the same device root as
// the VTF system (in a product the CPU interface and the VTF share one die and
// could share one key schedule).

`timescale 1ns/1ps

module crypto3d_vtf_cpu_bridge #(
  parameter int REQUESTERS = 5
) (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         root_load_i,
  input  logic [127:0] root_key_i,
  input  logic [31:0]  active_epoch_i,
  output logic         keys_ready_o,

  // CPU side
  input  logic         cpu_valid_i,
  output logic         cpu_ready_o,
  input  logic         cpu_fetch_i,       // 1 = instruction fetch
  input  logic         cpu_write_i,
  input  logic [7:0]   cpu_layer_i,
  input  logic [31:0]  cpu_addr_i,
  input  logic [31:0]  cpu_wdata_i,
  output logic         cpu_rsp_valid_o,   // one-cycle pulse
  output logic         cpu_rsp_ok_o,      // executed and response authenticated
  output logic [31:0]  cpu_rsp_rdata_o,
  output logic         tamper_o,          // sticky: forged/corrupted response seen

  // VTF side (to crypto3d_vtf_system_top)
  output logic         vtf_req_valid_o,
  input  logic         vtf_req_ready_i,
  output logic [2:0]   vtf_req_requester_o,
  output logic         vtf_req_write_o,
  output logic [7:0]   vtf_req_layer_o,
  output logic [31:0]  vtf_req_addr_o,
  output logic [31:0]  vtf_req_data_o,
  output logic [31:0]  vtf_req_sequence_o,
  output logic [31:0]  vtf_req_epoch_o,
  output logic [31:0]  vtf_req_nonce_o,
  output logic [127:0] vtf_req_tag_o,
  input  logic         vtf_rsp_valid_i,
  input  logic [7:0]   vtf_rsp_status_i,
  input  logic [31:0]  vtf_rsp_data_i,
  input  logic [255:0] vtf_rsp_msg_i,
  input  logic [127:0] vtf_rsp_tag_i
);
  localparam logic [2:0] REQ_CPU_FETCH = 3'd0, REQ_CPU_DATA = 3'd1;

  typedef enum logic [2:0] {B_IDLE, B_SIGN, B_SEND, B_WAIT, B_VERIFY, B_DONE} state_t;
  state_t state_q;

  logic [127:0] req_key [REQUESTERS];
  logic [127:0] req_k1  [REQUESTERS];
  logic [127:0] rsp_key, rsp_k1;

  vtf_key_schedule #(.EPOCH_KEYS(1'b1), .REQUESTERS(REQUESTERS)) keys_i (
    .clk(clk), .rst_n(rst_n), .root_load_i(root_load_i), .root_key_i(root_key_i),
    .active_epoch_i(active_epoch_i), .zeroize_i(1'b0), .ready_o(keys_ready_o),
    .req_key_o(req_key), .req_k1_o(req_k1), .rsp_key_o(rsp_key), .rsp_k1_o(rsp_k1)
  );

  logic         cm_start, cm_busy, cm_done;
  logic [127:0] cm_key, cm_k1, cm_tag;
  logic [255:0] cm_msg;
  aes_cmac32 cmac_i (
    .clk(clk), .rst_n(rst_n), .start_i(cm_start), .clear_i(1'b0), .key_i(cm_key),
    .k1_valid_i(1'b1), .k1_i(cm_k1), .msg_i(cm_msg),
    .busy_o(cm_busy), .done_o(cm_done), .tag_o(cm_tag)
  );

  logic [31:0]  seq_fetch_q, seq_data_q;
  logic [2:0]   rq_q;
  logic         wr_q;
  logic [7:0]   ly_q;
  logic [31:0]  ad_q, dt_q, sq_q, ep_q, nc_q;
  logic [127:0] tag_q, rtag_q;
  logic [255:0] rmsg_q;
  logic [7:0]   rstatus_q;
  logic [31:0]  rdata_q;

  function automatic logic [255:0] req_msg(input logic [2:0] rq, input logic wr, input logic [7:0] ly,
                                           input logic [31:0] ad, input logic [31:0] dt, input logic [31:0] sq,
                                           input logic [31:0] ep, input logic [31:0] nc);
    req_msg = {8'hC3, 8'hD1, 5'd0, rq, 7'd0, wr, ly, 24'd0, ad, dt, sq, ep, nc, 32'h56544631};
  endfunction

  // fields of the signed response that must echo the request
  wire fields_match = (rmsg_q[255:240] == 16'hC3D2) && (rmsg_q[239:235] == 5'd0) && (rmsg_q[234:232] == rq_q) &&
                      (rmsg_q[231:225] == 7'd0) && (rmsg_q[207:192] == 16'd0) &&
                      (rmsg_q[224] == wr_q) && (rmsg_q[223:216] == ly_q) &&
                      (rmsg_q[191:160] == ad_q) && (rmsg_q[127:96] == sq_q) &&
                      (rmsg_q[95:64] == ep_q) && (rmsg_q[63:32] == nc_q) &&
                      (rmsg_q[31:0] == 32'h56544632) &&
                      (rmsg_q[215:208] == rstatus_q) && (rmsg_q[159:128] == rdata_q) &&
                      (!wr_q || rdata_q == dt_q);   // a write must echo exactly the written word

  assign cpu_ready_o = (state_q == B_IDLE) && keys_ready_o && !cm_busy;
  assign vtf_req_valid_o     = (state_q == B_SEND);
  assign vtf_req_requester_o = rq_q;
  assign vtf_req_write_o     = wr_q;
  assign vtf_req_layer_o     = ly_q;
  assign vtf_req_addr_o      = ad_q;
  assign vtf_req_data_o      = dt_q;
  assign vtf_req_sequence_o  = sq_q;
  assign vtf_req_epoch_o     = ep_q;
  assign vtf_req_nonce_o     = nc_q;
  assign vtf_req_tag_o       = tag_q;

  always_ff @(posedge clk) begin
    if (!rst_n) begin
      state_q <= B_IDLE;
      seq_fetch_q <= '0; seq_data_q <= '0;
      rq_q <= '0; wr_q <= 1'b0; ly_q <= '0; ad_q <= '0; dt_q <= '0; sq_q <= '0; ep_q <= '0; nc_q <= '0;
      tag_q <= '0; rtag_q <= '0; rmsg_q <= '0; rstatus_q <= '0; rdata_q <= '0;
      cm_start <= 1'b0; cm_key <= '0; cm_k1 <= '0; cm_msg <= '0;
      cpu_rsp_valid_o <= 1'b0; cpu_rsp_ok_o <= 1'b0; cpu_rsp_rdata_o <= '0; tamper_o <= 1'b0;
    end else begin
      cm_start <= 1'b0;
      cpu_rsp_valid_o <= 1'b0;
      unique case (state_q)
        B_IDLE: if (cpu_valid_i && cpu_ready_o) begin
          logic [2:0] rq;
          logic [31:0] sq;
          rq = cpu_fetch_i ? REQ_CPU_FETCH : REQ_CPU_DATA;
          sq = (cpu_fetch_i ? seq_fetch_q : seq_data_q) + 32'd1;
          if (cpu_fetch_i) seq_fetch_q <= sq; else seq_data_q <= sq;
          rq_q <= rq; wr_q <= cpu_write_i && !cpu_fetch_i; ly_q <= cpu_layer_i;
          ad_q <= cpu_addr_i; dt_q <= cpu_write_i ? cpu_wdata_i : 32'd0;
          sq_q <= sq; ep_q <= active_epoch_i; nc_q <= 32'hC0DE0000 ^ {sq[28:0], rq};
          cm_key <= req_key[rq]; cm_k1 <= req_k1[rq];
          cm_msg <= req_msg(rq, cpu_write_i && !cpu_fetch_i, cpu_layer_i, cpu_addr_i,
                            cpu_write_i ? cpu_wdata_i : 32'd0, sq, active_epoch_i,
                            32'hC0DE0000 ^ {sq[28:0], rq});
          cm_start <= 1'b1;
          state_q <= B_SIGN;
        end
        B_SIGN: if (cm_done) begin
          tag_q <= cm_tag;
          state_q <= B_SEND;
        end
        B_SEND: if (vtf_req_ready_i) state_q <= B_WAIT;
        B_WAIT: if (vtf_rsp_valid_i) begin
          rmsg_q <= vtf_rsp_msg_i; rtag_q <= vtf_rsp_tag_i;
          rstatus_q <= vtf_rsp_status_i; rdata_q <= vtf_rsp_data_i;
          cm_key <= rsp_key; cm_k1 <= rsp_k1; cm_msg <= vtf_rsp_msg_i;
          cm_start <= 1'b1;
          state_q <= B_VERIFY;
        end
        B_VERIFY: if (cm_done) begin
          cpu_rsp_valid_o <= 1'b1;
          cpu_rsp_ok_o <= (cm_tag == rtag_q) && fields_match && (rstatus_q == 8'd1);
          cpu_rsp_rdata_o <= ((cm_tag == rtag_q) && fields_match) ? rdata_q : 32'd0;
          if (cm_tag != rtag_q) tamper_o <= 1'b1;
          state_q <= B_DONE;
        end
        B_DONE: state_q <= B_IDLE;
        default: state_q <= B_IDLE;
      endcase
    end
  end
endmodule
