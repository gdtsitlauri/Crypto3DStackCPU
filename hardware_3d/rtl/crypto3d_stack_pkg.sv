// SPDX-License-Identifier: MIT
// Crypto3DStackCPU 3D stacked memory package.
// Behavioral hardware package for future RTL/fabrication-oriented work.
// This is not a foundry PDK-bound memory macro.

package crypto3d_stack_pkg;

  parameter int C3D_LAYERS      = 4;
  parameter int C3D_WORDS       = 1024;
  parameter int C3D_WORD_WIDTH  = 32;
  parameter int C3D_ADDR_WIDTH  = 10;
  parameter int C3D_LAYER_WIDTH = 2;
  parameter int C3D_BLOCK_WORDS = 4;

  typedef logic [C3D_WORD_WIDTH-1:0]  c3d_word_t;
  typedef logic [C3D_ADDR_WIDTH-1:0]  c3d_addr_t;
  typedef logic [C3D_LAYER_WIDTH-1:0] c3d_layer_t;

  typedef struct packed {
    c3d_layer_t layer;
    c3d_addr_t  addr;
    c3d_word_t  wdata;
    logic       ren;
    logic       wen;
  } c3d_mem_req_t;

  typedef struct packed {
    c3d_word_t rdata;
    logic      ready;
    logic      denied;
    logic      tamper;
  } c3d_mem_rsp_t;

  typedef enum logic [2:0] {
    C3D_LAYER_ROLE_EXEC        = 3'd0,
    C3D_LAYER_ROLE_DATA        = 3'd1,
    C3D_LAYER_ROLE_KEY_HIDE    = 3'd2,
    C3D_LAYER_ROLE_SENTINEL    = 3'd3,
    C3D_LAYER_ROLE_RESERVED    = 3'd7
  } c3d_layer_role_t;

endpackage
