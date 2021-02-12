// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Top module auto-generated by `reggen`

`include "prim_assert.sv"

module spi_device_reg_top (
  input clk_i,
  input rst_ni,

  // Below Regster interface can be changed
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // Output port for window
  output tlul_pkg::tl_h2d_t tl_win_o  [1],
  input  tlul_pkg::tl_d2h_t tl_win_i  [1],

  // To HW
  output spi_device_reg_pkg::spi_device_reg2hw_t reg2hw, // Write
  input  spi_device_reg_pkg::spi_device_hw2reg_t hw2reg, // Read

  // Config
  input devmode_i // If 1, explicit error return for unmapped register access
);

  import spi_device_reg_pkg::* ;

  localparam int AW = 13;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // register signals
  logic           reg_we;
  logic           reg_re;
  logic [AW-1:0]  reg_addr;
  logic [DW-1:0]  reg_wdata;
  logic [DBW-1:0] reg_be;
  logic [DW-1:0]  reg_rdata;
  logic           reg_error;

  logic          addrmiss, wr_err;

  logic [DW-1:0] reg_rdata_next;

  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;

  // incoming payload check
  logic chk_err;
  tlul_payload_chk u_chk (
    .tl_i,
    .err_o(chk_err)
  );

  // outgoing payload generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_gen_payload_chk u_gen_chk (
    .tl_i(tl_o_pre),
    .tl_o
  );

  tlul_pkg::tl_h2d_t tl_socket_h2d [2];
  tlul_pkg::tl_d2h_t tl_socket_d2h [2];

  logic [1:0] reg_steer;

  // socket_1n connection
  assign tl_reg_h2d = tl_socket_h2d[1];
  assign tl_socket_d2h[1] = tl_reg_d2h;

  assign tl_win_o[0] = tl_socket_h2d[0];
  assign tl_socket_d2h[0] = tl_win_i[0];

  // Create Socket_1n
  tlul_socket_1n #(
    .N          (2),
    .HReqPass   (1'b1),
    .HRspPass   (1'b1),
    .DReqPass   ({2{1'b1}}),
    .DRspPass   ({2{1'b1}}),
    .HReqDepth  (4'h0),
    .HRspDepth  (4'h0),
    .DReqDepth  ({2{4'h0}}),
    .DRspDepth  ({2{4'h0}})
  ) u_socket (
    .clk_i,
    .rst_ni,
    .tl_h_i (tl_i),
    .tl_h_o (tl_o_pre),
    .tl_d_o (tl_socket_h2d),
    .tl_d_i (tl_socket_d2h),
    .dev_select_i (reg_steer)
  );

  // Create steering logic
  always_comb begin
    reg_steer = 1;       // Default set to register

    // TODO: Can below codes be unique case () inside ?
    if (tl_i.a_address[AW-1:0] >= 4096) begin
      // Exceed or meet the address range. Removed the comparison of limit addr 'h 2000
      reg_steer = 0;
    end
    if (chk_err) begin
      reg_steer = 1;
    end
  end

  tlul_adapter_reg #(
    .RegAw(AW),
    .RegDw(DW)
  ) u_reg_if (
    .clk_i,
    .rst_ni,

    .tl_i (tl_reg_h2d),
    .tl_o (tl_reg_d2h),

    .we_o    (reg_we),
    .re_o    (reg_re),
    .addr_o  (reg_addr),
    .wdata_o (reg_wdata),
    .be_o    (reg_be),
    .rdata_i (reg_rdata),
    .error_i (reg_error)
  );

  assign reg_rdata = reg_rdata_next ;
  assign reg_error = (devmode_i & addrmiss) | wr_err | chk_err;

  // Define SW related signals
  // Format: <reg>_<field>_{wd|we|qs}
  //        or <reg>_{wd|we|qs} if field == 1 or 0
  logic intr_state_rxf_qs;
  logic intr_state_rxf_wd;
  logic intr_state_rxf_we;
  logic intr_state_rxlvl_qs;
  logic intr_state_rxlvl_wd;
  logic intr_state_rxlvl_we;
  logic intr_state_txlvl_qs;
  logic intr_state_txlvl_wd;
  logic intr_state_txlvl_we;
  logic intr_state_rxerr_qs;
  logic intr_state_rxerr_wd;
  logic intr_state_rxerr_we;
  logic intr_state_rxoverflow_qs;
  logic intr_state_rxoverflow_wd;
  logic intr_state_rxoverflow_we;
  logic intr_state_txunderflow_qs;
  logic intr_state_txunderflow_wd;
  logic intr_state_txunderflow_we;
  logic intr_enable_rxf_qs;
  logic intr_enable_rxf_wd;
  logic intr_enable_rxf_we;
  logic intr_enable_rxlvl_qs;
  logic intr_enable_rxlvl_wd;
  logic intr_enable_rxlvl_we;
  logic intr_enable_txlvl_qs;
  logic intr_enable_txlvl_wd;
  logic intr_enable_txlvl_we;
  logic intr_enable_rxerr_qs;
  logic intr_enable_rxerr_wd;
  logic intr_enable_rxerr_we;
  logic intr_enable_rxoverflow_qs;
  logic intr_enable_rxoverflow_wd;
  logic intr_enable_rxoverflow_we;
  logic intr_enable_txunderflow_qs;
  logic intr_enable_txunderflow_wd;
  logic intr_enable_txunderflow_we;
  logic intr_test_rxf_wd;
  logic intr_test_rxf_we;
  logic intr_test_rxlvl_wd;
  logic intr_test_rxlvl_we;
  logic intr_test_txlvl_wd;
  logic intr_test_txlvl_we;
  logic intr_test_rxerr_wd;
  logic intr_test_rxerr_we;
  logic intr_test_rxoverflow_wd;
  logic intr_test_rxoverflow_we;
  logic intr_test_txunderflow_wd;
  logic intr_test_txunderflow_we;
  logic control_abort_qs;
  logic control_abort_wd;
  logic control_abort_we;
  logic [1:0] control_mode_qs;
  logic [1:0] control_mode_wd;
  logic control_mode_we;
  logic control_rst_txfifo_qs;
  logic control_rst_txfifo_wd;
  logic control_rst_txfifo_we;
  logic control_rst_rxfifo_qs;
  logic control_rst_rxfifo_wd;
  logic control_rst_rxfifo_we;
  logic cfg_cpol_qs;
  logic cfg_cpol_wd;
  logic cfg_cpol_we;
  logic cfg_cpha_qs;
  logic cfg_cpha_wd;
  logic cfg_cpha_we;
  logic cfg_tx_order_qs;
  logic cfg_tx_order_wd;
  logic cfg_tx_order_we;
  logic cfg_rx_order_qs;
  logic cfg_rx_order_wd;
  logic cfg_rx_order_we;
  logic [7:0] cfg_timer_v_qs;
  logic [7:0] cfg_timer_v_wd;
  logic cfg_timer_v_we;
  logic [15:0] fifo_level_rxlvl_qs;
  logic [15:0] fifo_level_rxlvl_wd;
  logic fifo_level_rxlvl_we;
  logic [15:0] fifo_level_txlvl_qs;
  logic [15:0] fifo_level_txlvl_wd;
  logic fifo_level_txlvl_we;
  logic [7:0] async_fifo_level_rxlvl_qs;
  logic async_fifo_level_rxlvl_re;
  logic [7:0] async_fifo_level_txlvl_qs;
  logic async_fifo_level_txlvl_re;
  logic status_rxf_full_qs;
  logic status_rxf_full_re;
  logic status_rxf_empty_qs;
  logic status_rxf_empty_re;
  logic status_txf_full_qs;
  logic status_txf_full_re;
  logic status_txf_empty_qs;
  logic status_txf_empty_re;
  logic status_abort_done_qs;
  logic status_abort_done_re;
  logic status_csb_qs;
  logic status_csb_re;
  logic [15:0] rxf_ptr_rptr_qs;
  logic [15:0] rxf_ptr_rptr_wd;
  logic rxf_ptr_rptr_we;
  logic [15:0] rxf_ptr_wptr_qs;
  logic [15:0] txf_ptr_rptr_qs;
  logic [15:0] txf_ptr_wptr_qs;
  logic [15:0] txf_ptr_wptr_wd;
  logic txf_ptr_wptr_we;
  logic [15:0] rxf_addr_base_qs;
  logic [15:0] rxf_addr_base_wd;
  logic rxf_addr_base_we;
  logic [15:0] rxf_addr_limit_qs;
  logic [15:0] rxf_addr_limit_wd;
  logic rxf_addr_limit_we;
  logic [15:0] txf_addr_base_qs;
  logic [15:0] txf_addr_base_wd;
  logic txf_addr_base_we;
  logic [15:0] txf_addr_limit_qs;
  logic [15:0] txf_addr_limit_wd;
  logic txf_addr_limit_we;

  // Register instances
  // R[intr_state]: V(False)

  //   F[rxf]: 0:0
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_rxf (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_rxf_we),
    .wd     (intr_state_rxf_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.rxf.de),
    .d      (hw2reg.intr_state.rxf.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.rxf.q ),

    // to register interface (read)
    .qs     (intr_state_rxf_qs)
  );


  //   F[rxlvl]: 1:1
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_rxlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_rxlvl_we),
    .wd     (intr_state_rxlvl_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.rxlvl.de),
    .d      (hw2reg.intr_state.rxlvl.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.rxlvl.q ),

    // to register interface (read)
    .qs     (intr_state_rxlvl_qs)
  );


  //   F[txlvl]: 2:2
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_txlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_txlvl_we),
    .wd     (intr_state_txlvl_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.txlvl.de),
    .d      (hw2reg.intr_state.txlvl.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.txlvl.q ),

    // to register interface (read)
    .qs     (intr_state_txlvl_qs)
  );


  //   F[rxerr]: 3:3
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_rxerr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_rxerr_we),
    .wd     (intr_state_rxerr_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.rxerr.de),
    .d      (hw2reg.intr_state.rxerr.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.rxerr.q ),

    // to register interface (read)
    .qs     (intr_state_rxerr_qs)
  );


  //   F[rxoverflow]: 4:4
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_rxoverflow (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_rxoverflow_we),
    .wd     (intr_state_rxoverflow_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.rxoverflow.de),
    .d      (hw2reg.intr_state.rxoverflow.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.rxoverflow.q ),

    // to register interface (read)
    .qs     (intr_state_rxoverflow_qs)
  );


  //   F[txunderflow]: 5:5
  prim_subreg #(
    .DW      (1),
    .SWACCESS("W1C"),
    .RESVAL  (1'h0)
  ) u_intr_state_txunderflow (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_state_txunderflow_we),
    .wd     (intr_state_txunderflow_wd),

    // from internal hardware
    .de     (hw2reg.intr_state.txunderflow.de),
    .d      (hw2reg.intr_state.txunderflow.d ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_state.txunderflow.q ),

    // to register interface (read)
    .qs     (intr_state_txunderflow_qs)
  );


  // R[intr_enable]: V(False)

  //   F[rxf]: 0:0
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_rxf (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_rxf_we),
    .wd     (intr_enable_rxf_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.rxf.q ),

    // to register interface (read)
    .qs     (intr_enable_rxf_qs)
  );


  //   F[rxlvl]: 1:1
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_rxlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_rxlvl_we),
    .wd     (intr_enable_rxlvl_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.rxlvl.q ),

    // to register interface (read)
    .qs     (intr_enable_rxlvl_qs)
  );


  //   F[txlvl]: 2:2
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_txlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_txlvl_we),
    .wd     (intr_enable_txlvl_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.txlvl.q ),

    // to register interface (read)
    .qs     (intr_enable_txlvl_qs)
  );


  //   F[rxerr]: 3:3
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_rxerr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_rxerr_we),
    .wd     (intr_enable_rxerr_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.rxerr.q ),

    // to register interface (read)
    .qs     (intr_enable_rxerr_qs)
  );


  //   F[rxoverflow]: 4:4
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_rxoverflow (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_rxoverflow_we),
    .wd     (intr_enable_rxoverflow_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.rxoverflow.q ),

    // to register interface (read)
    .qs     (intr_enable_rxoverflow_qs)
  );


  //   F[txunderflow]: 5:5
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_intr_enable_txunderflow (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (intr_enable_txunderflow_we),
    .wd     (intr_enable_txunderflow_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.intr_enable.txunderflow.q ),

    // to register interface (read)
    .qs     (intr_enable_txunderflow_qs)
  );


  // R[intr_test]: V(True)

  //   F[rxf]: 0:0
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_rxf (
    .re     (1'b0),
    .we     (intr_test_rxf_we),
    .wd     (intr_test_rxf_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.rxf.qe),
    .q      (reg2hw.intr_test.rxf.q ),
    .qs     ()
  );


  //   F[rxlvl]: 1:1
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_rxlvl (
    .re     (1'b0),
    .we     (intr_test_rxlvl_we),
    .wd     (intr_test_rxlvl_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.rxlvl.qe),
    .q      (reg2hw.intr_test.rxlvl.q ),
    .qs     ()
  );


  //   F[txlvl]: 2:2
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_txlvl (
    .re     (1'b0),
    .we     (intr_test_txlvl_we),
    .wd     (intr_test_txlvl_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.txlvl.qe),
    .q      (reg2hw.intr_test.txlvl.q ),
    .qs     ()
  );


  //   F[rxerr]: 3:3
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_rxerr (
    .re     (1'b0),
    .we     (intr_test_rxerr_we),
    .wd     (intr_test_rxerr_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.rxerr.qe),
    .q      (reg2hw.intr_test.rxerr.q ),
    .qs     ()
  );


  //   F[rxoverflow]: 4:4
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_rxoverflow (
    .re     (1'b0),
    .we     (intr_test_rxoverflow_we),
    .wd     (intr_test_rxoverflow_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.rxoverflow.qe),
    .q      (reg2hw.intr_test.rxoverflow.q ),
    .qs     ()
  );


  //   F[txunderflow]: 5:5
  prim_subreg_ext #(
    .DW    (1)
  ) u_intr_test_txunderflow (
    .re     (1'b0),
    .we     (intr_test_txunderflow_we),
    .wd     (intr_test_txunderflow_wd),
    .d      ('0),
    .qre    (),
    .qe     (reg2hw.intr_test.txunderflow.qe),
    .q      (reg2hw.intr_test.txunderflow.q ),
    .qs     ()
  );


  // R[control]: V(False)

  //   F[abort]: 0:0
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_control_abort (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (control_abort_we),
    .wd     (control_abort_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.control.abort.q ),

    // to register interface (read)
    .qs     (control_abort_qs)
  );


  //   F[mode]: 5:4
  prim_subreg #(
    .DW      (2),
    .SWACCESS("RW"),
    .RESVAL  (2'h0)
  ) u_control_mode (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (control_mode_we),
    .wd     (control_mode_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.control.mode.q ),

    // to register interface (read)
    .qs     (control_mode_qs)
  );


  //   F[rst_txfifo]: 16:16
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_control_rst_txfifo (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (control_rst_txfifo_we),
    .wd     (control_rst_txfifo_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.control.rst_txfifo.q ),

    // to register interface (read)
    .qs     (control_rst_txfifo_qs)
  );


  //   F[rst_rxfifo]: 17:17
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_control_rst_rxfifo (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (control_rst_rxfifo_we),
    .wd     (control_rst_rxfifo_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.control.rst_rxfifo.q ),

    // to register interface (read)
    .qs     (control_rst_rxfifo_qs)
  );


  // R[cfg]: V(False)

  //   F[cpol]: 0:0
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_cfg_cpol (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (cfg_cpol_we),
    .wd     (cfg_cpol_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.cfg.cpol.q ),

    // to register interface (read)
    .qs     (cfg_cpol_qs)
  );


  //   F[cpha]: 1:1
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_cfg_cpha (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (cfg_cpha_we),
    .wd     (cfg_cpha_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.cfg.cpha.q ),

    // to register interface (read)
    .qs     (cfg_cpha_qs)
  );


  //   F[tx_order]: 2:2
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_cfg_tx_order (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (cfg_tx_order_we),
    .wd     (cfg_tx_order_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.cfg.tx_order.q ),

    // to register interface (read)
    .qs     (cfg_tx_order_qs)
  );


  //   F[rx_order]: 3:3
  prim_subreg #(
    .DW      (1),
    .SWACCESS("RW"),
    .RESVAL  (1'h0)
  ) u_cfg_rx_order (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (cfg_rx_order_we),
    .wd     (cfg_rx_order_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.cfg.rx_order.q ),

    // to register interface (read)
    .qs     (cfg_rx_order_qs)
  );


  //   F[timer_v]: 15:8
  prim_subreg #(
    .DW      (8),
    .SWACCESS("RW"),
    .RESVAL  (8'h7f)
  ) u_cfg_timer_v (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (cfg_timer_v_we),
    .wd     (cfg_timer_v_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.cfg.timer_v.q ),

    // to register interface (read)
    .qs     (cfg_timer_v_qs)
  );


  // R[fifo_level]: V(False)

  //   F[rxlvl]: 15:0
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h80)
  ) u_fifo_level_rxlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (fifo_level_rxlvl_we),
    .wd     (fifo_level_rxlvl_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.fifo_level.rxlvl.q ),

    // to register interface (read)
    .qs     (fifo_level_rxlvl_qs)
  );


  //   F[txlvl]: 31:16
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h0)
  ) u_fifo_level_txlvl (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (fifo_level_txlvl_we),
    .wd     (fifo_level_txlvl_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.fifo_level.txlvl.q ),

    // to register interface (read)
    .qs     (fifo_level_txlvl_qs)
  );


  // R[async_fifo_level]: V(True)

  //   F[rxlvl]: 7:0
  prim_subreg_ext #(
    .DW    (8)
  ) u_async_fifo_level_rxlvl (
    .re     (async_fifo_level_rxlvl_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.async_fifo_level.rxlvl.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (async_fifo_level_rxlvl_qs)
  );


  //   F[txlvl]: 23:16
  prim_subreg_ext #(
    .DW    (8)
  ) u_async_fifo_level_txlvl (
    .re     (async_fifo_level_txlvl_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.async_fifo_level.txlvl.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (async_fifo_level_txlvl_qs)
  );


  // R[status]: V(True)

  //   F[rxf_full]: 0:0
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_rxf_full (
    .re     (status_rxf_full_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.rxf_full.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_rxf_full_qs)
  );


  //   F[rxf_empty]: 1:1
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_rxf_empty (
    .re     (status_rxf_empty_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.rxf_empty.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_rxf_empty_qs)
  );


  //   F[txf_full]: 2:2
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_txf_full (
    .re     (status_txf_full_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.txf_full.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_txf_full_qs)
  );


  //   F[txf_empty]: 3:3
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_txf_empty (
    .re     (status_txf_empty_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.txf_empty.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_txf_empty_qs)
  );


  //   F[abort_done]: 4:4
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_abort_done (
    .re     (status_abort_done_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.abort_done.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_abort_done_qs)
  );


  //   F[csb]: 5:5
  prim_subreg_ext #(
    .DW    (1)
  ) u_status_csb (
    .re     (status_csb_re),
    .we     (1'b0),
    .wd     ('0),
    .d      (hw2reg.status.csb.d),
    .qre    (),
    .qe     (),
    .q      (),
    .qs     (status_csb_qs)
  );


  // R[rxf_ptr]: V(False)

  //   F[rptr]: 15:0
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h0)
  ) u_rxf_ptr_rptr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (rxf_ptr_rptr_we),
    .wd     (rxf_ptr_rptr_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rxf_ptr.rptr.q ),

    // to register interface (read)
    .qs     (rxf_ptr_rptr_qs)
  );


  //   F[wptr]: 31:16
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RO"),
    .RESVAL  (16'h0)
  ) u_rxf_ptr_wptr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    .we     (1'b0),
    .wd     ('0  ),

    // from internal hardware
    .de     (hw2reg.rxf_ptr.wptr.de),
    .d      (hw2reg.rxf_ptr.wptr.d ),

    // to internal hardware
    .qe     (),
    .q      (),

    // to register interface (read)
    .qs     (rxf_ptr_wptr_qs)
  );


  // R[txf_ptr]: V(False)

  //   F[rptr]: 15:0
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RO"),
    .RESVAL  (16'h0)
  ) u_txf_ptr_rptr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    .we     (1'b0),
    .wd     ('0  ),

    // from internal hardware
    .de     (hw2reg.txf_ptr.rptr.de),
    .d      (hw2reg.txf_ptr.rptr.d ),

    // to internal hardware
    .qe     (),
    .q      (),

    // to register interface (read)
    .qs     (txf_ptr_rptr_qs)
  );


  //   F[wptr]: 31:16
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h0)
  ) u_txf_ptr_wptr (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (txf_ptr_wptr_we),
    .wd     (txf_ptr_wptr_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.txf_ptr.wptr.q ),

    // to register interface (read)
    .qs     (txf_ptr_wptr_qs)
  );


  // R[rxf_addr]: V(False)

  //   F[base]: 15:0
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h0)
  ) u_rxf_addr_base (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (rxf_addr_base_we),
    .wd     (rxf_addr_base_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rxf_addr.base.q ),

    // to register interface (read)
    .qs     (rxf_addr_base_qs)
  );


  //   F[limit]: 31:16
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h1fc)
  ) u_rxf_addr_limit (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (rxf_addr_limit_we),
    .wd     (rxf_addr_limit_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rxf_addr.limit.q ),

    // to register interface (read)
    .qs     (rxf_addr_limit_qs)
  );


  // R[txf_addr]: V(False)

  //   F[base]: 15:0
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h200)
  ) u_txf_addr_base (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (txf_addr_base_we),
    .wd     (txf_addr_base_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.txf_addr.base.q ),

    // to register interface (read)
    .qs     (txf_addr_base_qs)
  );


  //   F[limit]: 31:16
  prim_subreg #(
    .DW      (16),
    .SWACCESS("RW"),
    .RESVAL  (16'h3fc)
  ) u_txf_addr_limit (
    .clk_i   (clk_i    ),
    .rst_ni  (rst_ni  ),

    // from register interface
    .we     (txf_addr_limit_we),
    .wd     (txf_addr_limit_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0  ),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.txf_addr.limit.q ),

    // to register interface (read)
    .qs     (txf_addr_limit_qs)
  );




  logic [11:0] addr_hit;
  always_comb begin
    addr_hit = '0;
    addr_hit[ 0] = (reg_addr == SPI_DEVICE_INTR_STATE_OFFSET);
    addr_hit[ 1] = (reg_addr == SPI_DEVICE_INTR_ENABLE_OFFSET);
    addr_hit[ 2] = (reg_addr == SPI_DEVICE_INTR_TEST_OFFSET);
    addr_hit[ 3] = (reg_addr == SPI_DEVICE_CONTROL_OFFSET);
    addr_hit[ 4] = (reg_addr == SPI_DEVICE_CFG_OFFSET);
    addr_hit[ 5] = (reg_addr == SPI_DEVICE_FIFO_LEVEL_OFFSET);
    addr_hit[ 6] = (reg_addr == SPI_DEVICE_ASYNC_FIFO_LEVEL_OFFSET);
    addr_hit[ 7] = (reg_addr == SPI_DEVICE_STATUS_OFFSET);
    addr_hit[ 8] = (reg_addr == SPI_DEVICE_RXF_PTR_OFFSET);
    addr_hit[ 9] = (reg_addr == SPI_DEVICE_TXF_PTR_OFFSET);
    addr_hit[10] = (reg_addr == SPI_DEVICE_RXF_ADDR_OFFSET);
    addr_hit[11] = (reg_addr == SPI_DEVICE_TXF_ADDR_OFFSET);
  end

  assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;

  // Check sub-word write is permitted
  always_comb begin
    wr_err = 1'b0;
    if (addr_hit[ 0] && reg_we && (SPI_DEVICE_PERMIT[ 0] != (SPI_DEVICE_PERMIT[ 0] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 1] && reg_we && (SPI_DEVICE_PERMIT[ 1] != (SPI_DEVICE_PERMIT[ 1] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 2] && reg_we && (SPI_DEVICE_PERMIT[ 2] != (SPI_DEVICE_PERMIT[ 2] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 3] && reg_we && (SPI_DEVICE_PERMIT[ 3] != (SPI_DEVICE_PERMIT[ 3] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 4] && reg_we && (SPI_DEVICE_PERMIT[ 4] != (SPI_DEVICE_PERMIT[ 4] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 5] && reg_we && (SPI_DEVICE_PERMIT[ 5] != (SPI_DEVICE_PERMIT[ 5] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 6] && reg_we && (SPI_DEVICE_PERMIT[ 6] != (SPI_DEVICE_PERMIT[ 6] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 7] && reg_we && (SPI_DEVICE_PERMIT[ 7] != (SPI_DEVICE_PERMIT[ 7] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 8] && reg_we && (SPI_DEVICE_PERMIT[ 8] != (SPI_DEVICE_PERMIT[ 8] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[ 9] && reg_we && (SPI_DEVICE_PERMIT[ 9] != (SPI_DEVICE_PERMIT[ 9] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[10] && reg_we && (SPI_DEVICE_PERMIT[10] != (SPI_DEVICE_PERMIT[10] & reg_be))) wr_err = 1'b1 ;
    if (addr_hit[11] && reg_we && (SPI_DEVICE_PERMIT[11] != (SPI_DEVICE_PERMIT[11] & reg_be))) wr_err = 1'b1 ;
  end

  assign intr_state_rxf_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_rxf_wd = reg_wdata[0];

  assign intr_state_rxlvl_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_rxlvl_wd = reg_wdata[1];

  assign intr_state_txlvl_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_txlvl_wd = reg_wdata[2];

  assign intr_state_rxerr_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_rxerr_wd = reg_wdata[3];

  assign intr_state_rxoverflow_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_rxoverflow_wd = reg_wdata[4];

  assign intr_state_txunderflow_we = addr_hit[0] & reg_we & ~wr_err;
  assign intr_state_txunderflow_wd = reg_wdata[5];

  assign intr_enable_rxf_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_rxf_wd = reg_wdata[0];

  assign intr_enable_rxlvl_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_rxlvl_wd = reg_wdata[1];

  assign intr_enable_txlvl_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_txlvl_wd = reg_wdata[2];

  assign intr_enable_rxerr_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_rxerr_wd = reg_wdata[3];

  assign intr_enable_rxoverflow_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_rxoverflow_wd = reg_wdata[4];

  assign intr_enable_txunderflow_we = addr_hit[1] & reg_we & ~wr_err;
  assign intr_enable_txunderflow_wd = reg_wdata[5];

  assign intr_test_rxf_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_rxf_wd = reg_wdata[0];

  assign intr_test_rxlvl_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_rxlvl_wd = reg_wdata[1];

  assign intr_test_txlvl_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_txlvl_wd = reg_wdata[2];

  assign intr_test_rxerr_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_rxerr_wd = reg_wdata[3];

  assign intr_test_rxoverflow_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_rxoverflow_wd = reg_wdata[4];

  assign intr_test_txunderflow_we = addr_hit[2] & reg_we & ~wr_err;
  assign intr_test_txunderflow_wd = reg_wdata[5];

  assign control_abort_we = addr_hit[3] & reg_we & ~wr_err;
  assign control_abort_wd = reg_wdata[0];

  assign control_mode_we = addr_hit[3] & reg_we & ~wr_err;
  assign control_mode_wd = reg_wdata[5:4];

  assign control_rst_txfifo_we = addr_hit[3] & reg_we & ~wr_err;
  assign control_rst_txfifo_wd = reg_wdata[16];

  assign control_rst_rxfifo_we = addr_hit[3] & reg_we & ~wr_err;
  assign control_rst_rxfifo_wd = reg_wdata[17];

  assign cfg_cpol_we = addr_hit[4] & reg_we & ~wr_err;
  assign cfg_cpol_wd = reg_wdata[0];

  assign cfg_cpha_we = addr_hit[4] & reg_we & ~wr_err;
  assign cfg_cpha_wd = reg_wdata[1];

  assign cfg_tx_order_we = addr_hit[4] & reg_we & ~wr_err;
  assign cfg_tx_order_wd = reg_wdata[2];

  assign cfg_rx_order_we = addr_hit[4] & reg_we & ~wr_err;
  assign cfg_rx_order_wd = reg_wdata[3];

  assign cfg_timer_v_we = addr_hit[4] & reg_we & ~wr_err;
  assign cfg_timer_v_wd = reg_wdata[15:8];

  assign fifo_level_rxlvl_we = addr_hit[5] & reg_we & ~wr_err;
  assign fifo_level_rxlvl_wd = reg_wdata[15:0];

  assign fifo_level_txlvl_we = addr_hit[5] & reg_we & ~wr_err;
  assign fifo_level_txlvl_wd = reg_wdata[31:16];

  assign async_fifo_level_rxlvl_re = addr_hit[6] && reg_re;

  assign async_fifo_level_txlvl_re = addr_hit[6] && reg_re;

  assign status_rxf_full_re = addr_hit[7] && reg_re;

  assign status_rxf_empty_re = addr_hit[7] && reg_re;

  assign status_txf_full_re = addr_hit[7] && reg_re;

  assign status_txf_empty_re = addr_hit[7] && reg_re;

  assign status_abort_done_re = addr_hit[7] && reg_re;

  assign status_csb_re = addr_hit[7] && reg_re;

  assign rxf_ptr_rptr_we = addr_hit[8] & reg_we & ~wr_err;
  assign rxf_ptr_rptr_wd = reg_wdata[15:0];



  assign txf_ptr_wptr_we = addr_hit[9] & reg_we & ~wr_err;
  assign txf_ptr_wptr_wd = reg_wdata[31:16];

  assign rxf_addr_base_we = addr_hit[10] & reg_we & ~wr_err;
  assign rxf_addr_base_wd = reg_wdata[15:0];

  assign rxf_addr_limit_we = addr_hit[10] & reg_we & ~wr_err;
  assign rxf_addr_limit_wd = reg_wdata[31:16];

  assign txf_addr_base_we = addr_hit[11] & reg_we & ~wr_err;
  assign txf_addr_base_wd = reg_wdata[15:0];

  assign txf_addr_limit_we = addr_hit[11] & reg_we & ~wr_err;
  assign txf_addr_limit_wd = reg_wdata[31:16];

  // Read data return
  always_comb begin
    reg_rdata_next = '0;
    unique case (1'b1)
      addr_hit[0]: begin
        reg_rdata_next[0] = intr_state_rxf_qs;
        reg_rdata_next[1] = intr_state_rxlvl_qs;
        reg_rdata_next[2] = intr_state_txlvl_qs;
        reg_rdata_next[3] = intr_state_rxerr_qs;
        reg_rdata_next[4] = intr_state_rxoverflow_qs;
        reg_rdata_next[5] = intr_state_txunderflow_qs;
      end

      addr_hit[1]: begin
        reg_rdata_next[0] = intr_enable_rxf_qs;
        reg_rdata_next[1] = intr_enable_rxlvl_qs;
        reg_rdata_next[2] = intr_enable_txlvl_qs;
        reg_rdata_next[3] = intr_enable_rxerr_qs;
        reg_rdata_next[4] = intr_enable_rxoverflow_qs;
        reg_rdata_next[5] = intr_enable_txunderflow_qs;
      end

      addr_hit[2]: begin
        reg_rdata_next[0] = '0;
        reg_rdata_next[1] = '0;
        reg_rdata_next[2] = '0;
        reg_rdata_next[3] = '0;
        reg_rdata_next[4] = '0;
        reg_rdata_next[5] = '0;
      end

      addr_hit[3]: begin
        reg_rdata_next[0] = control_abort_qs;
        reg_rdata_next[5:4] = control_mode_qs;
        reg_rdata_next[16] = control_rst_txfifo_qs;
        reg_rdata_next[17] = control_rst_rxfifo_qs;
      end

      addr_hit[4]: begin
        reg_rdata_next[0] = cfg_cpol_qs;
        reg_rdata_next[1] = cfg_cpha_qs;
        reg_rdata_next[2] = cfg_tx_order_qs;
        reg_rdata_next[3] = cfg_rx_order_qs;
        reg_rdata_next[15:8] = cfg_timer_v_qs;
      end

      addr_hit[5]: begin
        reg_rdata_next[15:0] = fifo_level_rxlvl_qs;
        reg_rdata_next[31:16] = fifo_level_txlvl_qs;
      end

      addr_hit[6]: begin
        reg_rdata_next[7:0] = async_fifo_level_rxlvl_qs;
        reg_rdata_next[23:16] = async_fifo_level_txlvl_qs;
      end

      addr_hit[7]: begin
        reg_rdata_next[0] = status_rxf_full_qs;
        reg_rdata_next[1] = status_rxf_empty_qs;
        reg_rdata_next[2] = status_txf_full_qs;
        reg_rdata_next[3] = status_txf_empty_qs;
        reg_rdata_next[4] = status_abort_done_qs;
        reg_rdata_next[5] = status_csb_qs;
      end

      addr_hit[8]: begin
        reg_rdata_next[15:0] = rxf_ptr_rptr_qs;
        reg_rdata_next[31:16] = rxf_ptr_wptr_qs;
      end

      addr_hit[9]: begin
        reg_rdata_next[15:0] = txf_ptr_rptr_qs;
        reg_rdata_next[31:16] = txf_ptr_wptr_qs;
      end

      addr_hit[10]: begin
        reg_rdata_next[15:0] = rxf_addr_base_qs;
        reg_rdata_next[31:16] = rxf_addr_limit_qs;
      end

      addr_hit[11]: begin
        reg_rdata_next[15:0] = txf_addr_base_qs;
        reg_rdata_next[31:16] = txf_addr_limit_qs;
      end

      default: begin
        reg_rdata_next = '1;
      end
    endcase
  end

  // Unused signal tieoff

  // wdata / byte enable are not always fully used
  // add a blanket unused statement to handle lint waivers
  logic unused_wdata;
  logic unused_be;
  assign unused_wdata = ^reg_wdata;
  assign unused_be = ^reg_be;

  // Assertions for Register Interface
  `ASSERT_PULSE(wePulse, reg_we)
  `ASSERT_PULSE(rePulse, reg_re)

  `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o.d_valid)

  `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit))

  // this is formulated as an assumption such that the FPV testbenches do disprove this
  // property by mistake
  //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)

endmodule
