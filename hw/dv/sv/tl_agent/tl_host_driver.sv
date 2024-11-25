// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//

// ---------------------------------------------
// TileLink host driver
// ---------------------------------------------
class tl_host_driver extends tl_base_driver;

  tl_seq_item pending_a_req[$];
  bit reset_asserted;

  `uvm_component_utils(tl_host_driver)
  `uvm_component_new

  virtual task get_and_drive();
    // Wait for initial reset to pass.
    @(cfg.vif.host_cb);
    cfg.vif.axi_wr_req <= 0;
    cfg.vif.axi_rd_req <= 0;
    wait(cfg.vif.rst_n === 1'b1);
    @(cfg.vif.host_cb);
    fork
      begin : process_seq_item
        forever begin
          seq_item_port.try_next_item(req);
          if (req != null) begin
            // send_a_channel_request(req);
            send_axi_req(req);
          end else begin
            if (reset_asserted) flush_during_reset();
            if (!reset_asserted) begin
              `DV_SPINWAIT_EXIT(@(cfg.vif.host_cb);,
                                wait(reset_asserted);)
            end
          end // req != null
        end // forever
      end : process_seq_item
      // d_channel_thread();
      // d_ready_rsp();
      // axi_rd_in_TOOUT_rsp_thread();
      // axi_wr_in_rsp_thread();
    join_none
  endtask

  // keep flushing items when reset is asserted
  virtual task flush_during_reset();
    `DV_SPINWAIT_EXIT(
                      forever begin
                        seq_item_port.get_next_item(req);
                        send_a_channel_request(req);
                      end,
                      wait(!reset_asserted);)
  endtask

  // reset axi signals  
  virtual task reset_axi_signals();
    cfg.vif.axi_wr_req.awvalid <= 1'b0;
    cfg.vif.axi_wr_req.wvalid <= 1'b0;
    cfg.vif.axi_wr_req.bready <= 1'b0;
    cfg.vif.axi_rd_req.arvalid <= 1'b0;
    cfg.vif.axi_rd_req.rready <= 1'b0;
  endtask

  // Send request on AXI WR channel
  virtual task send_wr_channel_request(tl_seq_item req);
    `uvm_info(get_full_name(), $sformatf("WR Req %0s", req.convert2string()), UVM_NONE)
    drive_axi_wr_transaction(req);
  endtask : send_wr_channel_request 

  // Send request on AXI RD channel
  virtual task send_rd_channel_request(tl_seq_item req);
    `uvm_info(get_full_name(), $sformatf("RD Req %0s", req.convert2string()), UVM_NONE)
    drive_axi_read_transaction(req);
  endtask : send_rd_channel_request

  virtual task drive_axi_read_transaction(tl_seq_item req);
    begin
      pending_a_req.push_back(req);
      // preparing response
      @(cfg.vif.rd_cb);
      // driving read req
      `uvm_info(get_full_name(), $sformatf("RD req %0s", req.convert2string()), UVM_NONE)

      // Drive address channel
      cfg.vif.axi_rd_req.arvalid <= 1'b1;
      cfg.vif.axi_rd_req.araddr  <= req.a_addr;
      cfg.vif.axi_rd_req.arid    <= req.a_source;
      cfg.vif.axi_rd_req.arsize  <= req.a_size;
      cfg.vif.axi_rd_req.arburst <= 2'b01;   // Incremental burst, can adjust based on your design
      cfg.vif.axi_rd_req.aruser  <= {1'b0, req.a_mask, req.a_user[17:0]};
      cfg.vif.axi_rd_req.arlock  <= 1'b0;
      cfg.vif.axi_rd_req.arlen   <= 8'h0;    // Single beat read transaction

      // driving wstb to zero for read
      cfg.vif.axi_wr_req.wstrb   <= 4'b0000;
      cfg.vif.axi_wr_req.wdata   <= 32'h0;

      // Wait until slave accepts the address phase
      @(cfg.vif.rd_cb);
      while (!cfg.vif.axi_rd_rsp.arready) @(cfg.vif.rd_cb);
      cfg.vif.axi_rd_req.arvalid <= 1'b0;

      // Drive data phase (assuming a single beat read transaction here)
      cfg.vif.axi_rd_req.rready <= 1'b1;
      while (!cfg.vif.axi_rd_rsp.rvalid) @(cfg.vif.rd_cb); 

      req.req_completed <= 1'b1;
      req.d_data   <= cfg.vif.axi_rd_rsp.rdata;
      req.d_error  <= ( cfg.vif.axi_rd_rsp.rresp == 0 ? 0 : 1 );
      req.d_source <= req.a_source;
      req.d_size   <= req.a_size;
      req.d_user   <= req.a_user;
      req.d_sink   <= 0;
      req.d_param  <= 0;
      req.d_opcode <= tlul_pkg::tl_d_op_e'(AccessAckData);
      
      // Wait until slave accepts the read response
      @(cfg.vif.rd_cb);
      cfg.vif.axi_rd_req.rready <= 1'b0;
      
      @(cfg.vif.rd_cb);
      req.rsp_completed = !reset_asserted;
      seq_item_port.put_response(req);
      `uvm_info(get_full_name(), $sformatf("Got response %0s, pending req:%0d",
                                       req.convert2string(), pending_a_req.size()), UVM_NONE)
      // pending_a_req.delete(pending_a_req.size()-1);
      void'(pending_a_req.pop_back());
      
    end
  endtask

  // Drive AXI write transaction
  virtual task drive_axi_wr_transaction(tl_seq_item req);
    begin

      pending_a_req.push_back(req);

      @(cfg.vif.wr_cb);
      // Drive address channel
      cfg.vif.axi_wr_req.awvalid <= 1'b1;
      cfg.vif.axi_wr_req.awaddr  <= req.a_addr;
      cfg.vif.axi_wr_req.awid    <= req.a_source;
      cfg.vif.axi_wr_req.awsize  <= req.a_size;
      cfg.vif.axi_wr_req.awburst <= 2'b01;   // Incremental burst, can adjust based on your design
      cfg.vif.axi_wr_req.awuser  <= req.a_user;
      cfg.vif.axi_wr_req.awlock  <= 1'b0;
      cfg.vif.axi_wr_req.awlen   <= 8'h0;    // Single beat write transaction

      // Wait until slave accepts the data phase
      @(cfg.vif.wr_cb);
      while (!cfg.vif.axi_wr_rsp.awready) @(cfg.vif.wr_cb);
      cfg.vif.axi_wr_req.awvalid <= 1'b0;

      cfg.vif.axi_wr_req.wvalid  <= 1'b1;
      cfg.vif.axi_wr_req.wdata   <= req.a_data;
      cfg.vif.axi_wr_req.wstrb   <= req.a_mask;
      cfg.vif.axi_wr_req.wlast   <= 1'b1;

      while (!cfg.vif.axi_wr_rsp.wready) @(cfg.vif.wr_cb);
      // Wait until slave accepts the write response
      @(cfg.vif.wr_cb);
      while (!cfg.vif.axi_wr_rsp.bvalid) @(cfg.vif.wr_cb);
      cfg.vif.axi_wr_req.wvalid <= 1'b0;
      cfg.vif.axi_wr_req.wlast  <= 1'b0;
      cfg.vif.axi_wr_req.bready <= 1'b1;
      req.d_error               <= (cfg.vif.axi_wr_rsp.bresp == 0 ? 0 : 1);

      @(cfg.vif.wr_cb);
      cfg.vif.axi_wr_req.bready <= 1'b0;

      req.req_completed <= 1'b1;
      req.d_source  <= req.a_source;


      @(cfg.vif.rd_cb);
      req.rsp_completed = !reset_asserted;
      seq_item_port.put_response(req);
      `uvm_info(get_full_name(), $sformatf("Got response %0s, pending req:%0d",
                                       req.convert2string(), pending_a_req.size()), UVM_NONE)
      void'(pending_a_req.pop_back());

    end
  endtask

  // reset signals every time reset occurs.
  virtual task reset_signals();
    invalidate_a_channel();
    cfg.vif.h2d_int.d_ready <= 1'b0;
    forever begin
      // @(negedge cfg.vif.rst_n);
      // reset_asserted = 1'b1;
      // invalidate_a_channel();
      // cfg.vif.h2d_int.d_ready <= 1'b0;
      @(posedge cfg.vif.rst_n);
      reset_asserted = 1'b0;
      reset_axi_signals();
      // Check for seq_item_port FIFO & pending req queue is empty when coming out of reset
      `DV_CHECK_EQ(pending_a_req.size(), 0)
      `DV_CHECK_EQ(seq_item_port.has_do_available(), 0)
      // Check if the a_source_pend_q maintained in the cfg is empty.
      if (cfg.check_tl_errs) begin
        `DV_CHECK_EQ(cfg.a_source_pend_q.size(), 0)
      end
    end
  endtask
  
  virtual task send_axi_req(tl_seq_item req);

    int unsigned a_valid_delay, a_valid_len;
    bit req_done, req_abort;

    `DV_SPINWAIT_EXIT(while (is_source_in_pending_req(req.a_source)) @(cfg.vif.host_cb);,
    wait(reset_asserted);)

    while (!req_done && !req_abort) begin
      if (cfg.use_seq_item_a_valid_delay) begin
        a_valid_delay = req.a_valid_delay;
      end else begin
        a_valid_delay = $urandom_range(cfg.a_valid_delay_min, cfg.a_valid_delay_max);
      end

      if (req.req_abort_after_a_valid_len || cfg.allow_a_valid_drop_wo_a_ready) begin
        if (cfg.use_seq_item_a_valid_len) begin
          a_valid_len = req.a_valid_len;
        end else begin
          a_valid_len = $urandom_range(cfg.a_valid_len_min, cfg.a_valid_len_max);
        end
      end

      // break delay loop if reset asserted to release blocking
      `DV_SPINWAIT_EXIT(repeat (a_valid_delay) @(cfg.vif.host_cb);,
                        wait(reset_asserted);)

      if (!reset_asserted) begin
        if(req.a_opcode == tlul_pkg::tl_a_op_e'(Get)) begin
          send_rd_channel_request(req);
        end else begin
          send_wr_channel_request(req);
        end
        req_done = 1;
      end else begin
        req_abort = 1;
      end
      // // drop valid if it lasts for a_valid_len, even there is no a_ready
      // `DV_SPINWAIT_EXIT(send_a_request_body(req, a_valid_len, req_done, req_abort);,
      //                   wait(reset_asserted);)

      // when reset and host_cb.h2d_int.a_valid <= 1 occur at the same time, if clock is off,
      // there is a race condition and invalidate_a_channel can't clear a_valid.
      if (reset_asserted) cfg.vif.host_cb.h2d_int.a_valid <= 1'b0;
      // invalidate_a_channel();
    end
    seq_item_port.item_done();
    if (req_abort || reset_asserted) begin
      req.req_completed = 0;
      // Just wire the d_source back to a_source to avoid errors in upstream logic.
      req.d_source = req.a_source;
      seq_item_port.put_response(req);
    end else begin
      req.req_completed = 1;
    end
    `uvm_info(get_full_name(), $sformatf("Req %0s: %0s", req_abort ? "aborted" : "sent",
                                         req.convert2string()), UVM_NONE)
  endtask


  // Send request on A channel
  virtual task send_a_channel_request(tl_seq_item req);
    int unsigned a_valid_delay, a_valid_len;
    bit req_done, req_abort;

    // Seq may override the a_source or all valid sources are used but still send req, in which case
    // it is possible that it might not have factored
    // This wait is only needed in xbar test as xbar can use all valid sources and xbar_stress runs
    // all seq in parallel, which needs driver to stall when the source is currently being used
    // in the a_source values from pending requests that have not yet completed. If that is true, we
    // need to insert additional delays to ensure we do not end up sending the new request whose
    // a_source matches one of the pending requests.
    `DV_SPINWAIT_EXIT(while (is_source_in_pending_req(req.a_source)) @(cfg.vif.host_cb);,
                      wait(reset_asserted);)

    while (!req_done && !req_abort) begin
      if (cfg.use_seq_item_a_valid_delay) begin
        a_valid_delay = req.a_valid_delay;
      end else begin
        a_valid_delay = $urandom_range(cfg.a_valid_delay_min, cfg.a_valid_delay_max);
      end

      if (req.req_abort_after_a_valid_len || cfg.allow_a_valid_drop_wo_a_ready) begin
        if (cfg.use_seq_item_a_valid_len) begin
          a_valid_len = req.a_valid_len;
        end else begin
          a_valid_len = $urandom_range(cfg.a_valid_len_min, cfg.a_valid_len_max);
        end
      end

      // break delay loop if reset asserted to release blocking
      `DV_SPINWAIT_EXIT(repeat (a_valid_delay) @(cfg.vif.host_cb);,
                        wait(reset_asserted);)

      if (!reset_asserted) begin
        pending_a_req.push_back(req);

        cfg.vif.host_cb.h2d_int.a_address <= req.a_addr;
        cfg.vif.host_cb.h2d_int.a_opcode  <= tl_a_op_e'(req.a_opcode);
        cfg.vif.host_cb.h2d_int.a_size    <= req.a_size;
        cfg.vif.host_cb.h2d_int.a_param   <= req.a_param;
        cfg.vif.host_cb.h2d_int.a_data    <= req.a_data;
        cfg.vif.host_cb.h2d_int.a_mask    <= req.a_mask;
        cfg.vif.host_cb.h2d_int.a_user    <= req.a_user;
        cfg.vif.host_cb.h2d_int.a_source  <= req.a_source;
        cfg.vif.host_cb.h2d_int.a_valid   <= 1'b1;
      end else begin
        req_abort = 1;
      end
      // drop valid if it lasts for a_valid_len, even there is no a_ready
      `DV_SPINWAIT_EXIT(send_a_request_body(req, a_valid_len, req_done, req_abort);,
                        wait(reset_asserted);)

      // when reset and host_cb.h2d_int.a_valid <= 1 occur at the same time, if clock is off,
      // there is a race condition and invalidate_a_channel can't clear a_valid.
      if (reset_asserted) cfg.vif.host_cb.h2d_int.a_valid <= 1'b0;
      invalidate_a_channel();
    end
    seq_item_port.item_done();
    if (req_abort || reset_asserted) begin
      req.req_completed = 0;
      // Just wire the d_source back to a_source to avoid errors in upstream logic.
      req.d_source = req.a_source;
      seq_item_port.put_response(req);
    end else begin
      req.req_completed = 1;
    end
    `uvm_info(get_full_name(), $sformatf("Req %0s: %0s", req_abort ? "aborted" : "sent",
                                         req.convert2string()), UVM_HIGH)
  endtask : send_a_channel_request

  virtual task send_a_request_body(tl_seq_item req, int a_valid_len,
                                   ref bit req_done, ref bit req_abort);
    int unsigned a_valid_cnt;
    while (1) begin
      @(cfg.vif.host_cb);
      a_valid_cnt++;
      if (cfg.vif.host_cb.d2h.a_ready) begin
        req_done = 1;
        break;
      end else if ((req.req_abort_after_a_valid_len || cfg.allow_a_valid_drop_wo_a_ready) &&
                   a_valid_cnt >= a_valid_len) begin
        if (req.req_abort_after_a_valid_len) req_abort = 1;
        cfg.vif.host_cb.h2d_int.a_valid <= 1'b0;
        // remove unaccepted item
        void'(pending_a_req.pop_back());
        invalidate_a_channel();
        @(cfg.vif.host_cb);
        break;
      end
    end
  endtask : send_a_request_body

  // host responds d_ready
  virtual task d_ready_rsp();
    int unsigned d_ready_delay;
    tl_seq_item rsp;

    forever begin
      bit req_found;
      d_ready_delay = $urandom_range(cfg.d_ready_delay_min, cfg.d_ready_delay_max);
      // if a_valid high then d_ready must be high, exit the delay when a_valid is set
      repeat (d_ready_delay) begin
        if (!cfg.host_can_stall_rsp_when_a_valid_high && cfg.vif.h2d_int.a_valid) break;
        @(cfg.vif.host_cb);
      end

      cfg.vif.host_cb.h2d_int.d_ready <= 1'b1;
      @(cfg.vif.host_cb);
      cfg.vif.host_cb.h2d_int.d_ready <= 1'b0;
    end
  endtask : d_ready_rsp
  
  // Collect ack from D channel
  virtual task d_channel_thread();
    int unsigned d_ready_delay;
    tl_seq_item rsp;

    forever begin
      if ((cfg.vif.host_cb.d2h.d_valid && cfg.vif.h2d_int.d_ready && !reset_asserted) ||
          ((pending_a_req.size() != 0) & reset_asserted)) begin
        // Use the source ID to find the matching request
        foreach (pending_a_req[i]) begin
          if ((pending_a_req[i].a_source == cfg.vif.host_cb.d2h.d_source) | reset_asserted) begin
            rsp = pending_a_req[i];
            rsp.d_opcode = cfg.vif.host_cb.d2h.d_opcode;
            rsp.d_data   = cfg.vif.host_cb.d2h.d_data;
            rsp.d_param  = cfg.vif.host_cb.d2h.d_param;
            rsp.d_sink   = cfg.vif.host_cb.d2h.d_sink;
            rsp.d_size   = cfg.vif.host_cb.d2h.d_size;
            rsp.d_user   = cfg.vif.host_cb.d2h.d_user;
            // set d_error = 0 and rsp_completed = 0 when reset occurs
            rsp.d_error  = reset_asserted ? 0 : cfg.vif.host_cb.d2h.d_error;
            // make sure every req has a rsp with same source even during reset
            if (reset_asserted) rsp.d_source = rsp.a_source;
            else                rsp.d_source = cfg.vif.host_cb.d2h.d_source;
            seq_item_port.put_response(rsp);
            pending_a_req.delete(i);
            `uvm_info(get_full_name(), $sformatf("Got response %0s, pending req:%0d",
                                       rsp.convert2string(), pending_a_req.size()), UVM_HIGH)
            rsp.rsp_completed = !reset_asserted;
            break;
          end
        end

        // If there was a matching request, we responded to it above. If not, the device seems to
        // have sent a response without a request (and we won't have done anything yet).
        //
        // If we're in reset, we might have forgotten the request (and can ignore the response). If
        // not, we wouldn't normally expect this to happen. This is a property that is checked in
        // the tlul_assert module, which should be bound in. But it *might* happen if we're doing
        // fault injection and disabling assertions in that module.
        //
        // Ignore the response either way: we're a driver and there is definitely no sequence that
        // is waiting for the response here. If there's a bug in the design and we're generating
        // spurious responses, we expect something to fail in tlul_assert.
      end else if (reset_asserted) begin
        wait(!reset_asserted);
      end
      `DV_SPINWAIT_EXIT(@(cfg.vif.host_cb);,
                        wait(reset_asserted);)
    end
  endtask : d_channel_thread

  function bit is_source_in_pending_req(bit [SourceWidth-1:0] source);
    foreach (pending_a_req[i]) begin
      if (pending_a_req[i].a_source == source) return 1;
    end
    return 0;
  endfunction

  function void invalidate_a_channel();
    if (cfg.invalidate_a_x) begin
      cfg.vif.h2d_int.a_opcode <= tlul_pkg::tl_a_op_e'('x);
      cfg.vif.h2d_int.a_param <= '{default:'x};
      cfg.vif.h2d_int.a_size <= '{default:'x};
      cfg.vif.h2d_int.a_source <= '{default:'x};
      cfg.vif.h2d_int.a_address <= '{default:'x};
      cfg.vif.h2d_int.a_mask <= '{default:'x};
      cfg.vif.h2d_int.a_data <= '{default:'x};
      // The assignment to tl_type must have a cast since the LRM doesn't allow enum assignment of
      // values not belonging to the enumeration set.
      cfg.vif.h2d_int.a_user <= '{instr_type:prim_mubi_pkg::mubi4_t'('x), default:'x};
      cfg.vif.h2d_int.a_valid <= 1'b0;
    end else begin
      tlul_pkg::tl_h2d_t h2d;
      `DV_CHECK_STD_RANDOMIZE_FATAL(h2d)
      h2d.a_valid = 1'b0;
      cfg.vif.h2d_int <= h2d;
    end
  endfunction : invalidate_a_channel

endclass : tl_host_driver
