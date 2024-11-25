// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package axi_pkg;

    localparam int AXI_DW = 32;
    localparam int AXI_AW = 32;
    localparam int AXI_UW = 32;
    localparam int AXI_IW = 1;
    localparam int AXI_BC = AXI_DW/8;
    localparam int AXI_BW = $clog2(AXI_BC);

    // Data that is returned upon an a TL-UL error belonging to an instruction fetch.
    // Note that this data will be returned with the correct bus integrity value.
    //parameter logic [top_pkg::TL_DW-1:0] DataWhenInstrError = '0;
    // Data that is returned upon an a TL-UL error not belonging to an instruction fetch.
    // Note that this data will be returned with the correct bus integrity value.
    //parameter logic [top_pkg::TL_DW-1:0] DataWhenError      = {top_pkg::TL_DW{1'b1}};


    localparam AXI_LEN_MAX_VALUE = 256; // 8-bit LEN signal = 256 beats max
    localparam AXI_LEN_WIDTH     = $clog2(AXI_LEN_MAX_VALUE);
    localparam AXI_LEN_MAX_BYTES = 4096;
    localparam AXI_LEN_BC_WIDTH = $clog2(AXI_LEN_MAX_BYTES);

    // AXI Burst Enum
    typedef enum logic [1:0] {
        AXI_BURST_FIXED    = 2'b00,
        AXI_BURST_INCR     = 2'b01,
        AXI_BURST_WRAP     = 2'b10,
        AXI_BURST_RESERVED = 2'b11
    } axi_burst_e;

    // AXI Resp Enum
    typedef enum logic [1:0] {
        AXI_RESP_OKAY   = 2'b00,
        AXI_RESP_EXOKAY = 2'b01,
        AXI_RESP_SLVERR = 2'b10,
        AXI_RESP_DECERR = 2'b11
    } axi_resp_e;

endpackage
