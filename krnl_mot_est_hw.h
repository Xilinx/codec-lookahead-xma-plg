/*
 * Copyright (C) 2019, Xilinx Inc - All rights reserved
 * Xilinx Lookahead XMA Plugin
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
// ==============================================================
// ctrl
// 0x00 : Control signals
//        bit 0  - ap_start (Read/Write/COH)
//        bit 1  - ap_done (Read/COR)
//        bit 2  - ap_idle (Read)
//        bit 3  - ap_ready (Read)
//        bit 7  - auto_restart (Read/Write)
//        others - reserved
// 0x04 : Global Interrupt Enable Register
//        bit 0  - Global Interrupt Enable (Read/Write)
//        others - reserved
// 0x08 : IP Interrupt Enable Register (Read/Write)
//        bit 0  - Channel 0 (ap_done)
//        bit 1  - Channel 1 (ap_ready)
//        others - reserved
// 0x0c : IP Interrupt Status Register (Read/TOW)
//        bit 0  - Channel 0 (ap_done)
//        bit 1  - Channel 1 (ap_ready)
//        others - reserved
// 0x10 : Data signal of width
//        bit 31~0 - width[31:0] (Read/Write)
// 0x14 : reserved
// 0x18 : Data signal of height
//        bit 31~0 - height[31:0] (Read/Write)
// 0x1c : reserved
// 0x20 : Data signal of stride
//        bit 31~0 - stride[31:0] (Read/Write)
// 0x24 : reserved
// 0x28 : Data signal of write_mv
//        bit 31~0 - write_mv[31:0] (Read/Write)
// 0x2c : reserved
// 0x30 : Data signal of frm_buffer_ref_V
//        bit 31~0 - frm_buffer_ref_V[31:0] (Read/Write)
// 0x34 : Data signal of frm_buffer_ref_V
//        bit 31~0 - frm_buffer_ref_V[63:32] (Read/Write)
// 0x38 : reserved
// 0x3c : Data signal of frm_buffer_srch_V
//        bit 31~0 - frm_buffer_srch_V[31:0] (Read/Write)
// 0x40 : Data signal of frm_buffer_srch_V
//        bit 31~0 - frm_buffer_srch_V[63:32] (Read/Write)
// 0x44 : reserved
// 0x48 : Data signal of sad_V
//        bit 31~0 - sad_V[31:0] (Read/Write)
// 0x4c : Data signal of sad_V
//        bit 31~0 - sad_V[63:32] (Read/Write)
// 0x50 : reserved
// 0x54 : Data signal of mv_V
//        bit 31~0 - mv_V[31:0] (Read/Write)
// 0x58 : Data signal of mv_V
//        bit 31~0 - mv_V[63:32] (Read/Write)
// 0x5c : reserved
// 0x60 : Data signal of skip_l2
//        bit 31~0 - skip_l2[31:0] (Read/Write)
// 0x64 : reserved
// 0x6c : Data signal of var_V
//        bit 31~0 - var_V[31:0] (Read/Write)
// 0x70 : Data signal of var_V
//        bit 31~0 - var_V[63:32] (Read/Write)
// 0x74 : reserved
// 0x78 : Data signal of act_V
//        bit 31~0 - act_V[31:0] (Read/Write)
// 0x7c : Data signal of act_V
//        bit 31~0 - act_V[63:32] (Read/Write)
// 0x80 : reserved
// 0x84 : Data signal of pixFmt
//        bit 31~0 - pixFmt[31:0] (Read/Write)
// 0x88 : reserved
// (SC = Self Clear, COR = Clear on Read, TOW = Toggle on Write, COH = Clear on Handshake)

#define XV_MOT_EST_CTRL_ADDR_AP_CTRL                0x00
#define XV_MOT_EST_CTRL_ADDR_GIE                    0x04
#define XV_MOT_EST_CTRL_ADDR_IER                    0x08
#define XV_MOT_EST_CTRL_ADDR_ISR                    0x0c
#define XV_MOT_EST_CTRL_ADDR_WIDTH_DATA             0x10
#define XV_MOT_EST_CTRL_BITS_WIDTH_DATA             32
#define XV_MOT_EST_CTRL_ADDR_HEIGHT_DATA            0x18
#define XV_MOT_EST_CTRL_BITS_HEIGHT_DATA            32
#define XV_MOT_EST_CTRL_ADDR_STRIDE_DATA            0x20
#define XV_MOT_EST_CTRL_BITS_STRIDE_DATA            32
#define XV_MOT_EST_CTRL_ADDR_WRITE_MV_DATA          0x28
#define XV_MOT_EST_CTRL_BITS_WRITE_MV_DATA          32
#define XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_REF_V_DATA  0x30
#define XV_MOT_EST_CTRL_BITS_FRM_BUFFER_REF_V_DATA  64
#define XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_SRCH_V_DATA 0x3c
#define XV_MOT_EST_CTRL_BITS_FRM_BUFFER_SRCH_V_DATA 64
#define XV_MOT_EST_CTRL_ADDR_SAD_V_DATA             0x48
#define XV_MOT_EST_CTRL_BITS_SAD_V_DATA             64
#define XV_MOT_EST_CTRL_ADDR_MV_V_DATA              0x54
#define XV_MOT_EST_CTRL_BITS_MV_V_DATA              64
#define XV_MOT_EST_CTRL_ADDR_SKIP_L2_DATA           0x60
#define XV_MOT_EST_CTRL_BITS_SKIP_L2_DATA           32
#define XV_MOT_EST_CTRL_ADDR_VAR_V_DATA             0x6c
#define XV_MOT_EST_CTRL_BITS_VAR_V_DATA             64
#define XV_MOT_EST_CTRL_ADDR_ACT_V_DATA             0x78
#define XV_MOT_EST_CTRL_BITS_ACT_V_DATA             64
#define XV_MOT_EST_CTRL_ADDR_PIXFMT_DATA            0x84
#define XV_MOT_EST_CTRL_BITS_PIXFMT_DATA            32
#define XV_MOT_EST_CTRL_SIZE                        0x88

