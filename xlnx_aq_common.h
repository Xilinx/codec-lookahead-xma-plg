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
#ifndef XLNX_AQ_COMMON_H
#define XLNX_AQ_COMMON_H

#include <stdint.h>
#include "xlnx_la_plg_ext.h"

typedef enum
{
    EXlnxError,
    EXlnxSuccess,
    EXlnxTryAgain
} xlnx_status;

typedef struct xlnx_aq_buf
{
    uint8_t *ptr;
    size_t size;
} xlnx_aq_buf_t;

typedef struct xlnx_rc_fsfa
{
    uint32_t fs;
    uint32_t fa;
} xlnx_rc_fsfa_t;

typedef struct xlnx_qpmap
{
    xlnx_aq_buf_t buf;
    uint64_t frame_num;
} xlnx_qpmap_t;

typedef struct aq_config
{
    uint32_t width;
    uint32_t height;
    int32_t outWidth;
    int32_t outHeight;
    uint32_t actual_mb_w;
    uint32_t actual_mb_h;
    uint32_t padded_mb_w;
    uint32_t padded_mb_h;
    uint32_t blockWidth;
    uint32_t blockHeight;
    uint32_t intraPeriod;
    uint32_t la_depth;
    uint32_t spatial_aq_mode;
    uint32_t spatial_aq_gain;
    uint32_t temporal_aq_mode;
    uint32_t rate_control_mode;
    uint32_t num_mb;
    uint32_t qpmap_size;
    uint32_t num_b_frames;
    xlnx_codec_type_t codec_type;
} aq_config_t;

#endif // XLNX_AQ_COMMON_H

