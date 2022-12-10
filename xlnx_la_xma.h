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
#ifndef XLNX_LA_XMA_H
#define XLNX_LA_XMA_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
//#include <xma.h>
#include <xmaplugin.h>
#include <sys/time.h>
#include <xvbm.h>

//#define ENABLE_XLNX_TIME_LOGGER
#include "xlnx_time_logger.h"
#include "xlnx_ts_queue.h"
#include "xlnx_thread.h"
#include "xlnx_aq_core.h"
#include "krnl_mot_est_hw.h"
#include "xlnx_la_defines.h"
//#define ENABLE_YUV_DUMP

#ifdef __cplusplus
extern "C" {
#endif

typedef struct xlnx_la_dyn_param {
    bool is_spatial_gain_changed;
    uint32_t spatial_aq_gain;
    bool is_temporal_mode_changed;
    bool temporal_aq_mode;
    bool is_spatial_mode_changed;
    bool spatial_aq_mode;
}xlnx_la_dyn_param_t;

typedef struct xlnx_enc_dyn_Param {
    bool is_bitrate_changed;
    uint32_t bit_rate;
    bool is_bframes_changed;
    uint8_t num_b_frames;
    bool     is_min_max_qp_changed;
    uint32_t min_qp;
    uint32_t max_qp;
} xlnx_enc_dyn_Param_t;

typedef struct xlnx_dyn_param {
    xlnx_enc_dyn_Param_t enc_dyn_param;
    xlnx_la_dyn_param_t la_dyn_param;
} xlnx_dyn_param_t;

typedef struct xlnx_la_buf
{
    XmaFrame         xFrame;
    XvbmBufferHandle xvbmBuf;
    uint64_t         paddr;
    uint8_t          *pHost;
    uint64_t         size;
} xlnx_la_buf_t;

typedef enum
{
    EBPCMode8,
    EBPCMode10
} xlnx_la_bpc_mode_t;

typedef struct xlnx_la_mem_res
{
    xlnx_la_buf_t *cur_ready_buf;
    xlnx_la_buf_t *ref_in_buf;
    xlnx_la_buf_t *cur_in_buf;
    xlnx_ts_queue freeHwInBufQ;
    xlnx_ts_queue readyHwInBufQ;
    xlnx_ts_queue waitForVQInfoQ;
    xlnx_ts_queue freeVQInfoQ;
    xlnx_ts_queue readyVQInfoQ;
    xlnx_queue freeStatsBufQ;
    xlnx_queue readyStatsBufQ;
    XvbmPoolHandle pool;
    size_t var_off;
    size_t act_off;
    //@TODO not being used right now
    size_t mv_off;
} xlnx_la_mem_res_t;

typedef struct xlnx_la
{
    xlnx_la_mem_res_t la_bufs;
    XmaBufferObj stats_buf;
    uint32_t width;
    uint32_t height;
    uint32_t vcu_aligned_width;
    uint32_t vcu_aligned_height;
    uint32_t actual_mb_w;
    uint32_t actual_mb_h;
    uint32_t in_stride;
    xlnx_la_bpc_mode_t bpc_mode;
    uint32_t intraPeriod;
    uint32_t write_mv;
    uint32_t in_frame;
    uint32_t out_frame;
    uint32_t skip_l2;
    uint32_t enableHwInBuf;
    uint32_t lookahead_depth;
    uint32_t spatial_aq_mode;
    uint32_t spatial_aq_gain;
    uint32_t temporal_aq_mode;
    uint32_t rate_control_mode;
    uint32_t num_b_frames;
    uint32_t dynamic_gop;
    uint32_t bframes[XLNX_DYNAMIC_GOP_CACHE];
    uint32_t frame_complexity[XLNX_DYNAMIC_GOP_INTERVAL];
    xlnx_codec_type_t codec_type;
    uint32_t latency_logging;
    uint8_t bufpool_ext_req;
    uint8_t isKrnlRunning;
    xlnx_thread_t krnl_thread;
    aq_config_t qpmap_cfg;
    xlnx_aq_core_t qp_handle;
    uint32_t qpmap_size;
    uint32_t qpmap_out_size;
    uint32_t num_mb;
    uint64_t frame_num;
    uint8_t eos_received;
    uint8_t inEOS;
    pthread_mutex_t cfg_lock;
    xlnx_time_logger_t la_plg_tl;
    xlnx_time_logger_t dma_tl;
    xlnx_time_logger_t krnl_thread_tl;
    uint8_t ctrl[XV_MOT_EST_CTRL_SIZE];
    size_t use_out_length;
#ifdef ENABLE_YUV_DUMP
    FILE *inFile;
#endif //ENABLE_YUV_DUMP
    long long int frame_sent;
    long long int frame_recv;
    struct timespec latency;
    long long int time_taken;
    uint32_t is_first_ref_frame;
    int32_t is_idr;
    XmaFormatType in_frame_format;
} xlnx_la_t;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //XLNX_LA_XMA_H
