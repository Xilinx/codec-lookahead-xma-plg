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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include "xlnx_la_xma.h"
#include "xlnx_la_plg_ext.h"
#include "krnl_mot_est_hw.h"
#include "xlnx_la_defines.h"

#define XMA_LA_PLUGIN "XMA_LA_PLUGIN"

#define LOCK_CFG pthread_mutex_lock(&ctx->cfg_lock)
#define UNLOCK_CFG pthread_mutex_unlock(&ctx->cfg_lock)

static const char *outFilePath = "delta_qpmap";
static const uint32_t KERNEL_WAIT_TIMEOUT = 1000; //msec
static const char *XLNX_LA_EXT_PARAMS[] = {
    "ip",
    "lookahead_depth",
    "enable_hw_in_buf",
    "spatial_aq_mode",
    "temporal_aq_mode",
    "rate_control_mode",
    "spatial_aq_gain",
    "num_b_frames",
    "codec_type",
    "latency_logging"
};

static int32_t xma_release_mem_res(XmaFilterSession *sess);
static void cleanup_krnl_driver_thread(XmaFilterSession *sess);
static xlnx_thread_func_ret_t krnl_driver(xlnx_thread_func_args_t  args);

#define RET_IF_ERR(METHOD,...)                                                          \
    do {                                                                                \
        if (METHOD(__VA_ARGS__) <= XMA_ERROR) {                                         \
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, #METHOD " %p : Failed!!", ctx);    \
            return XMA_ERROR;                                                           \
        }                                                                               \
    } while (0);

#define CLEANUP_IF_ERR(XMA_SESSION, METHOD, ...)                                        \
    do {                                                                                \
        if (METHOD(__VA_ARGS__) <= XMA_ERROR) {                                         \
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, #METHOD " %p : FAILED!!", ctx);    \
            cleanup_krnl_driver_thread(XMA_SESSION);                                    \
            xma_release_mem_res(XMA_SESSION);                                           \
            return XMA_ERROR;                                                           \
        }                                                                               \
    } while (0);

#define TH_RET_IF_ERR(METHOD,...)                                                       \
    do {                                                                                \
        int32_t xma_ret = METHOD(__VA_ARGS__);                                          \
        if (xma_ret <= XMA_ERROR) {                                                     \
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, #METHOD " %p : FAILED!!", ctx);    \
            return ERetError;                                                           \
        }                                                                               \
    } while (0);

static int32_t init_krnl_regs(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "%p Set Krnl Regs width=%u height=%u stride=%u bpc_mode=%u write_mv=%u "
               "skip_l2=%u", ctx,
               ctx->width, ctx->height, ctx->vcu_aligned_width, ctx->bpc_mode, ctx->write_mv,
               ctx->skip_l2);

    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_WIDTH_DATA, &(ctx->width),
            sizeof(uint32_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_HEIGHT_DATA, &(ctx->height),
            sizeof(uint32_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_STRIDE_DATA, &(ctx->vcu_aligned_width),
            sizeof(uint32_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_WRITE_MV_DATA, &(ctx->write_mv),
            sizeof(uint32_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_SKIP_L2_DATA, &(ctx->skip_l2),
            sizeof(uint32_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_PIXFMT_DATA, &(ctx->bpc_mode),
            sizeof(uint32_t));

    return 0;
}

static int32_t xma_alloc_vq_info_buffer(xlnx_la_t *ctx, xlnx_aq_info_t *vq_info)
{
    int32_t ret = XMA_SUCCESS;
    xlnx_aq_buf_t *qpmap = &vq_info->qpmap;
    xlnx_aq_buf_t *fsfa = &vq_info->fsfa;
    uint8_t *qpmap_buf = NULL;
    uint8_t *fsfa_buf = NULL;
    qpmap->ptr = NULL;
    fsfa->ptr = NULL;

    qpmap_buf = calloc(1, sizeof(uint8_t) * ctx->qpmap_out_size);
    if(!qpmap_buf) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "OOM %s !!", __FUNCTION__);
        return XMA_ERROR;
    }
    qpmap->ptr = qpmap_buf;
    qpmap->size = sizeof(uint8_t) * ctx->qpmap_out_size;

    if (ctx->rate_control_mode != 0) {
        fsfa_buf = calloc(1, sizeof(xlnx_rc_fsfa_t) * ctx->lookahead_depth);
        if(!fsfa_buf) {
            if (qpmap_buf) {
                free(qpmap_buf);
            }
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "OOM %s !!", __FUNCTION__);
            return XMA_ERROR;
        }
        fsfa->ptr = fsfa_buf;
        fsfa->size = sizeof(xlnx_rc_fsfa_t) * ctx->lookahead_depth;
    }

    vq_info->frame_num = 0;

    return ret;
}

static void free_la_buffer(xlnx_la_buf_t *laBuf)
{
    if (!laBuf) {
        return;
    }
    if (laBuf->xvbmBuf) {
        xvbm_buffer_pool_entry_free(laBuf->xvbmBuf);
    }
    free(laBuf);
}

static void xma_free_hw_buffer_obj(XmaSession *xma_sess,
                                   XmaBufferObj *hw_buff_obj)
{
    if (!hw_buff_obj) {
        return;
    }
    if (hw_buff_obj->data) {
        xma_plg_buffer_free(*xma_sess, *hw_buff_obj);
        hw_buff_obj->data = 0;
    }
    hw_buff_obj->size = 0;
}

static void xma_free_hwbuf_TSQ(xlnx_ts_queue aTSQ)
{
    if (aTSQ == NULL) {
        return;
    }
    xlnx_la_buf_t *laBuf = NULL;
    while(!PopTSQ(aTSQ, &laBuf)) {
        free_la_buffer(laBuf);
        laBuf = NULL;
    }
    destroyTSQ(aTSQ);
}

static void xma_free_hwbuf_Q(XmaSession *xma_sess, xlnx_queue aQ)
{
    if (aQ == NULL) {
        return;
    }
    XmaBufferObj hwBufObj;
    while(!PopQ(aQ, &hwBufObj)) {
        xma_free_hw_buffer_obj(xma_sess, &hwBufObj);
    }
    destroyQueue(aQ);
}

static void xma_free_vq_info_TSQ(xlnx_ts_queue aTSQ)
{
    if (aTSQ == NULL) {
        return;
    }
    xlnx_aq_info_t vq_info;
    while(!PopTSQ(aTSQ, &vq_info)) {
        if (vq_info.qpmap.ptr) {
            free(vq_info.qpmap.ptr);
        }
        if (vq_info.fsfa.ptr) {
            free(vq_info.fsfa.ptr);
        }
    }
    destroyTSQ(aTSQ);
}

inline static size_t xlnx_align_to_base(size_t s, size_t align_base)
{
    return ((s + align_base - 1) & (~ (align_base - 1)));
}

static size_t setOutBufSize(xlnx_la_t *ctx, xlnx_la_mem_res_t *memRes,
                            size_t *length)
{
    uint32_t num_b = ctx->num_mb;
    //SAD
    uint32_t Bpb = 2;
    size_t totalSize = xlnx_align_to_base(num_b * Bpb, LINMEM_ALIGN_4K);
    //ACT
    memRes->act_off = totalSize;
    totalSize *= 2;
    //VAR
    memRes->var_off = totalSize;
    Bpb = 4;
    totalSize += xlnx_align_to_base(num_b * Bpb, LINMEM_ALIGN_4K);
    //MV
    *length = totalSize;
    memRes->mv_off = totalSize;
    totalSize += xlnx_align_to_base(num_b * Bpb, LINMEM_ALIGN_4K);
    return totalSize;
}

static int32_t xma_alloc_mem_res(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    xlnx_la_buf_t *la_buf = NULL;
    xlnx_aq_info_t vq_info;
    int32_t ret_code = XMA_ERROR;
    XmaBufferObj hwBufObj;
    XmaBufferObj wa_buf;

    memRes->cur_ready_buf = NULL;
    memRes->ref_in_buf = NULL;
    memRes->cur_in_buf = NULL;

    ctx->vcu_aligned_height = xlnx_align_to_base(ctx->height, VCU_HEIGHT_ALIGN);

    if (ctx->bpc_mode == EBPCMode8) {
        ctx->vcu_aligned_width = xlnx_align_to_base(ctx->in_stride, VCU_STRIDE_ALIGN);
    } else if (ctx->bpc_mode == EBPCMode10) {
        ctx->vcu_aligned_width = xlnx_align_to_base(((ctx->width+2)/3) << 2,
                                 VCU_STRIDE_ALIGN);
    } else {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : Invalid BPC mode=%d", ctx->bpc_mode);
        return XMA_ERROR;
    }
    unsigned int input_size = ((ctx->vcu_aligned_width) * (ctx->vcu_aligned_height)
                               * 3) >> 1;

    size_t output_size = setOutBufSize(ctx, memRes, &ctx->use_out_length);
    //printf("LA : %p input_size=%u output_size=%u\n", ctx, input_size, output_size);

    memRes->freeHwInBufQ = createTSQ(ctx->lookahead_depth + 1,
                                     sizeof(xlnx_la_buf_t *));
    memRes->readyHwInBufQ = createTSQ(ctx->lookahead_depth + 1,
                                      sizeof(xlnx_la_buf_t *));
    memRes->waitForVQInfoQ = createTSQ(ctx->lookahead_depth + 1,
                                       sizeof(xlnx_la_buf_t *));
    memRes->freeStatsBufQ = createQueue(XLNX_OUT_STATS_HW_BUF_Q_SIZE,
                                        sizeof(XmaBufferObj));
    memRes->readyStatsBufQ = createQueue(XLNX_OUT_STATS_HW_BUF_Q_SIZE,
                                         sizeof(XmaBufferObj));
    memRes->freeVQInfoQ = createTSQ(ctx->lookahead_depth + 1,
                                    sizeof(xlnx_aq_info_t));
    memRes->readyVQInfoQ = createTSQ(ctx->lookahead_depth + 1,
                                     sizeof(xlnx_aq_info_t));

    if(!memRes->freeHwInBufQ || !memRes->readyHwInBufQ ||
            !memRes->freeStatsBufQ || !memRes->readyStatsBufQ || !memRes->freeVQInfoQ ||
            !memRes->readyVQInfoQ || !memRes->waitForVQInfoQ) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "OOM %s %d!!", __FUNCTION__, __LINE__);
        xma_release_mem_res(sess);
        return XMA_ERROR;
    }
    /* Allocate input and output device buffers for processing Y plane data */
    for (uint32_t i = 0; i < ctx->lookahead_depth + 1; i++) {
        la_buf = calloc(1, sizeof(xlnx_la_buf_t));
        if (la_buf == NULL) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                       "%p : calloc  xlnx_la_buf_t FAILED!!", ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
        if (PushTSQ(memRes->freeHwInBufQ, &la_buf)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                       "%p : PushTSQ to freeHwInBufQ FAILED!!", ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
    }
    if (!ctx->enableHwInBuf) {
        //@TODO : Remove workaround for physical addr =0  bug
        wa_buf = xma_plg_buffer_alloc(sess->base, 4096, true, &ret_code);
        if (ret_code == XMA_ERROR) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "xma_plg_buffer_alloc: %p : FAILED!!",
                       ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
        memRes->pool = xvbm_buffer_pool_create(xma_plg_get_dev_handle(sess->base),
                                               ctx->lookahead_depth + 1, input_size, 0);
        if ((memRes->pool == (XvbmPoolHandle)-1) ||
                (memRes->pool == NULL)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                       "xvbm_buffer_pool_create: %p : FAILED!!", ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
        xma_plg_buffer_free(sess->base, wa_buf);
        wa_buf.data = NULL;

    } else {
        memRes->pool = NULL;
    }

    for (int32_t i = 0; i < XLNX_OUT_STATS_HW_BUF_Q_SIZE; i++) {
        hwBufObj = xma_plg_buffer_alloc(sess->base, output_size, false, &ret_code);
        if (ret_code == XMA_ERROR) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "xma_plg_buffer_alloc: %p : FAILED!!",
                       ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
        if (PushQ(memRes->freeStatsBufQ, &hwBufObj)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "%p : PushQ freeStatsBufQ FAILED!!",
                       ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
    }

    for (uint32_t i = 0; i < (ctx->lookahead_depth + 1); i++) {
        CLEANUP_IF_ERR(sess, xma_alloc_vq_info_buffer, ctx, &vq_info);
        if (PushTSQ(memRes->freeVQInfoQ, &vq_info)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "%p : PushTSQ freeVQInfoQ FAILED!!",
                       ctx);
            cleanup_krnl_driver_thread(sess);
            xma_release_mem_res(sess);
            return XMA_ERROR;
        }
    }

    return 0;
}

static int32_t xma_release_mem_res(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    XmaSession xma_sess = sess->base;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;

    if (ctx->qp_handle) {
        destroy_aq_core(ctx->qp_handle);
        ctx->qp_handle = NULL;
    }

    free_la_buffer(memRes->cur_ready_buf);
    memRes->cur_ready_buf = NULL;
    memRes->ref_in_buf = NULL;
    free_la_buffer(memRes->cur_in_buf);
    memRes->cur_in_buf = NULL;

    xma_free_hwbuf_TSQ(memRes->freeHwInBufQ);
    memRes->freeHwInBufQ = NULL;
    xma_free_hwbuf_TSQ(memRes->readyHwInBufQ);
    memRes->readyHwInBufQ = NULL;
    xma_free_hwbuf_TSQ(memRes->waitForVQInfoQ);
    memRes->waitForVQInfoQ = NULL;

    xma_free_hwbuf_Q(&xma_sess, memRes->freeStatsBufQ);
    memRes->freeStatsBufQ = NULL;
    xma_free_hwbuf_Q(&xma_sess, memRes->readyStatsBufQ);
    memRes->readyStatsBufQ = NULL;

    xma_free_vq_info_TSQ(memRes->freeVQInfoQ);
    memRes->freeVQInfoQ = NULL;
    xma_free_vq_info_TSQ(memRes->readyVQInfoQ);
    memRes->readyVQInfoQ = NULL;


    if (memRes->pool) {
        xvbm_buffer_pool_destroy(memRes->pool);
    }
    memRes->pool = NULL;
    return 0;
}

static int32_t init_qpmap_generator(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    aq_config_t *qpmapcfg = &ctx->qpmap_cfg;
    qpmapcfg->width = ctx->width;
    qpmapcfg->height = ctx->height;
    qpmapcfg->actual_mb_w = ctx->actual_mb_w;
    qpmapcfg->actual_mb_h = ctx->actual_mb_h;
    qpmapcfg->outWidth = sess->props.output.width;
    qpmapcfg->outHeight = sess->props.output.height;
    qpmapcfg->blockWidth = BLOCK_WIDTH;
    qpmapcfg->blockHeight = BLOCK_HEIGHT;
    qpmapcfg->padded_mb_w = sess->props.output.width/qpmapcfg->blockWidth;
    qpmapcfg->padded_mb_h = sess->props.output.height/qpmapcfg->blockHeight;
    qpmapcfg->intraPeriod = ctx->intraPeriod;
    qpmapcfg->la_depth = ctx->lookahead_depth;
    qpmapcfg->spatial_aq_mode = ctx->spatial_aq_mode;
    qpmapcfg->spatial_aq_gain = ctx->spatial_aq_gain;
    qpmapcfg->temporal_aq_mode = ctx->temporal_aq_mode;
    qpmapcfg->rate_control_mode = ctx->rate_control_mode;
    qpmapcfg->num_mb = ctx->num_mb;
    qpmapcfg->qpmap_size = ctx->qpmap_size;
    qpmapcfg->num_b_frames = ctx->num_b_frames;
    qpmapcfg->codec_type = ctx->codec_type;

    xlnx_aq_dump_cfg dumpCfg;
    dumpCfg.dumpDeltaQpMap = PRINT_FRAME_DELTAQP_MAP;
    dumpCfg.dumpDeltaQpMapHex = PRINT_HEX_FRAME_DELTAQP_MAP;
    dumpCfg.dumpBlockSAD = PRINT_BLOCK_SAD;
    dumpCfg.dumpFrameSAD = PRINT_FRAME_SAD;
    dumpCfg.outPath = outFilePath;

    ctx->qp_handle = create_aq_core(qpmapcfg, &dumpCfg);
    if (!ctx->qp_handle) {
        return -1;
    }
    return 0;
}

static int32_t check_la_settings(xlnx_la_t *ctx)
{
    if (ctx->in_frame_format == XMA_VCU_NV12_10LE32_FMT_TYPE &&
            !ctx->enableHwInBuf) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "check_la_settings: XMA_VCU_NV12_10LE32_FMT_TYPE supported only in Zero-copy mode");
        return -1;
    }

    if ((ctx->lookahead_depth == 0) && (ctx->temporal_aq_mode > 0)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "check_la_settings: Invalid Params lookahead_depth = %u, temporal mode = %u",
                   ctx->lookahead_depth,
                   ctx->temporal_aq_mode);
        return -1;
    }
    if (ctx->spatial_aq_mode && ((ctx->spatial_aq_gain == 0) ||
                                 (ctx->spatial_aq_gain > 100))) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "check_la_settings: Invalid Params spatial_aq_mode=%u, spatial_aq_gain=%u",
                   ctx->spatial_aq_mode,
                   ctx->spatial_aq_gain);
        return -1;
    }
    return 0;
}

static int32_t xma_la_init(XmaFilterSession *sess)
{
    openlog("XMA_Lookahead", LOG_PID, LOG_USER);

    xlnx_la_t *ctx = sess->base.plugin_data;
    XmaFilterProperties *filter_props = &sess->props;
    XmaParameter *extParam = NULL;
    uint32_t pc = 0;

    if ((filter_props->input.format != XMA_VCU_NV12_FMT_TYPE) &&
            (filter_props->input.format != XMA_VCU_NV12_10LE32_FMT_TYPE)
       ) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "xma_la_init: input Format %d not supported", filter_props->input.format);
        return -1;
    }
    ctx->in_frame_format = filter_props->input.format;
    syslog(LOG_DEBUG, "xma_la_handle = %p\n", ctx);
    clock_gettime (CLOCK_REALTIME, &ctx->latency);
    ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
    syslog(LOG_DEBUG, "%s : %p : xma_LA init start at %lld \n", __func__, ctx,
           ctx->time_taken);

    memset(ctx, 0, sizeof(xlnx_la_t));

    ctx->width = filter_props->input.width;
    ctx->height = filter_props->input.height;
    ctx->in_stride = filter_props->input.stride;

    if (filter_props->input.bits_per_pixel == 8) {
        ctx->bpc_mode = EBPCMode8;
    } else if (filter_props->input.bits_per_pixel == 10) {
        ctx->bpc_mode = EBPCMode10;
    } else {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "xma_la_init: bits_per_pixel = %u Invalid", filter_props->input.bits_per_pixel);
        return XMA_ERROR;
    }

    ctx->in_frame = 0;
    ctx->out_frame = 0;
    ctx->write_mv = 0;
    if ((ctx->width >= MAX_HOR_RES) && (ctx->height >= MAX_VERT_RES)) {
        ctx->skip_l2 = 0;
    } else {
        ctx->skip_l2 = 1;
    }

    ctx->enableHwInBuf = XLNX_DEFAULT_ENABLE_HW_IN_BUF;
    ctx->intraPeriod = XLNX_DEFAULT_INTRA_PERIOD;
    ctx->lookahead_depth = XLNX_DEFAULT_LA_DEPTH;
    ctx->spatial_aq_mode = XLNX_DEFAULT_SPATIAL_AQ_MODE;
    ctx->spatial_aq_gain = XLNX_DEFAULT_SPATIAL_AQ_GAIN;
    ctx->temporal_aq_mode = XLNX_DEFAULT_TEMPORAL_AQ_MODE;
    ctx->num_b_frames = XLNX_DEFAULT_NUM_OF_B_FRAMES;
    ctx->codec_type = XLNX_DEFAULT_CODEC_TYPE;
    ctx->rate_control_mode = XLNX_DEFAULT_RATE_CONTROL_MODE;
    ctx->latency_logging = XLNX_DEFAULT_LATENCY_LOGGING;
    ctx->use_out_length = 0;
    ctx->frame_num = 0;
    ctx->is_first_ref_frame = 1;

    for (pc = 0; pc < filter_props->param_cnt; pc++) {
        extParam = &filter_props->params[pc];
        switch (extParam->user_type) {
            case EParamIntraPeriod:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamIntraPeriod])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->intraPeriod = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->intraPeriod);
                break;
            case EParamLADepth:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamLADepth])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->lookahead_depth = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->lookahead_depth);
                break;
            case EParamEnableHwInBuf:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamEnableHwInBuf])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->enableHwInBuf = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->enableHwInBuf);
                break;
            case EParamSpatialAQMode:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamSpatialAQMode])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->spatial_aq_mode = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->spatial_aq_mode);
                break;
            case EParamTemporalAQMode:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamTemporalAQMode])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->temporal_aq_mode = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->temporal_aq_mode);
                break;
            case EParamRateControlMode:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamRateControlMode])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->rate_control_mode = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->rate_control_mode);
                break;
            case EParamSpatialAQGain:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamSpatialAQGain])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->spatial_aq_gain = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->spatial_aq_gain);
                break;
            case EParamNumBFrames:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamNumBFrames])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->num_b_frames = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->num_b_frames);
                break;
            case EParamCodecType:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamCodecType])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->codec_type = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->codec_type);
                break;
            case EParamLatencyLogging:
                if ((extParam->type != XMA_UINT32) ||
                        strcmp(extParam->name, XLNX_LA_EXT_PARAMS[EParamLatencyLogging])) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                               "xma_la_init: Ext Param %s of type %d Invalid", extParam->name,
                               extParam->type);
                    return -1;
                }
                ctx->latency_logging = *((uint32_t *)extParam->value);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Set ext param %s = %u", extParam->name,
                           ctx->latency_logging);
                break;
            default:
                xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                           "xma_la_init: Unknown ext Param %s ignored", extParam->name);
                break;
        }
    }
    RET_IF_ERR(check_la_settings, ctx);
    ctx->actual_mb_w = xlnx_align_to_base(ctx->width, 16) / 16;
    ctx->actual_mb_h = xlnx_align_to_base(ctx->height, 16) / 16;
    ctx->qpmap_size = ctx->actual_mb_w * ctx->actual_mb_h;
    if (ctx->codec_type == EXlnxHevc) {
        ctx->qpmap_out_size = (xlnx_align_to_base(ctx->width,
                               32) * xlnx_align_to_base(ctx->height, 32)) / (32 * 32);
    } else {
        ctx->qpmap_out_size = ctx->qpmap_size;
    }

    //printf("qpmap_size=%u\n\n", ctx->qpmap_size);
    ctx->num_mb = ((filter_props->output.width * filter_props->output.height)/
                   (BLOCK_WIDTH * BLOCK_HEIGHT));

    if ((ctx->enableHwInBuf) && (ctx->lookahead_depth >= 1)) {
        ctx->bufpool_ext_req = 1;
    } else {
        ctx->bufpool_ext_req = 0;
    }
    RET_IF_ERR(init_qpmap_generator, sess);
    RET_IF_ERR(xma_alloc_mem_res, sess);

    CLEANUP_IF_ERR(sess, init_krnl_regs, sess);

    ctx->isKrnlRunning = 0;

    //XLNX_TL_CREATE(ctx->la_plg_tl);
    //XLNX_TL_CREATE(ctx->dma_tl);
    //XLNX_TL_CREATE(ctx->krnl_thread_tl);

    ctx->eos_received = 0;
    ctx->inEOS = 0;

    if (pthread_mutex_init(&ctx->cfg_lock, NULL) < 0) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "Init: Failed to create mutex lock");
        return -1;
    }

    ctx->krnl_thread = xlnx_thread_create();
    xlnx_thread_param paramStart;
    paramStart.func = krnl_driver;
    paramStart.arg = sess;
    CLEANUP_IF_ERR(sess, xlnx_thread_start, ctx->krnl_thread, &paramStart);

    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "Init: Buffer allocation complete...");
#ifdef ENABLE_YUV_DUMP
    char fstr[512];
    sprintf(fstr, "la_plg_input_%u_%u_%p.yuv", ctx->width, ctx->height, ctx);
    ctx->inFile = fopen(fstr, "wb");
    if (NULL == ctx->inFile) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "Init: Failed to open %s", fstr);
    }
#endif //ENABLE_YUV_DUMP

    clock_gettime (CLOCK_REALTIME, &ctx->latency);
    ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
    syslog(LOG_DEBUG, "%s : %p : xma_LA init finished at %lld \n", __func__, ctx,
           ctx->time_taken);

    return 0;
}

static int32_t unblock_queues(xlnx_la_mem_res_t *memRes)
{
    if (memRes->freeHwInBufQ) {
        unBlockTSQ(memRes->freeHwInBufQ);
    }
    if (memRes->readyHwInBufQ) {
        unBlockTSQ(memRes->readyHwInBufQ);
    }
    if (memRes->waitForVQInfoQ) {
        unBlockTSQ(memRes->waitForVQInfoQ);
    }
    if (memRes->freeVQInfoQ) {
        unBlockTSQ(memRes->freeVQInfoQ);
    }
    if (memRes->readyVQInfoQ) {
        unBlockTSQ(memRes->readyVQInfoQ);
    }
    return 0;
}

#ifdef ENABLE_YUV_DUMP
static void write_dev_buf_to_file(xlnx_la_t *ctx, xlnx_la_buf_t *buf)
{
    if (!buf ||  !buf->pHost || !buf->size) {
        return;
    }
    memset(buf->pHost, 0, buf->size);
    if (xvbm_buffer_read(buf->xvbmBuf, buf->pHost, buf->size, 0)) {
        fprintf(stderr, "write_dev_buf_to_file: Failed to read device side buffer!!\n");
        return;
    }
    fwrite(buf->pHost, buf->size, 1, ctx->inFile);
}
#endif//ENABLE_YUV_DUMP

static void push_to_free_in_q(xlnx_la_mem_res_t *memRes, xlnx_la_buf_t *buf)
{
    if (!buf) {
        return;
    }
    memset(buf, 0, sizeof(xlnx_la_buf_t));
    PushTSQ(memRes->freeHwInBufQ, &buf);
}

static xlnx_thread_func_ret_t run_hw(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    XmaSession xma_sess = sess->base;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    uint64_t paddr = 0;
    int ret = -1;

    if(memRes->ref_in_buf == NULL) {
        if(PopTSQ_b(memRes->readyHwInBufQ, &memRes->ref_in_buf)) {
            unblock_queues(memRes);
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : run_hw ref User aborted, so exit!!", ctx);
            return ERetDone;
        }
        if(memRes->ref_in_buf == NULL) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : run_hw ref got EOS, so exit!!", ctx);
            ctx->eos_received = 1;
            return ERetDone;
        }
        memRes->cur_in_buf = memRes->ref_in_buf;
    } else {
        if (PopTSQ(memRes->readyHwInBufQ, &memRes->cur_in_buf)) {
            //printf("%p : LA Plugin is waiting for input buffer!!\n", ctx);
            if (isEmpty(memRes->readyStatsBufQ) == 0) {
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "%p : run_hw I/P buff not avaialable, last krnl O/P(%d) waiting", ctx,
                           getSize(memRes->readyStatsBufQ));
                return ERetRunAgain;
            }
            if (PopTSQ_b(memRes->readyHwInBufQ, &memRes->cur_in_buf)) {
                unblock_queues(memRes);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "%p : run_hw User aborted, so exit!!", ctx);
                return ERetDone;
            }
        }
        if(memRes->cur_in_buf->size == 0) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : run_hw got EOS, so exit!!", ctx);
            ctx->eos_received = 1;
            if (memRes->ref_in_buf) {
                if (ctx->lookahead_depth != 0) {
                    if (PushTSQ_b(memRes->waitForVQInfoQ, &memRes->ref_in_buf)) {
                        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                                   "%p : run_hw EOS releasing ref=%lx failed", ctx, memRes->ref_in_buf->paddr);
                        return XMA_ERROR;
                    }
                }
                memRes->ref_in_buf = NULL;
            }
            return ERetDone;
        }
    }
    PopQ(memRes->freeStatsBufQ, &ctx->stats_buf);
    if (ctx->lookahead_depth == 0) {
        memRes->ref_in_buf = memRes->cur_in_buf;
    }
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "%p : Set Krnl Regs XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_SRCH_V_DATA=%lx XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_REF_V_DATA=%lx out=%lx xma_sess=%p",
               ctx,
               memRes->ref_in_buf->paddr, memRes->cur_in_buf->paddr,
               ctx->stats_buf.paddr,
               xma_sess);

    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_SRCH_V_DATA,
            &(memRes->ref_in_buf->paddr),
            sizeof(uint64_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_FRM_BUFFER_REF_V_DATA,
            &(memRes->cur_in_buf->paddr),
            sizeof(uint64_t));
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_SAD_V_DATA, &(ctx->stats_buf.paddr),
            sizeof(uint64_t));

    paddr = ctx->stats_buf.paddr + memRes->mv_off;
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_MV_V_DATA, &paddr, sizeof(uint64_t));
    paddr = ctx->stats_buf.paddr + memRes->var_off;
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_VAR_V_DATA, &paddr, sizeof(uint64_t));
    paddr = ctx->stats_buf.paddr + memRes->act_off;
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_ACT_V_DATA, &paddr, sizeof(uint64_t));

    // set stride
    memcpy (ctx->ctrl + XV_MOT_EST_CTRL_ADDR_STRIDE_DATA, &(ctx->vcu_aligned_width),
            sizeof(uint32_t));

    /* Schedule execution of lookahead kernel */
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : START Krnl %p", ctx,
               xma_sess);
//    TH_RET_IF_ERR(xma_plg_schedule_work_item, hw_sess);
    xma_plg_schedule_work_item(xma_sess, ctx->ctrl,
                               XV_MOT_EST_CTRL_SIZE, &ret);
    if (ret != XMA_SUCCESS) {
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "failed to schedule work item, err= %d\n", ret);
        return ERetError;
    }
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : Krnl Started %p", ctx,
               xma_sess);
    ctx->isKrnlRunning = 1;
    return ERetRunAgain;
}

static void pump_out_qpmaps(xlnx_la_t *ctx, uint64_t frame_num)
{
    xlnx_aq_info_t vqInfo;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    xlnx_status algo_status = EXlnxSuccess;
    do {
        if (PopTSQ(memRes->freeVQInfoQ, &vqInfo)) {
            //printf("%p : LA Plugin is waiting for Output QP buffer!!\n", ctx);
            if (PopTSQ_b(memRes->freeVQInfoQ, &vqInfo)) {
                unblock_queues(memRes);
                xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                           "%p : pump_out_qpmaps User aborted, so exit!!", ctx);
                return;
            }
        }
        //algo_status = recv_frame_aq_info(ctx->qp_handle, &vqInfo);
        algo_status = recv_frame_aq_info(ctx->qp_handle, &vqInfo, frame_num,
                                         ctx->is_idr);
        if (EXlnxSuccess == algo_status) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : pump_out_qpmaps Push out generated vq info of frame = %lu", ctx,
                       vqInfo.frame_num);

            PushTSQ(memRes->readyVQInfoQ, &vqInfo);
            if (ctx->latency_logging) {
                if (vqInfo.frame_num == 0) {
                    clock_gettime (CLOCK_REALTIME, &ctx->latency);
                    ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
                    syslog(LOG_DEBUG, "%s : %p : xma_la_first_out_frame_available : %lld\n",
                           __func__, ctx,
                           ctx->time_taken);
                }
            }
        } else {
            PushTSQ(memRes->freeVQInfoQ, &vqInfo);
        }
    } while (EXlnxSuccess == algo_status);
}

static void set_frame_stats(xlnx_la_t *ctx, xlnx_frame_stats *stats,
                            const uint16_t *sad, const uint32_t *var,
                            const uint16_t *act, const uint32_t *mv)
{
    (void)mv;
    stats->mv = NULL;
    stats->sad = NULL;
    stats->var = NULL;
    stats->act = NULL;
    stats->num_blocks = ctx->num_mb;
    stats->mv = NULL;

    stats->var = var;
    if (ctx->spatial_aq_mode == XLNX_AQ_SPATIAL_ACTIVITY) {
        stats->act = act;
    }

    if (ctx->rate_control_mode) {
        stats->act = act;
    }

    stats->sad = sad;
}

static xlnx_thread_func_ret_t process_last_output(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    XmaSession xma_sess = sess->base;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    XmaBufferObj last_stats_buf;
    xlnx_frame_stats stats;
    uint32_t isLastFrameStat = 0;
    uint8_t *host_buf = NULL;
    xlnx_thread_func_ret_t ret_status = ERetRunAgain;

    if (isEmpty(memRes->readyStatsBufQ)) {
        if (ctx->eos_received) {
            set_frame_stats(ctx, &stats, NULL,
                            NULL,
                            NULL, NULL);
            if(send_frame_stats(ctx->qp_handle, ctx->frame_num+1, NULL, 1, ctx->is_idr) == EXlnxError) {
                return ERetError;
            }
            pump_out_qpmaps(ctx, ctx->frame_num+1);
            return ERetDone;
        } else {
            return ERetRunAgain;
        }
    }
    PopQ(memRes->readyStatsBufQ, &last_stats_buf);

    TH_RET_IF_ERR(xma_plg_buffer_read, xma_sess,
                  last_stats_buf,
                  ctx->use_out_length, 0);

    if (isEmpty(memRes->readyStatsBufQ) && ctx->eos_received) {
        isLastFrameStat = 1;
        ret_status = ERetDone;
    }
    host_buf = last_stats_buf.data;
    set_frame_stats(ctx, &stats,
                    (uint16_t *)host_buf,
                    (uint32_t *)(host_buf + memRes->var_off),
                    (uint16_t *)(host_buf + memRes->act_off), NULL);
    if(send_frame_stats(ctx->qp_handle, ctx->frame_num, &stats,
                     isLastFrameStat, ctx->is_idr) == EXlnxError) {
        return ERetError;
    }
    pump_out_qpmaps(ctx, ctx->frame_num);
    ctx->frame_num++;
    PushQ(memRes->freeStatsBufQ, &last_stats_buf);

    return ret_status;
}

static xlnx_thread_func_ret_t wait_for_hw(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    XmaSession xma_sess = sess->base;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;

    if (!ctx->isKrnlRunning) {
        return ERetRunAgain;
    }

    TH_RET_IF_ERR(xma_plg_is_work_item_done, xma_sess, KERNEL_WAIT_TIMEOUT);
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : Krnl DONE", ctx);
    ctx->isKrnlRunning = 0;
    //XLNX_TL_PAUSE(ctx->krnl_thread_tl);

    if (memRes->ref_in_buf) {
        if ((ctx->is_first_ref_frame == 0) || (ctx->lookahead_depth == 0)) {
            if (PushTSQ_b(memRes->waitForVQInfoQ, &memRes->ref_in_buf)) {
                xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                           "%p : wait_for_hw LA in error state!!", ctx);
                return XMA_ERROR;
            }
            memRes->ref_in_buf = NULL;
        } else {
            ctx->is_first_ref_frame = 0;
        }
    }

    memRes->ref_in_buf = memRes->cur_in_buf;

    ctx->is_idr = 0;
    if(ctx->frame_num > 0) {
        ctx->is_idr = memRes->cur_in_buf->xFrame.is_idr;
    }

    PushQ(memRes->readyStatsBufQ, &ctx->stats_buf);
    memRes->cur_in_buf = NULL;

    return ERetRunAgain;
}

static int send_frame_to_device(xlnx_la_t *ctx, xlnx_la_buf_t *labuf,
                                XmaFrame *frame)
{
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    XvbmBufferHandle b_handle = xvbm_buffer_pool_entry_alloc(memRes->pool);
    if(!b_handle) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "Error: (%s) Buffer Pool full - "
                   "no free buffer available", __func__);
        return XMA_ERROR;
    }
    uint8_t *device_buffer = (uint8_t *)xvbm_buffer_get_host_ptr(b_handle);
    uint8_t *src_buffer;
    uint16_t src_bytes_in_line  = frame->frame_props.linesize[0];
    uint16_t dev_bytes_in_line  = ctx->vcu_aligned_width;
    uint16_t src_height         = frame->frame_props.height;
    uint16_t dev_height         = ctx->vcu_aligned_height;
    size_t dev_y_size           = dev_bytes_in_line * dev_height;
    int ret                     = XMA_ERROR;

    if (src_bytes_in_line != dev_bytes_in_line) {
        uint16_t dev_rows_in_plane = dev_height;
        uint16_t src_rows_in_plane = src_height;
        int16_t stride_delta = dev_bytes_in_line - src_bytes_in_line;
        int16_t height_delta = dev_rows_in_plane - src_rows_in_plane;
        size_t dev_index = 0;
        for (int plane_id = 0; plane_id < xma_frame_planes_get(&frame->frame_props);
                plane_id++) {
            size_t src_index = 0;
            src_buffer = (uint8_t *)frame->data[plane_id].buffer;
            if(plane_id > 0) {
                dev_rows_in_plane = dev_height / 2;
                src_rows_in_plane = src_height / 2;
                height_delta = dev_rows_in_plane - src_rows_in_plane;
            }
            for(uint16_t h = 0; h < src_rows_in_plane && h < dev_rows_in_plane; h++) {
                for(uint16_t w = 0; w < src_bytes_in_line && w < dev_bytes_in_line; w++) {
                    device_buffer[dev_index] = src_buffer[src_index];
                    src_index++;
                    dev_index++;
                }
                if(stride_delta > 0) {
                    dev_index += stride_delta;
                } else {
                    src_index += -1 * stride_delta; // src > dev (higher alignment)
                }
            }
            if(height_delta > 0) {
                dev_index += dev_bytes_in_line * height_delta;
            } // No else necessary because src_index resets.
        }
        XLNX_TL_START(ctx->dma_tl);
        ret = xvbm_buffer_write(b_handle, device_buffer,
                                (3 * dev_y_size) >> 1, 0);
        XLNX_TL_PAUSE(ctx->dma_tl);
    } else {
        size_t src_y_size = src_bytes_in_line * src_height;
        XLNX_TL_START(ctx->dma_tl);
        ret = xvbm_buffer_write(b_handle, frame->data[0].buffer, src_y_size, 0);
        if (!ret) {
            ret = xvbm_buffer_write(b_handle, frame->data[1].buffer, src_y_size >> 1,
                                    dev_y_size);
        }
        XLNX_TL_PAUSE(ctx->dma_tl);
    }
    if (ret == XMA_SUCCESS) {
        labuf->xvbmBuf = b_handle;
    } else {
        xvbm_buffer_pool_entry_free(b_handle);
        labuf->xvbmBuf = NULL;
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "Error: (%s) DMA to device failed", __func__);
    }

    return ret;
}

static int prepare_n_push_ready_buf(xlnx_la_t *ctx,
                                    XmaFrame *frame)
{
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    xlnx_la_buf_t *la_buf = NULL;

    if (memRes->cur_ready_buf != NULL) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : prepare_n_push_ready_buf invalid state!!", ctx);
        return XMA_ERROR;
    }
    if (PopTSQ_b(memRes->freeHwInBufQ, &la_buf)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : prepare_n_push_ready_buf LA in error state!!", ctx);
        return XMA_ERROR;
    }
    memRes->cur_ready_buf = la_buf;
    if (frame) {
        XmaSideDataHandle *side_data = la_buf->xFrame.side_data;
        memcpy(&la_buf->xFrame, frame, sizeof (XmaFrame));
        la_buf->xFrame.side_data = side_data;

        XmaSideDataHandle dynparam_sd = xma_frame_get_side_data(frame, XMA_FRAME_DYNAMIC_PARAMS);
        if(dynparam_sd) {
            xlnx_dyn_param_t *dynparam_ptr = (xlnx_dyn_param_t *)xma_side_data_get_buffer(dynparam_sd);
            if(dynparam_ptr->la_dyn_param.is_spatial_mode_changed) {
                ctx->spatial_aq_mode = dynparam_ptr->la_dyn_param.spatial_aq_mode;
            }
            if(dynparam_ptr->la_dyn_param.is_temporal_mode_changed) {
                ctx->temporal_aq_mode = dynparam_ptr->la_dyn_param.temporal_aq_mode;
            }
            if(dynparam_ptr->la_dyn_param.is_spatial_gain_changed) {
                ctx->spatial_aq_gain = dynparam_ptr->la_dyn_param.spatial_aq_gain;
            }
            if(dynparam_ptr->enc_dyn_param.is_bframes_changed) {
                ctx->num_b_frames = dynparam_ptr->enc_dyn_param.num_b_frames;
            }

            ctx->qpmap_cfg.spatial_aq_mode = ctx->spatial_aq_mode;
            ctx->qpmap_cfg.temporal_aq_mode = ctx->temporal_aq_mode;
            ctx->qpmap_cfg.spatial_aq_gain = ctx->spatial_aq_gain;
            ctx->qpmap_cfg.num_b_frames = ctx->num_b_frames;
            XmaSideDataHandle dynparam_handle = xma_side_data_alloc(dynparam_ptr, 
                                           XMA_FRAME_DYNAMIC_PARAMS, sizeof(xlnx_enc_dyn_Param_t), 0);
            xma_frame_add_side_data(&la_buf->xFrame, dynparam_handle);
            xma_side_data_dec_ref(dynparam_handle);
            xma_frame_remove_side_data_type(frame, XMA_FRAME_DYNAMIC_PARAMS);
        }
        LOCK_CFG;
        update_aq_modes(ctx->qp_handle, &ctx->qpmap_cfg);
        UNLOCK_CFG;

        XmaSideDataHandle hdr_sd = xma_frame_get_side_data(frame, XMA_FRAME_HDR);
        if(hdr_sd) {
            xma_frame_add_side_data(&la_buf->xFrame, hdr_sd);
            xma_frame_remove_side_data(frame, hdr_sd);
        }

        if (ctx->enableHwInBuf) {
            la_buf->xvbmBuf = (XvbmBufferHandle)(frame->data[0].buffer);
            la_buf->pHost = (uint8_t *)xvbm_buffer_get_host_ptr(la_buf->xvbmBuf);
            xvbm_buffer_refcnt_inc(la_buf->xvbmBuf);
        } else {
            if (send_frame_to_device(ctx, la_buf, frame) <= XMA_ERROR) {
                xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN, "send_frame_to_device %p : Failed!!",
                           ctx);
                push_to_free_in_q(memRes, memRes->cur_ready_buf);
                memRes->cur_ready_buf = NULL;
                return XMA_ERROR;
            }
            la_buf->xFrame.data[0].buffer = la_buf->xvbmBuf;
            la_buf->xFrame.data[0].buffer_type = XMA_DEVICE_BUFFER_TYPE;
            la_buf->xFrame.frame_props.format = ctx->in_frame_format;
            la_buf->xFrame.frame_props.linesize[0] = ctx->vcu_aligned_width;
            //@TODO remove this dirty hack
            // This is required for the downstream componen to know the chroma offset
            la_buf->xFrame.frame_props.linesize[1] = ctx->vcu_aligned_height;
            xvbm_buffer_refcnt_inc(la_buf->xvbmBuf);
        }
        la_buf->paddr = (uint64_t) xvbm_buffer_get_paddr(la_buf->xvbmBuf);
        la_buf->size = (uint64_t) xvbm_buffer_get_size(la_buf->xvbmBuf);
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : prepare_n_push_ready_buf New in buff=%p size=%u", ctx,
                   la_buf->paddr, la_buf->size);
#ifdef ENABLE_YUV_DUMP
        write_dev_buf_to_file(ctx, la_buf);
#endif //#ifdef ENABLE_YUV_DUMP
    }
    if (PushTSQ_b(memRes->readyHwInBufQ, &memRes->cur_ready_buf)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : prepare_n_push_ready_buf LA in error state!!", ctx);
        if (memRes->cur_ready_buf) {
            push_to_free_in_q(memRes, memRes->cur_ready_buf);
            memRes->cur_ready_buf = NULL;
        }
        return XMA_ERROR;
    }
    memRes->cur_ready_buf = NULL;
    return 0;
}

static int extend_input_bufpool(XvbmBufferHandle b_handle,
                                uint32_t extension_count)
{
    uint32_t num = xvbm_buffer_pool_num_buffers_get(b_handle);
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "LA plg Request to extend LA input pool(%d) by %d buffers", num,
               extension_count);
    /* TODO: if the incoming pool is shared between multiple instances,
       the the pool is extended multiple times. Need to add a proper check to avoid this.
    */
    uint32_t cnt = xvbm_buffer_pool_extend(b_handle, extension_count);
    if (cnt != num + extension_count) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "OOM: LA plg Failed to extend LA input pool by %d buffers", extension_count);
        return XMA_ERROR;
    }
    return XMA_SUCCESS;
}

static int32_t xma_la_send_frame(XmaFilterSession *sess,
                                 XmaFrame *frame)
{
    xlnx_la_t         *ctx    = sess->base.plugin_data;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;

    if (ctx->inEOS) {
        if (frame && frame->data[0].buffer) {
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                       "%p : xma_la_send_frame OUT, EOS notified, in frame = %p", ctx, frame);
            return XMA_ERROR;
        }
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_send_frame OUT, EOS notified, in frame = NULL", ctx);
        return XMA_SUCCESS;
    }
    if (frame && frame->do_not_encode) {
        if (ctx->enableHwInBuf && frame->data[0].buffer) {
            xvbm_buffer_pool_entry_free(frame->data[0].buffer);
        }
        if (frame->is_last_frame || (frame->data[0].buffer == NULL)) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : EOS Received!!", ctx);
            ctx->inEOS = 1;
            RET_IF_ERR(prepare_n_push_ready_buf, ctx, NULL);
        }
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_send_frame OUT, in frame = %p with do_not_encode",
                   ctx, frame);
        return XMA_SEND_MORE_DATA;
    }

    XLNX_TL_START(ctx->la_plg_tl);
    if (ctx->latency_logging) {
        clock_gettime (CLOCK_REALTIME, &ctx->latency);
        ctx->frame_sent++;
        ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
        syslog(LOG_DEBUG, "%s : %p : xma_la_frame_sent %lld : %lld\n", __func__, ctx,
               ctx->frame_sent,
               ctx->time_taken);
        if (ctx->in_frame == 0) {
            syslog(LOG_DEBUG, "%s : %p : xma_la_first_frame_in : %lld\n", __func__,
                   ctx,
                   ctx->time_taken);
        }
    }

    if(isFullTSQ(memRes->readyVQInfoQ)) {
        XLNX_TL_PAUSE(ctx->la_plg_tl);
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_send_frame OUT, out Q is full, so XMA_TRY_AGAIN", ctx);
        return XMA_TRY_AGAIN;
    }
    if (frame && frame->data[0].buffer) {
        if (ctx->enableHwInBuf) {
            if (ctx->bufpool_ext_req) {
                if (ctx->latency_logging) {
                    clock_gettime (CLOCK_REALTIME, &ctx->latency);
                    ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
                    syslog(LOG_DEBUG, "%s : %p : xma_extend_la start at %lld\n", __func__, ctx,
                           ctx->time_taken);
                }

                if (extend_input_bufpool(frame->data[0].buffer, ctx->lookahead_depth + 1)) {
                    return XMA_ERROR;
                }

                if (ctx->latency_logging) {
                    clock_gettime (CLOCK_REALTIME, &ctx->latency);
                    ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
                    syslog(LOG_DEBUG, "%s : %p : xma_extend_la end at %lld\n", __func__, ctx,
                           ctx->time_taken);
                }
            }
            ctx->bufpool_ext_req = 0;
            if (frame->frame_props.linesize[0] != ctx->vcu_aligned_width) {
                ctx->vcu_aligned_width = frame->frame_props.linesize[0];
            }
        }
        RET_IF_ERR(prepare_n_push_ready_buf, ctx, frame);
        if (frame->is_last_frame) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : EOS Received!!", ctx);
            ctx->inEOS = 1;
            RET_IF_ERR(prepare_n_push_ready_buf, ctx, NULL);
        }
        ctx->in_frame++;
    } else {
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN, "%p : EOS Received!!", ctx);
        ctx->inEOS = 1;
        RET_IF_ERR(prepare_n_push_ready_buf, ctx, NULL);
    }

    XLNX_TL_PAUSE(ctx->la_plg_tl);

    if ((ctx->in_frame <= ctx->lookahead_depth) && (!ctx->inEOS)) {
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_send_frame OUT XMA_SEND_MORE_DATA in_frame=%d", ctx,
                   ctx->in_frame);
        return XMA_SEND_MORE_DATA;
    }
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "%p : xma_la_send_frame OUT XMA_SUCCESS in_frame=%d", ctx, ctx->in_frame);
    return XMA_SUCCESS;
}

static int32_t xma_la_recv_data(XmaFilterSession *sess,
                                XmaFrame         *frame)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    xlnx_aq_info_t vq_info;
    void *sd_ptr = NULL;
    size_t sd_size = 0;
    XmaSideDataHandle sd = 0;
    xlnx_la_buf_t *outBuf = NULL;
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "%p : xma_la_recv_data IN", ctx);
    XLNX_TL_START(ctx->la_plg_tl);

    if (isEmptyTSQ(memRes->readyVQInfoQ)) {
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_recv_data QpMap not ready, in frames=%u, out frames=%u, ctx->inEOS=%u",
                   ctx, ctx->in_frame, ctx->out_frame, ctx->inEOS);
        if (((ctx->in_frame - ctx->out_frame) <= ctx->lookahead_depth) &&
                (ctx->inEOS == 0)) {
            XLNX_TL_PAUSE(ctx->la_plg_tl);
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : xma_la_recv_data OUT Queued frames = %u ctx->lookahead_depth=%u",
                       ctx, (ctx->in_frame - ctx->out_frame), ctx->lookahead_depth);
            return XMA_SEND_MORE_DATA;
        } else if ((ctx->inEOS == 1) && (ctx->in_frame == ctx->out_frame)) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : xma_la_recv_data OUT XMA_EOS", ctx);
            return XMA_EOS;
        }
        xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_recv_data Wait for qpmap", ctx);
    }
    if (isEmptyTSQ(memRes->waitForVQInfoQ)) {
        int min_diff = 1;
        if (ctx->temporal_aq_mode !=0) {
            min_diff = 2;
        }
        if (((ctx->in_frame - ctx->out_frame) < min_diff) && (ctx->inEOS == 0)) {
            xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
                       "%p : xma_la_recv_data XMA_SEND_MORE_DATA in_frame=%u out_frame=%u", ctx,
                       ctx->in_frame, ctx->out_frame);
            return XMA_SEND_MORE_DATA;
        }
    }
    if (PopTSQ_b(memRes->waitForVQInfoQ, &outBuf)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_recv_data LA in error state!!", ctx);
        return XMA_ERROR;
    }

    if (PopTSQ_b(memRes->readyVQInfoQ, &vq_info)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : xma_la_recv_data LA in error state!!", ctx);
        if (outBuf->xvbmBuf) {
            xvbm_buffer_pool_entry_free(outBuf->xvbmBuf);
        }
        push_to_free_in_q(memRes, outBuf);
        return XMA_ERROR;
    }
    XmaSideDataHandle *side_data = frame->side_data;
    memcpy (frame, &outBuf->xFrame, sizeof (XmaFrame));
    frame->side_data = side_data;

    XmaSideDataHandle dynparam_sd = xma_frame_get_side_data(&outBuf->xFrame, XMA_FRAME_DYNAMIC_PARAMS);
    if(dynparam_sd) {
        xma_frame_add_side_data(frame, dynparam_sd);
    }

    XmaSideDataHandle hdr_sd = xma_frame_get_side_data(&outBuf->xFrame, XMA_FRAME_HDR);
    if(hdr_sd) {
        xma_frame_add_side_data(frame, hdr_sd);
    }

    /* Clear out the side data in the intermediate xmaframe */
    if(dynparam_sd || hdr_sd) {
        xma_frame_clear_all_side_data(&outBuf->xFrame);
    }

    if (outBuf->xvbmBuf) {
        xvbm_buffer_pool_entry_free(outBuf->xvbmBuf);
    }

    push_to_free_in_q(memRes, outBuf);

    if (vq_info.qpmap.ptr) {
        sd = xma_frame_get_side_data(frame, XMA_FRAME_QP_MAP);
        if (sd) {
            sd_ptr = xma_side_data_get_buffer(sd);
            sd_size = xma_side_data_get_size(sd);
            if (sd_size != ctx->qpmap_out_size) {
                xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                           "%p : sd_size != ctx->qpmap_out_size!!", ctx);
                return XMA_ERROR;
            }
            memcpy(sd_ptr, vq_info.qpmap.ptr, ctx->qpmap_out_size);
        } else {
            sd = xma_side_data_alloc(vq_info.qpmap.ptr, XMA_FRAME_QP_MAP,
                                     vq_info.qpmap.size, 0);
            xma_frame_add_side_data(frame, sd);
            /* Do not hold on to the side data buffer
            Let it be released when xma frame is freed */
            xma_side_data_free(sd);
        }
    }
    if (ctx->rate_control_mode) {
        sd = xma_frame_get_side_data(frame, XMA_FRAME_RC_FSFA);
        if (sd) {
            sd_ptr = xma_side_data_get_buffer(sd);
            sd_size = xma_side_data_get_size(sd);
            if (sd_size != vq_info.fsfa.size) {
                xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                           "%p : sd_size != vq_info.fsfa.size!!", ctx);
                return XMA_ERROR;
            }
            memcpy(sd_ptr, vq_info.fsfa.ptr, vq_info.fsfa.size);
        } else {
            sd = xma_side_data_alloc(vq_info.fsfa.ptr, XMA_FRAME_RC_FSFA,
                                     vq_info.fsfa.size, 0);
            xma_frame_add_side_data(frame, sd);
            /* Do not hold on to the side data buffer
            Let it be released when xma frame is freed */
            xma_side_data_free(sd);
        }
    }

    PushTSQ(memRes->freeVQInfoQ, &vq_info);

    ctx->out_frame++;
    if (ctx->latency_logging) {
        clock_gettime (CLOCK_REALTIME, &ctx->latency);
        ctx->frame_recv++;
        ctx->time_taken = (ctx->latency.tv_sec * 1e3) + (ctx->latency.tv_nsec / 1e6);
        syslog(LOG_DEBUG, "%s : %p : xma_la_frame_recv %lld : %lld\n", __func__, ctx,
               ctx->frame_recv,
               ctx->time_taken);
        if (ctx->out_frame == 1) {
            syslog(LOG_DEBUG, "%s : %p : xma_la_first_frame_out : %lld\n", __func__,
                   ctx,
                   ctx->time_taken);
        }
    }
    XLNX_TL_PAUSE(ctx->la_plg_tl);
    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "%p : xma_la_recv_data OUT out_frame=%u", ctx, ctx->out_frame);
    return XMA_SUCCESS;
}

static void cleanup_krnl_driver_thread(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    xlnx_aq_info_t vq_info;
    xlnx_la_buf_t *tmp_buf;
    xlnx_thread_t  krnl_thread = ctx->krnl_thread;
    if (krnl_thread) {
        xlnx_thread_state_t state;
        xlnx_thread_get_state(krnl_thread, &state);
        if (state == EXlnxThreadStarted || state == EXlnxThreadStart) {
            while (!isEmptyTSQ(memRes->readyHwInBufQ)) {
                tmp_buf = NULL;
                PopTSQ(memRes->readyHwInBufQ, &tmp_buf);
                if (tmp_buf->xvbmBuf) {
                    xvbm_buffer_pool_entry_free(tmp_buf->xvbmBuf);
                }
                push_to_free_in_q(memRes, tmp_buf);
            }
            prepare_n_push_ready_buf(ctx, NULL);
            while (!isEmptyTSQ(memRes->waitForVQInfoQ)) {
                tmp_buf = NULL;
                PopTSQ(memRes->waitForVQInfoQ, &tmp_buf);
                if (tmp_buf->xvbmBuf) {
                    xvbm_buffer_pool_entry_free(tmp_buf->xvbmBuf);
                }
                push_to_free_in_q(memRes, tmp_buf);
            }

            while (!isEmptyTSQ(memRes->readyVQInfoQ)) {
                PopTSQ(memRes->readyVQInfoQ, &vq_info);
                PushTSQ(memRes->freeVQInfoQ, &vq_info);
            }
            xlnx_thread_stop(krnl_thread);
        }
        xlnx_thread_destroy(krnl_thread);
    }
    ctx->krnl_thread = NULL;
}

static xlnx_thread_func_ret_t krnl_driver(xlnx_thread_func_args_t  args)
{
    XmaFilterSession *sess = (XmaFilterSession *) args;
    xlnx_thread_func_ret_t ret;
    if (!sess) {
        return ERetError;
    }

    xlnx_la_t *ctx = sess->base.plugin_data;
    xlnx_la_mem_res_t *memRes = &ctx->la_bufs;
    XLNX_TL_START(ctx->krnl_thread_tl);

    ret = run_hw(sess);
    if (ret == ERetError) {
        XLNX_TL_PAUSE(ctx->krnl_thread_tl);
        unblock_queues(memRes);
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : krnl_driver run_hw failed, so exit!!", ctx);
        return ret;
    }

    LOCK_CFG;
    ret = process_last_output(sess);
    UNLOCK_CFG;
    if (ret != ERetRunAgain) {
        XLNX_TL_PAUSE(ctx->krnl_thread_tl);
        if (ret == ERetError) {
            unblock_queues(memRes);
            xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                       "%p : krnl_driver read failed, so exit!!", ctx);
        }
        return ret;
    }

    ret = wait_for_hw(sess);
    if (ret == ERetError) {
        unblock_queues(memRes);
        xma_logmsg(XMA_ERROR_LOG, XMA_LA_PLUGIN,
                   "%p : krnl_driver Kernel Timeout, so exit!!", ctx);
    }
    XLNX_TL_PAUSE(ctx->krnl_thread_tl);
    return ret;
}

static int32_t xma_la_close(XmaFilterSession *sess)
{
    xlnx_la_t *ctx = sess->base.plugin_data;
    cleanup_krnl_driver_thread(sess);
    pthread_mutex_destroy(&ctx->cfg_lock);

    char strbuf[512];
    if (ctx->la_plg_tl) {
        sprintf(strbuf, "lookahead_plg_perf_%u_%u_%p", ctx->width,
                ctx->height, ctx);
        XLNX_TL_DUMP_RESULTS(ctx->la_plg_tl, &strbuf[0], ctx->in_frame);
        XLNX_TL_DESTROY(ctx->la_plg_tl);
    }
    if (ctx->dma_tl) {
        sprintf(strbuf, "lookahead_dma_perf_%u_%u_%p", ctx->width,
                ctx->height, ctx);
        XLNX_TL_DUMP_RESULTS(ctx->dma_tl, &strbuf[0], ctx->in_frame);
        XLNX_TL_DESTROY(ctx->dma_tl);
    }
    if (ctx->krnl_thread_tl) {
        sprintf(strbuf, "krnl_thread_perf_%u_%u_%p", ctx->width,
                ctx->height, ctx);
        XLNX_TL_DUMP_RESULTS(ctx->krnl_thread_tl, &strbuf[0],
                             ctx->in_frame);
        XLNX_TL_DESTROY(ctx->krnl_thread_tl);
        ctx->krnl_thread_tl = NULL;
    }

    xma_release_mem_res(sess);

    xma_logmsg(XMA_DEBUG_LOG, XMA_LA_PLUGIN,
               "Released lookahead plugin resources!");
#ifdef ENABLE_YUV_DUMP
    if (ctx->inFile) {
        fclose(ctx->inFile);
        ctx->inFile = NULL;
    }
#endif //ENABLE_YUV_DUMP

    closelog();

    return 0;
}

static int32_t xma_la_version(int32_t *main_version, int32_t *sub_version)
{
    *main_version = 2020;
    *sub_version = 1;

    return 0;
}

XmaFilterPlugin filter_plugin = {
    .hwfilter_type = XMA_2D_FILTER_TYPE,
    .hwvendor_string = "Xilinx",
    .plugin_data_size = sizeof(xlnx_la_t),
    .init = xma_la_init,
    .send_frame = xma_la_send_frame,
    .recv_frame = xma_la_recv_data,
    .close = xma_la_close,
    .xma_version = xma_la_version
};

