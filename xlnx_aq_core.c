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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <xma.h>
#include "xlnx_aq_core.h"
#include "xlnx_rc_aq.h"
#include "xlnx_spatial_aq.h"
#include "xlnx_la_defines.h"

#define XMA_XLNX_ALGOS "xlnx_aq_core"

static const uint32_t XLNX_MIN_QP = 9;
static const uint32_t XLNX_MAX_QP = 0;

struct xlnx_aq_core_ctx;
typedef struct xlnx_tp_qpmap
{
    xlnx_aq_buf_t qpmap;
    uint32_t inUse;
    uint64_t frame_num;
} xlnx_tp_qpmap_t;

typedef void *xlnx_aq_dump_t;
typedef void *xlnx_qpmap_store_t;

static int32_t xlnx_temporal_gen_qpmap(struct xlnx_aq_core_ctx *ctx,
                                       const uint16_t *sadIn, uint64_t frame_num, uint32_t *frameSAD,
                                       xlnx_tp_qpmap_t *outMapCtx);
static int32_t xlnx_temporal_gen_la_qpmap(struct xlnx_aq_core_ctx *ctx,
        xlnx_tp_qpmap_t *outMapCtx);

typedef enum
{
    ENoneType,
    EIType,
    EPType
} QpMapType;

typedef struct xlnx_qpmap_store_ctx
{
    xlnx_tp_qpmap_t *maps;
    uint32_t numQPMaps;
} xlnx_qpmap_store_ctx_t;

typedef struct xlnx_ap_dump_ctx
{
    xlnx_aq_dump_cfg dumpCfg;
    aq_config_t cfg;
} xlnx_ap_dump_ctx_t;

typedef struct xlnx_aq_core_ctx
{
    aq_config_t cfg;
    uint64_t accumulatedSadFrames;
    uint8_t isDeltaQpMapLAPending;
    uint32_t *collocatedSadLA;
    xlnx_qpmap_store_t qpStore;
    xlnx_aq_dump_t dump_handle;
    uint32_t write_idx;
    uint32_t read_idx;
    xlnx_tp_qpmap_t *laMapCtx;
    uint32_t spatial_aq_mode;
    uint32_t temporal_aq_mode;
    uint32_t rate_control_mode;
    uint32_t num_mb;
    uint8_t qpmaps_enabled;
    xlnx_rc_aq_t rc_h;
    xlnx_spatial_aq_t sp_h;
    xlnx_codec_type_t codec_type;
    int32_t *tmp_hevc_map;
} xlnx_aq_core_ctx_t;

static xlnx_qpmap_store_t create_qp_map_store(aq_config_t *cfg)
{
    xlnx_tp_qpmap_t *maps;
    xlnx_tp_qpmap_t *tp_qpmap;
    uint32_t numL1Lcu;
    xlnx_qpmap_store_ctx_t *store = calloc(1, sizeof(xlnx_qpmap_store_ctx_t));
    if (!store) {
        return NULL;
    }
    store->numQPMaps = cfg->la_depth + 1;
    maps = (xlnx_tp_qpmap_t *)calloc(store->numQPMaps, sizeof(xlnx_tp_qpmap_t));
    if (!maps) {
        free(store);
        return NULL;
    }
    //@TODO +1 recomemded???????
    numL1Lcu = cfg->num_mb + 1;

    for (uint32_t i = 0; i < store->numQPMaps; i++) {
        tp_qpmap = &maps[i];
        xlnx_aq_buf_t *qpmap = &tp_qpmap->qpmap;
        qpmap->ptr = (uint8_t *)calloc(1, sizeof(uint32_t)*numL1Lcu);
        qpmap->size = cfg->qpmap_size;
        tp_qpmap->inUse = 0;
        tp_qpmap->frame_num = 0;
    }
    xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS,
               "%s width=%u height=%u lookahead=%u", __FUNCTION__, cfg->outWidth,
               cfg->outHeight, cfg->la_depth);
    store->maps = maps;
    return (xlnx_qpmap_store_t)store;
}

static xlnx_tp_qpmap_t *get_qp_map_at(xlnx_qpmap_store_t handle, uint32_t idx)
{
    xlnx_qpmap_store_ctx_t *store = (xlnx_qpmap_store_ctx_t *)handle;
    if (idx >= store->numQPMaps) {
        return NULL;
    }
    return &store->maps[idx];
}

static void destroy_qp_map_store(xlnx_qpmap_store_t handle)
{
    xlnx_tp_qpmap_t *xlnx_tp_qpmap_t;
    xlnx_qpmap_store_ctx_t *store = (xlnx_qpmap_store_ctx_t *)handle;
    for (uint32_t i = 0; i < store->numQPMaps; i++) {
        xlnx_tp_qpmap_t = &store->maps[i];
        free(xlnx_tp_qpmap_t->qpmap.ptr);
    }
    free(store->maps);
    store->maps = NULL;
    free(store);
}

static xlnx_aq_dump_t create_aq_dump_handle(xlnx_aq_dump_cfg *dumpCfg,
        aq_config_t *cfg)
{
    xlnx_ap_dump_ctx_t *ctx = calloc(1, sizeof(xlnx_ap_dump_ctx_t));
    if (!ctx) {
        return NULL;
    }
    ctx->cfg = *cfg;
    ctx->dumpCfg = *dumpCfg;
    if (dumpCfg->outPath && dumpCfg->dumpDeltaQpMapHex) {
        if (system("mkdir output")) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS,
                       "%s Info : Failed to create output dir", __FUNCTION__);
        }
        char strbuf[512];
#if MULTI_CHANNEL_DUMP
        sprintf(strbuf, "mkdir -p output/%u_%u_%p/", cfg->outWidth * cfg->blockWidth,
                cfg->outHeight * cfg->blockHeight, ctx);
#else
        sprintf(strbuf, "mkdir -p output/%u_%u/", cfg->outWidth * cfg->blockWidth,
                cfg->outHeight * cfg->blockHeight);
#endif
        if (system(strbuf)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s Info : Failed to execute %s",
                       __FUNCTION__, strbuf);
        }
    }
    return (xlnx_aq_dump_t)ctx;
}

static int32_t destroy_aq_dump_handle(xlnx_aq_dump_t handle)
{
    xlnx_ap_dump_ctx_t *ctx = (xlnx_ap_dump_ctx_t *)handle;
    if (ctx) {
        free(ctx);
    }
    return 0;
}

#if DUMP_FRAME_BLOCK_SAD
static int32_t dump_frame_block_sad(xlnx_aq_dump_t handle,
                                    uint64_t frame_num,
                                    const uint16_t *frameSAD,
                                    size_t size)
{
    xlnx_ap_dump_ctx_t *ctx = (xlnx_ap_dump_ctx_t *)handle;
    xlnx_aq_dump_cfg *dumpCfg = &ctx->dumpCfg;
    if (dumpCfg->dumpBlockSAD) {
        char strbuf[512];
        sprintf(strbuf, "output/BlockSAD_%04ld.bin", frame_num);
        const char *fileName = strbuf;
        FILE *frameSAD_f = fopen(fileName, "wb");
        if (NULL == frameSAD_f) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s %d Failed to open file %s",
                       __FUNCTION__, __LINE__, fileName);
            return(-1);
        }
        fwrite(frameSAD, sizeof(uint16_t), size, frameSAD_f);
        fclose(frameSAD_f);
    }
    return 0;
}
#endif //DUMP_FRAME_BLOCK_SAD

static int32_t dump_frame_delta_qp_map(xlnx_aq_dump_t handle,
                                       uint8_t *deltaQpMap, uint32_t dump_length, uint64_t frame_num, uint8_t isLA)
{
    //printf("dump_frame_delta_qp_map frame_num=%lu isLA=%d\n", frame_num, isLA);
    FILE *f_DeltaQpMap = NULL;
    FILE *f_DeltaQpMapHex = NULL;
    xlnx_ap_dump_ctx_t *ctx = (xlnx_ap_dump_ctx_t *)handle;
    xlnx_aq_dump_cfg *dumpCfg = &ctx->dumpCfg;
    aq_config_t *cfg = &ctx->cfg;
    uint32_t idx;
    char strbuf[512];
    const char *fileName;

    /*printf("dump_frame_delta_qp_map frame_num=%lu isLA=%d dump_length=%u\n",
           frame_num, isLA, dump_length);*/
    if (dumpCfg->dumpDeltaQpMap) {
        if (isLA) {
            sprintf(strbuf, "output/%s_LA-delta_QP_map_frame%ld.csv", dumpCfg->outPath,
                    frame_num);
        } else {
            sprintf(strbuf, "output/%s_deltaQp_map_frame%ld.csv", dumpCfg->outPath,
                    frame_num);
        }
        fileName = strbuf;
        f_DeltaQpMap = fopen(fileName, "wb");
        if (NULL == f_DeltaQpMap) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s Failed to open file %s",
                       __FUNCTION__, fileName);
            return(-1);
        }
    }
    if (dumpCfg->dumpDeltaQpMapHex) {
#if MULTI_CHANNEL_DUMP
        sprintf(strbuf, "output/%u_%u_%p/QP_%ld.hex", cfg->outWidth * cfg->blockWidth,
                cfg->outHeight * cfg->blockHeight, ctx, frame_num);
#else
        sprintf(strbuf, "output/%u_%u/QP_%ld.hex", cfg->outWidth * cfg->blockWidth,
                cfg->outHeight * cfg->blockHeight, frame_num);
#endif
        fileName = strbuf;
        f_DeltaQpMapHex = fopen(fileName, "wb");
        if (NULL == f_DeltaQpMapHex) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s Failed to open file %s",
                       __FUNCTION__, fileName);
            if (f_DeltaQpMap) {
                fclose(f_DeltaQpMap);
            }
            return(-1);
        }
    }
    for (idx = 0; idx < dump_length; idx++) {
        if (dumpCfg->dumpDeltaQpMap) {
            fprintf(f_DeltaQpMap, ",%d", deltaQpMap[idx]);
        }
        if (dumpCfg->dumpDeltaQpMapHex) {
            fprintf(f_DeltaQpMapHex, "%02X\n", deltaQpMap[idx]);
        }
        if (dumpCfg->dumpDeltaQpMap) {
            fprintf(f_DeltaQpMap, "\n");
        }
    }
    if (f_DeltaQpMap) {
        fclose(f_DeltaQpMap);
    }
    if (f_DeltaQpMapHex) {
        fclose(f_DeltaQpMapHex);
    }
    return 0;
}

xlnx_aq_core_t create_aq_core(aq_config_t *cfg, xlnx_aq_dump_cfg *dumpCfg)
{
    uint32_t numL1Lcu;
    xlnx_aq_core_ctx_t *ctx = calloc(1, sizeof(xlnx_aq_core_ctx_t));
    if (!ctx) {
        return NULL;
    }
    ctx->cfg = *cfg;
    ctx->num_mb = cfg->num_mb;
    numL1Lcu = ctx->num_mb + 1;
    ctx->isDeltaQpMapLAPending = 1;
    ctx->spatial_aq_mode = cfg->spatial_aq_mode;
    ctx->temporal_aq_mode = cfg->temporal_aq_mode;
    ctx->rate_control_mode = cfg->rate_control_mode;
    ctx->codec_type = cfg->codec_type;
    if (ctx->spatial_aq_mode || ctx->temporal_aq_mode) {
        ctx->qpmaps_enabled = 1;
    } else {
        ctx->qpmaps_enabled = 0;
    }
    ctx->rc_h = NULL;
    ctx->sp_h = NULL;
    ctx->qpStore = NULL;
    ctx->tmp_hevc_map = NULL;
    ctx->collocatedSadLA = NULL;
    if (ctx->rate_control_mode > 0) {
        ctx->rc_h = xlnx_algo_rc_create(cfg->la_depth);
        if (ctx->rc_h == NULL) {
            destroy_aq_core(ctx);
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s xlnx_algo_rc_create Failed",
                       __FUNCTION__);
            return NULL;
        }
    }
    if (ctx->temporal_aq_mode) {
        ctx->collocatedSadLA = malloc(sizeof(uint32_t)*numL1Lcu);
        if (!ctx->collocatedSadLA) {
            destroy_aq_core(ctx);
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s OOM", __FUNCTION__);
            return NULL;
        }
        memset(ctx->collocatedSadLA, 0, sizeof(uint32_t)*numL1Lcu);
        ctx->qpStore = create_qp_map_store(cfg);
        if (!ctx->qpStore) {
            destroy_aq_core(ctx);
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s OOM", __FUNCTION__);
            return NULL;
        }
        if ((ctx->codec_type == EXlnxHevc) && (ctx->tmp_hevc_map == NULL)) {
            ctx->tmp_hevc_map = calloc(1, sizeof(int32_t) * cfg->qpmap_size);
            if (ctx->tmp_hevc_map == NULL) {
                destroy_aq_core(ctx);
                xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s OOM", __FUNCTION__);
                return NULL;
            }
        }
        ctx->read_idx = 1;
        ctx->write_idx = 1;
        ctx->laMapCtx = get_qp_map_at(ctx->qpStore, 0);
    } else {
        ctx->read_idx = 0;
        ctx->write_idx = 0;
        ctx->laMapCtx = NULL;
    }

    if (dumpCfg) {
        ctx->dump_handle = create_aq_dump_handle(dumpCfg, cfg);
    } else {
        ctx->dump_handle = NULL;
    }
    if (ctx->spatial_aq_mode != 0) {
        ctx->sp_h = xlnx_spatial_create(cfg);
        if (ctx->sp_h == NULL) {
            destroy_aq_core(ctx);
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s xlnx_spatial_create Failed",
                       __FUNCTION__);
            return NULL;
        }
        if ((ctx->codec_type == EXlnxHevc) && (ctx->tmp_hevc_map == NULL)) {
            ctx->tmp_hevc_map = calloc(1, sizeof(int32_t) * cfg->qpmap_size);
            if (ctx->tmp_hevc_map == NULL) {
                destroy_aq_core(ctx);
                xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s OOM", __FUNCTION__);
                return NULL;
            }
        }
    }

    return (xlnx_aq_core_t)ctx;
}

void destroy_aq_core(xlnx_aq_core_t handle)
{
    xlnx_aq_core_ctx_t *ctx = (xlnx_aq_core_ctx_t *)handle;
    if (ctx->collocatedSadLA) {
        free(ctx->collocatedSadLA);
        ctx->collocatedSadLA = NULL;
    }
    if (ctx->dump_handle) {
        destroy_aq_dump_handle(ctx->dump_handle);
        ctx->dump_handle = NULL;
    }
    if (ctx->qpStore) {
        destroy_qp_map_store(ctx->qpStore);
        ctx->qpStore = NULL;
    }
    if (ctx->rc_h) {
        xlnx_algo_rc_destroy(ctx->rc_h);
        ctx->rc_h = NULL;
    }
    if (ctx->sp_h) {
        xlnx_spatial_destroy(ctx->sp_h);
        ctx->sp_h = NULL;
    }
    if (ctx->tmp_hevc_map) {
        free(ctx->tmp_hevc_map);
        ctx->tmp_hevc_map = NULL;
    }
    free(ctx);
}

static inline uint8_t getQpHexByte(int32_t qp_value_32)
{
    uint8_t qp_value_8;
    if (qp_value_32 < 0) {
        qp_value_8 =  (uint8_t)(64+qp_value_32);
    } else {
        qp_value_8 = (uint8_t) qp_value_32;
    }
    return qp_value_8;
}

static inline int getFrameSad(xlnx_aq_core_ctx_t *ctx,  const uint16_t *sadIn,
                              uint32_t *frameSAD)
{
    *frameSAD = 0;
    const uint16_t *sad = sadIn;
    if (!sad) {
        return -1;
    }
    uint32_t frame_sad = 0;
    aq_config_t *cfg = &ctx->cfg;
    uint32_t blockWidth = cfg->blockWidth;
    uint32_t blockHeight = cfg->blockHeight;
    int32_t outWidth = cfg->outWidth;
    int32_t outHeight = cfg->outHeight;
    for (int y=0; y<outHeight; y+=blockHeight) {
        for (int x=0; x<outWidth; x+=blockWidth) {
            frame_sad += *sad;
            sad++;
        }
    }
    //printf("calculated framesad=%lu\n", frame_sad);
    *frameSAD = frame_sad;
    return 0;
}

static int32_t xlnx_temporal_gen_qpmap(xlnx_aq_core_ctx_t *ctx,
                                       const uint16_t *sadIn,
                                       uint64_t frame_num, uint32_t *frameSAD, xlnx_tp_qpmap_t *outMapCtx)
{
    if (frame_num == 0) {
        *frameSAD = 0;
        return 0;
    }
    int32_t avgBlockSad;
    int32_t minBlockSad, maxBlockSad, maxBlockDistance, absMinBlockDistance;
    int32_t minBlockDistance;

    int32_t x, y = 0;
    int32_t colIn = 0;
    minBlockSad = 0xFFFF;
    maxBlockSad = 0;
    int32_t tmp_qp = 0;
    int32_t *deltaQpMap = NULL;


    aq_config_t *cfg = &ctx->cfg;
    uint32_t blockWidth = cfg->blockWidth;
    uint32_t blockHeight = cfg->blockHeight;
    int32_t outWidth = cfg->outWidth;
    int32_t outHeight = cfg->outHeight;
    uint32_t intraPeriod = cfg->intraPeriod;
    xlnx_tp_qpmap_t *xlnx_tp_qpmap_t = outMapCtx;

    uint32_t numL1Lcu = ctx->num_mb+1;
    uint32_t lastIntra = (frame_num/intraPeriod)*intraPeriod;
    const uint16_t *sad = sadIn;
    *frameSAD = 0;

    xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS,
               "%s frame_num=%lu ctx->isDeltaQpMapLAPending=%u", __FUNCTION__,
               frame_num, ctx->isDeltaQpMapLAPending);

    for (y=0; y<outHeight; y+=blockHeight) {
        for (x=0; x<outWidth; x+=blockWidth) {
            ctx->collocatedSadLA[colIn++] += *sad;
            *frameSAD += *sad;
            minBlockSad = (minBlockSad < *sad)? minBlockSad : *sad;
            maxBlockSad = (maxBlockSad > *sad)? maxBlockSad : *sad;
            sad++;
        }
    }

    avgBlockSad = *frameSAD/numL1Lcu;
    /*printf("frameSad[%lu]= %lu; minBlockSad=%d maxBlockSad=%d assumed blocks=%u actual blocks=%u\n",
           frame_num,
           *frameSAD, minBlockSad, maxBlockSad, numL1Lcu, colIn);*/
    minBlockDistance = abs(minBlockSad - avgBlockSad);
    absMinBlockDistance = minBlockDistance;
    maxBlockDistance = maxBlockSad - avgBlockSad;

    if(minBlockDistance < maxBlockDistance) {
        maxBlockDistance = minBlockDistance;
        minBlockDistance = (int32_t)(0 - minBlockDistance);
    } else {
        minBlockDistance = (int32_t)(0 - maxBlockDistance);
    }

    absMinBlockDistance = (absMinBlockDistance == 0)? 1: absMinBlockDistance;
    maxBlockDistance = (maxBlockDistance == 0)? 1: maxBlockDistance;

    uint32_t minQp, maxQp;
    uint32_t pFrameFreq = cfg->num_b_frames + 1;
    // GOP based AQ weights here
    if((frame_num-lastIntra)%pFrameFreq ==0) {
        minQp = 6;
        maxQp = 3;
    } else {
        minQp = 2;
        maxQp = 2;
    }
    uint32_t dndx =0;
    int32_t diffSad;
    deltaQpMap = (int32_t *)xlnx_tp_qpmap_t->qpmap.ptr;
    sad = sadIn;
    for (int32_t hgt=0; hgt<outHeight; hgt+=blockHeight) {
        for (int32_t wth=0; wth<outWidth; wth+=blockWidth) {
            diffSad = (int32_t)(*sad - avgBlockSad);

            if((int32_t)diffSad <=0) {
                tmp_qp = 0 - (int32_t)(minQp* XLNX_MIN(avgBlockSad-*sad,
                                                       absMinBlockDistance)/absMinBlockDistance);
            } else {
                tmp_qp = (int32_t)(maxQp* XLNX_MIN(diffSad,
                                                   maxBlockDistance)/maxBlockDistance);
            }
            deltaQpMap[dndx++] = tmp_qp;
            sad++;
        }
    }

    if (((frame_num%intraPeriod) != 0)) {
        xlnx_tp_qpmap_t->inUse = 1;
        xlnx_tp_qpmap_t->frame_num = frame_num;
    }

#if DUMP_FRAME_BLOCK_SAD
    if (ctx->dump_handle && sadIn) {
        dump_frame_block_sad(ctx->dump_handle, frame_num, sadIn, numL1Lcu-1);
    }
#endif //DUMP_FRAME_BLOCK_SAD
    return 0;
}

static int32_t xlnx_temporal_gen_la_qpmap(xlnx_aq_core_ctx_t *ctx,
        xlnx_tp_qpmap_t *outMapCtx)
{
    uint32_t minQp, maxQp;
    int32_t colIn = 0;
    uint64_t accLaSad = 0;
    int32_t avgLaSad = 0;
    int32_t tmp_qp = 0;
    uint32_t minLaBlockSad, maxLaBlockSad;
    int32_t minLaDistance, maxLaDistance;
    aq_config_t *cfg = &ctx->cfg;
    uint32_t blockWidth = cfg->blockWidth;
    uint32_t blockHeight = cfg->blockHeight;
    int32_t outWidth = cfg->outWidth;
    int32_t outHeight = cfg->outHeight;
    int32_t *deltaQpMapLA = NULL;
    xlnx_tp_qpmap_t *laMapCtx = outMapCtx;
    uint32_t numL1Lcu = ctx->num_mb+1;

    accLaSad = 0;
    minLaBlockSad = 0xFFFF;
    maxLaBlockSad = 0;

    for (int32_t hgt=0; hgt<outHeight; hgt+=blockHeight) {
        for (int32_t wth=0; wth<outWidth; wth+=blockWidth) {
            accLaSad += ctx->collocatedSadLA[colIn];
            minLaBlockSad = (minLaBlockSad < ctx->collocatedSadLA[colIn])? minLaBlockSad :
                            ctx->collocatedSadLA[colIn];
            maxLaBlockSad = (maxLaBlockSad > ctx->collocatedSadLA[colIn])? maxLaBlockSad :
                            ctx->collocatedSadLA[colIn];
            colIn++;
        }
    }
    avgLaSad = accLaSad/numL1Lcu;
    uint32_t absMinLaDistance;
    //printf("avgLaSad %d\t minLaBlockSad %d\t maxLaBlockSad %d\n", avgLaSad, minLaBlockSad, maxLaBlockSad);

    minLaDistance = abs(minLaBlockSad - avgLaSad);
    maxLaDistance = maxLaBlockSad - avgLaSad;

    //printf("minLaDistance %d\t maxLaDistance %d\n", minLaDistance, maxLaDistance);

    if(minLaDistance < maxLaDistance) {
        maxLaDistance = minLaDistance;
        absMinLaDistance = minLaDistance;
        minLaDistance = (int32_t)(0 - minLaDistance);
    } else {
        absMinLaDistance = maxLaDistance;
        minLaDistance = (int32_t)(0 - maxLaDistance);
    }

    absMinLaDistance = (absMinLaDistance == 0)? 1: absMinLaDistance;
    maxLaDistance = (maxLaDistance == 0)? 1: maxLaDistance;

    // Adjust AQ weights here
    minQp = XLNX_MIN_QP;
    maxQp = XLNX_MAX_QP; // For intra frames do not increase the QP

    colIn = 0;
    uint32_t dnx =0;
    int32_t diffSadLa;
    if (laMapCtx->inUse != 0) {
        xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS,
                   "%s Intra qpmap buf(frame_num=%d) already occupied", __FUNCTION__,
                   laMapCtx->frame_num);
        return -1;
    }
    deltaQpMapLA = (int32_t *)laMapCtx->qpmap.ptr;
    for (int32_t hgt=0; hgt<outHeight; hgt+=blockHeight) {
        for (int32_t wth=0; wth<outWidth; wth+=blockWidth) {
            diffSadLa = (int32_t)(ctx->collocatedSadLA[colIn] - avgLaSad);

            if((int32_t)diffSadLa < 0) {
                tmp_qp = 0 - (int32_t)(minQp* XLNX_MIN(avgLaSad-
                                                       ctx->collocatedSadLA[colIn], absMinLaDistance)/absMinLaDistance);
            } else {
                tmp_qp = (int32_t)(maxQp* XLNX_MIN(diffSadLa,
                                                   maxLaDistance)/maxLaDistance);
            }
            deltaQpMapLA[dnx++] = tmp_qp;
            colIn++;
        }
    }
    ctx->accumulatedSadFrames = 0;
    memset(ctx->collocatedSadLA, 0, sizeof(uint32_t)*numL1Lcu);
    return 0;
}

void merge_qp_maps(xlnx_aq_core_ctx_t *ctx, int32_t *temporal_qpmap,
                   float *spatial_qpmap,
                   uint32_t num_mb,
                   uint8_t *out_map)
{
    aq_config_t *cfg = &ctx->cfg;
    uint32_t padded_w = cfg->padded_mb_w;
    uint32_t actual_w = cfg->actual_mb_w;
    int32_t temporal = 0;
    float spatial = 0;
    int32_t last_deltaQp = 0;
    uint8_t out_byte = 0;
    uint8_t remove_padding = 0;
    uint32_t w_size = 0;
    if (padded_w != actual_w) {
        remove_padding = 1;
        //printf("padded_w = %u actual_w=%u\n", padded_w, actual_w);
    }
    for (uint32_t i=0; i<num_mb; i++) {
        if (temporal_qpmap) {
            temporal = temporal_qpmap[i];
        }
        if (spatial_qpmap) {
            spatial = spatial_qpmap[i];
            int32_t finaldeltaQP;
            finaldeltaQP = temporal + (spatial + 0.5);
            if(i != 0) {
                finaldeltaQP = abs(finaldeltaQP - last_deltaQp) == 1 ? last_deltaQp :
                               finaldeltaQP;
            }

            last_deltaQp = finaldeltaQP;
            if (remove_padding) {
                if ((i % padded_w) >= actual_w) {
                    continue;
                }
            }
            out_byte = getQpHexByte(finaldeltaQP);
        } else {
            out_byte = getQpHexByte(temporal);
            if (remove_padding) {
                if (((i+1) % padded_w) == actual_w) {
                    //printf("skip @ i=%u by %u \n", i, padded_w - actual_w);
                    i = i + padded_w - actual_w;

                }
            }
        }
        out_map[w_size] = out_byte;
        w_size++;
        if (w_size == cfg->qpmap_size) {
            //printf("break at i=%u num_mb = %u map_size =%u %u \n",i, num_mb, w_size, cfg->qpmap_size);
            break;
        }
    }
}

void merge_qp_maps_hevc(xlnx_aq_core_ctx_t *ctx, int32_t *temporal_qpmap,
                        float *spatial_qpmap,
                        uint32_t num_mb,
                        uint8_t *out_map)
{
    aq_config_t *cfg = &ctx->cfg;
    uint32_t padded_w = cfg->padded_mb_w;
    uint32_t actual_w = cfg->actual_mb_w;
    uint32_t actual_h = cfg->actual_mb_h;
    int32_t temporal = 0;
    float spatial = 0;
    int32_t last_deltaQp = 0;
    uint8_t remove_padding = 0;
    uint32_t w_size = 0;
    int32_t *hevc_map = ctx->tmp_hevc_map;
    int32_t out_qp = 0;
    int32_t out_idx = 0;

    if (padded_w != actual_w) {
        remove_padding = 1;
        //printf("padded_w = %u actual_w=%u\n", padded_w, actual_w);
    }
    for (uint32_t i=0; i<num_mb; i++) {
        if (temporal_qpmap) {
            temporal = temporal_qpmap[i];
        }
        if (spatial_qpmap) {
            spatial = spatial_qpmap[i];
            int32_t finaldeltaQP;
            finaldeltaQP = temporal + (spatial + 0.5);
            if(i != 0) {
                finaldeltaQP = abs(finaldeltaQP - last_deltaQp) == 1 ? last_deltaQp :
                               finaldeltaQP;
            }

            last_deltaQp = finaldeltaQP;
            if (remove_padding) {
                if ((i % padded_w) >= actual_w) {
                    continue;
                }
            }
            out_qp = finaldeltaQP;
        } else {
            out_qp = temporal;
            if (remove_padding) {
                if (((i+1) % padded_w) == actual_w) {
                    //printf("skip @ i=%u by %u \n", i, padded_w - actual_w);
                    i = i + padded_w - actual_w;

                }
            }
        }
        hevc_map[w_size] = out_qp;
        w_size++;
        if (w_size == cfg->qpmap_size) {
            //printf("break at i=%u num_mb = %u map_size =%u %u \n",i, num_mb, w_size, cfg->qpmap_size);
            break;
        }
    }

    // average values to derive final values
    for (uint32_t h=0; h < actual_h; h += 2) {
        for (uint32_t w=0; w < actual_w; w += 2) {
            int avgdeltaQP = hevc_map[(h * actual_w) + w];
            int countMbs = 1;

            if ((w + 1) < actual_w) {
                avgdeltaQP += hevc_map[(h * actual_w) + w + 1];
                countMbs++;
            }
            if ((h + 1) < actual_h) {
                avgdeltaQP += hevc_map[((h + 1) * actual_w) + w];
                countMbs++;
            }

            if (((w + 1) < actual_w) && ((h + 1) < actual_h)) {
                avgdeltaQP += hevc_map[((h + 1) * actual_w) + w + 1];
                countMbs++;
            }

            avgdeltaQP = avgdeltaQP / countMbs;
            out_map[out_idx++] = getQpHexByte(avgdeltaQP);
        }
    }
}
static xlnx_status generateQPMap(xlnx_aq_core_t handle, uint64_t frame_num,
                                 const uint16_t *sadIn,
                                 const uint32_t *var_energy_map, const uint16_t *act_energy_map,
                                 uint32_t isLastFrame,
                                 uint32_t *frame_activity,
                                 uint32_t *frame_sad)
{
    xlnx_status ret_status = EXlnxSuccess;

    xlnx_aq_core_ctx_t *ctx = (xlnx_aq_core_ctx_t *)handle;
    aq_config_t *cfg = &ctx->cfg;
    uint32_t intraPeriod = cfg->intraPeriod;
    xlnx_tp_qpmap_t *laMapCtx = ctx->laMapCtx;
    xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS,
               "%s IN frame_num=%lu sadIn=%p var_energy_map=%p act_energy_map=%p isLastFrame=%u",
               __FUNCTION__, frame_num, sadIn,
               var_energy_map, act_energy_map,
               isLastFrame);

    uint32_t numL1Lcu = ctx->num_mb+1;
    xlnx_tp_qpmap_t *xlnx_tp_qpmap_t = NULL;
    //float *spatial_map = NULL;
    uint8_t isIntraFrame = 0;
    uint32_t isTemporalEnabled = (ctx->temporal_aq_mode == XLNX_AQ_TEMPORAL_LINEAR);
    if (isTemporalEnabled) {
        if((frame_num % intraPeriod) == 0) {
            isIntraFrame = 1;
        }
    }

    if (ctx->sp_h) {
        ret_status = xlnx_spatial_gen_qpmap(ctx->sp_h, var_energy_map, act_energy_map,
                                            frame_num, frame_activity);
        if (ret_status != EXlnxSuccess) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s Spatial AQ failed",
                       __FUNCTION__);
            return ret_status;
        }
    }
    if (isTemporalEnabled) {
        if (sadIn) {
            xlnx_tp_qpmap_t = get_qp_map_at(ctx->qpStore, ctx->write_idx);
            if (xlnx_tp_qpmap_t->inUse == 1) {
                xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS, "%s Input SAD Q is full",
                           __FUNCTION__);
                return EXlnxTryAgain;
            }

            if ((frame_num % intraPeriod) == 0) {
                ctx->isDeltaQpMapLAPending = 1;
                assert(laMapCtx->inUse == 0);
                laMapCtx->frame_num = (frame_num/intraPeriod)*intraPeriod;
                memset(ctx->collocatedSadLA, 0, sizeof(uint32_t)*numL1Lcu);
            }
            xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS,
                       "%s frame_num=%lu ctx->isDeltaQpMapLAPending=%u", __FUNCTION__,
                       frame_num, ctx->isDeltaQpMapLAPending);

            if (xlnx_temporal_gen_qpmap(ctx, sadIn, frame_num, frame_sad,
                                        xlnx_tp_qpmap_t)) {
                return EXlnxTryAgain;
            }
            if(isIntraFrame == 0) {
                ctx->write_idx++;
                if (ctx->write_idx >= (cfg->la_depth+1)) {
                    ctx->write_idx = 1;
                }
            }
            ctx->accumulatedSadFrames += *frame_sad;
        }
        xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS,
                   "%s frame_num=%lu isDeltaQpMapLAPending=%u distance=%lu isLastFrame=%u",
                   __FUNCTION__, frame_num, ctx->isDeltaQpMapLAPending,
                   (frame_num % intraPeriod), isLastFrame);

        if((frame_num && (((frame_num % intraPeriod) + 1) == cfg->la_depth)) ||
                ((cfg->la_depth == 1) && (frame_num == 1))
                || isLastFrame ||
                (sadIn == NULL)) {
            if(ctx->isDeltaQpMapLAPending) {
                if (laMapCtx->frame_num != (frame_num/intraPeriod)*intraPeriod) {
                    xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS,
                               "%s Expected Intra map = %lu does not match =%lu", __FUNCTION__,
                               laMapCtx->frame_num, (frame_num/intraPeriod)*intraPeriod);
                    return EXlnxError;
                }
                xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS, "%s Dump I %lu", __FUNCTION__,
                           laMapCtx->frame_num);
                xlnx_temporal_gen_la_qpmap(ctx, laMapCtx);
                laMapCtx->inUse = 1;
                ctx->isDeltaQpMapLAPending = 0;
            }
        }
    }
    return EXlnxSuccess;
}

xlnx_status send_frame_stats(xlnx_aq_core_t handle, uint64_t frame_num,
                             xlnx_frame_stats *stats,
                             uint32_t isLastFrame)
{
    xlnx_aq_core_ctx_t *ctx = (xlnx_aq_core_ctx_t *)handle;
    const uint16_t *sadIn = NULL;
    const uint32_t *varIn = NULL;
    const uint16_t *actIn = NULL;
    uint32_t frame_activity = 0;
    uint32_t frame_sad = 0;

    if (stats != NULL) {
        sadIn = stats->sad;
        varIn = stats->var;
        actIn = stats->act;
    }
    xlnx_status ret = EXlnxSuccess;
    if (ctx->qpmaps_enabled) {
        ret = generateQPMap(handle, frame_num, sadIn, varIn, actIn, isLastFrame,
                            &frame_activity, &frame_sad);
        if (ret != EXlnxSuccess && stats && !isLastFrame) {
            return ret;
        }
    }

    if (ctx->rc_h) {
        if (sadIn && actIn) {
            xlnx_rc_fsfa_t fsfa;
            if (ctx->temporal_aq_mode == XLNX_AQ_TEMPORAL_LINEAR) {
                fsfa.fs = frame_sad;
            } else {
                if (getFrameSad(ctx, sadIn, &fsfa.fs)) {
                    return ret;
                }
            }
            if (ctx->spatial_aq_mode == XLNX_AQ_SPATIAL_ACTIVITY) {
                fsfa.fa = frame_activity;
            } else {
                if (xlnx_spatial_frame_activity(&ctx->cfg, actIn, &fsfa.fa)) {
                    return ret;
                }
            }
            ret = xlnx_algo_rc_write_fsfa(ctx->rc_h, &fsfa);
            if (isLastFrame) {
                //printf("EOS sent from xlnx algos\n");
                xlnx_algo_rc_write_fsfa(ctx->rc_h, NULL);
            }
        } else {
            //printf("EOS sent from xlnx algos\n");
            ret = xlnx_algo_rc_write_fsfa(ctx->rc_h, NULL);
        }
    }
    return ret;
}

static int32_t is_qp_map_pending(xlnx_aq_core_ctx_t *ctx, QpMapType type,
                                 uint64_t *frame_num, uint32_t *is_available)
{
    xlnx_tp_qpmap_t *xlnx_tp_qpmap_t = NULL;

    *frame_num = 0;
    *is_available = 0;
    if (type == EIType) {
        xlnx_tp_qpmap_t = ctx->laMapCtx;
        if (ctx->isDeltaQpMapLAPending || xlnx_tp_qpmap_t->inUse) {
            if (xlnx_tp_qpmap_t->inUse) {
                *is_available = 1;
            }
            *frame_num = xlnx_tp_qpmap_t->frame_num;
            return 1;
        }
    } else if (type == EPType) {
        xlnx_tp_qpmap_t = get_qp_map_at(ctx->qpStore, ctx->read_idx);
        if (xlnx_tp_qpmap_t->inUse) {
            *is_available = 1;
            *frame_num = xlnx_tp_qpmap_t->frame_num;
            return 1;
        }
    }
    return 0;
}

static xlnx_status copy_qpmaps(xlnx_aq_core_ctx_t *ctx,
                               xlnx_aq_info_t *dstVQInfo,
                               xlnx_tp_qpmap_t *t_qpmap, spatial_qpmap_t *s_qpmap, uint32_t num_mb)
{
    if (t_qpmap && !dstVQInfo) {
        xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s VQ out buffer invalid!!",
                   __FUNCTION__);
        return EXlnxError;
    }
    if (t_qpmap && t_qpmap->qpmap.ptr && s_qpmap && s_qpmap->fPtr &&
            (t_qpmap->frame_num != s_qpmap->frame_num)) {
        xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS,
                   "Warning : Temporal frame number(%lu) != Spatial qpmap number(%lu)",
                   t_qpmap->frame_num, s_qpmap->frame_num);
    }
    int32_t *temporal_qpmap = NULL;
    float *spatial_qpmap = NULL;
    xlnx_aq_buf_t *dst_qpmap = &dstVQInfo->qpmap;
    if (dst_qpmap->ptr == NULL) {
        xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s VQ out buffer invalid!!",
                   __FUNCTION__);
        return EXlnxError;
    }
    uint64_t frame_num = 0;
    if (t_qpmap && t_qpmap->qpmap.ptr) {
        temporal_qpmap = (int32_t *)t_qpmap->qpmap.ptr;
        frame_num = t_qpmap->frame_num;
    }
    if (s_qpmap && s_qpmap->fPtr) {
        spatial_qpmap = s_qpmap->fPtr;
        frame_num = s_qpmap->frame_num;
    }
    if (ctx->tmp_hevc_map) {
        merge_qp_maps_hevc(ctx, temporal_qpmap, spatial_qpmap, num_mb,
                           dst_qpmap->ptr);
    } else {
        merge_qp_maps(ctx, temporal_qpmap, spatial_qpmap, num_mb,
                      dst_qpmap->ptr);
    }
    dstVQInfo->frame_num = frame_num;
    return EXlnxSuccess;
}

static xlnx_status copy_fsfa(xlnx_rc_aq_t rc,
                             xlnx_aq_info_t *dstVQInfo)
{
    if (rc && dstVQInfo) {
        xlnx_aq_buf_t *dst_fsfa = &dstVQInfo->fsfa;
        if (!dst_fsfa->ptr) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s VQ out buffer invalid!!",
                       __FUNCTION__);
            return EXlnxError;
        }
        uint64_t rc_frame_num = 0;
        if (EXlnxSuccess != xlnx_algo_rc_read_fsfa(rc, dst_fsfa, &rc_frame_num)) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s RC algo failed",  __FUNCTION__);
            return EXlnxError;
        }
        if (dstVQInfo->qpmap.ptr) {
            if (dstVQInfo->frame_num != rc_frame_num) {
                xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS,
                           "Warning : RC frame number(%lu) is not same as qpmap number(%lu)",
                           rc_frame_num, dstVQInfo->frame_num);
            }
        } else {
            dstVQInfo->frame_num = rc_frame_num;
        }
    }
    return EXlnxSuccess;
}

static int xlnx_temporal_is_ready(xlnx_aq_core_ctx_t *ctx)
{
    uint64_t frameNumI, frameNumP;
    uint32_t is_available;
    int32_t iPending, pPending;
    int ret_available = 0;
    iPending = is_qp_map_pending(ctx, EIType, &frameNumI, &is_available);
    if (iPending && is_available) {
        ret_available = 1;
    } else {
        pPending = is_qp_map_pending(ctx, EPType, &frameNumP, &is_available);
        if (pPending && is_available) {
            if ((frameNumP < frameNumI) || !iPending) {
                ret_available = 1;
            }
        }
    }
    return ret_available;
}

static int all_qpmaps_available(xlnx_aq_core_ctx_t *ctx)
{
    int ret = 1;
    int sp_ready = 1;
    int tp_ready = 1;

    if (ctx->sp_h) {
        sp_ready = xlnx_spatial_is_ready(ctx->sp_h);
    }
    uint32_t isTemporalEnabled = ctx->temporal_aq_mode == XLNX_AQ_TEMPORAL_LINEAR;
    if (isTemporalEnabled) {
        tp_ready = xlnx_temporal_is_ready(ctx);
    }
    if (!sp_ready || !tp_ready) {
        ret = 0;
    }
    return ret;
}

xlnx_status recv_frame_aq_info(xlnx_aq_core_t handle, xlnx_aq_info_t *vqInfo)
{
    xlnx_aq_core_ctx_t *ctx = (xlnx_aq_core_ctx_t *)handle;
    aq_config_t *cfg = &ctx->cfg;
    uint64_t frameNumI, frameNumP;
    uint32_t is_available;
    int32_t iPending;
    int32_t pPending;

    if (ctx->rc_h) {
        if (xlnx_algo_rc_fsfa_available(ctx->rc_h) == 0) {
            return EXlnxTryAgain;
        }
    }

    if (ctx->qpmaps_enabled) {
        if (all_qpmaps_available(ctx) == 0) {
            return EXlnxTryAgain;
        }
        xlnx_status qp_status = EXlnxSuccess;
        spatial_qpmap_t s_qpmap;
        s_qpmap.fPtr = NULL;
        if (ctx->sp_h) {
            qp_status = xlnx_spatial_recv_qpmap(ctx->sp_h, &s_qpmap);
            if (qp_status != EXlnxSuccess) {
                xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s Spatial qpmap not available",
                           __FUNCTION__
                          );
            }
        }
        xlnx_tp_qpmap_t *t_qpmap = NULL;
        uint32_t isTemporalEnabled = ctx->temporal_aq_mode == XLNX_AQ_TEMPORAL_LINEAR;
        if (isTemporalEnabled) {
            iPending = is_qp_map_pending(ctx, EIType, &frameNumI, &is_available);
            if (iPending && is_available) {
                t_qpmap = ctx->laMapCtx;
                pPending = is_qp_map_pending(ctx, EPType, &frameNumP, &is_available);
                if (pPending && is_available) {
                    if (frameNumP < frameNumI) {
                        t_qpmap = get_qp_map_at(ctx->qpStore, ctx->read_idx);
                        ctx->read_idx++;
                        if (ctx->read_idx >= (cfg->la_depth + 1)) {
                            ctx->read_idx = 1;
                        }
                        xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS, "%s OUT P available", __FUNCTION__
                                  );
                    }
                }
            } else {
                t_qpmap = get_qp_map_at(ctx->qpStore, ctx->read_idx);
                ctx->read_idx++;
                if (ctx->read_idx >= (cfg->la_depth + 1)) {
                    ctx->read_idx = 1;
                }
                xma_logmsg(XMA_DEBUG_LOG, XMA_XLNX_ALGOS, "%s OUT P available", __FUNCTION__
                          );
            }
        }

        qp_status = copy_qpmaps(ctx, vqInfo, t_qpmap, &s_qpmap, ctx->num_mb);
        if (t_qpmap) {
            t_qpmap->inUse = 0;
        }
        if (ctx->sp_h) {
            xlnx_spatial_release_qpmap(ctx->sp_h, &s_qpmap);
        }
        if (qp_status != EXlnxSuccess) {
            xma_logmsg(XMA_ERROR_LOG, XMA_XLNX_ALGOS, "%s qpmap generation status = %d",
                       __FUNCTION__, qp_status);
            return qp_status;
        }
        if (ctx->dump_handle) {
            dump_frame_delta_qp_map(ctx->dump_handle, vqInfo->qpmap.ptr, vqInfo->qpmap.size,
                                    vqInfo->frame_num, 0);
        }
    }
    return copy_fsfa(ctx->rc_h, vqInfo);
}
