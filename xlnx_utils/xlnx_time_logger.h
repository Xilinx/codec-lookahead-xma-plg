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
#ifndef XLNX_TIME_LOGGER_H
#define XLNX_TIME_LOGGER_H

typedef void *xlnx_time_logger_t;
#ifdef ENABLE_XLNX_TIME_LOGGER
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <assert.h>
#include "xlnx_time_logger.h"

#define USEC 1000000L
#define MSEC 1000L

typedef struct
{
    struct timeval startTime;
    long int tt;
    long int mint;
    long int maxt;
    int started;
} xlnx_time_logger;

static inline long int getUElapsedTime(struct timeval *startTime,
                                       struct timeval *endTime)
{
    long int diff = (endTime->tv_usec + USEC * endTime->tv_sec) -
                    (startTime->tv_usec + USEC * startTime->tv_sec);
    //printf("%ld.%03ld msecs\n", diff / MSEC, diff % MSEC);
    return diff;
}


static inline xlnx_time_logger_t xlnx_tl_create(void)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)calloc(1, sizeof(xlnx_time_logger));
    if (!tl) {
        return NULL;
    }
    tl->started = 0;
    tl->mint = 0;
    tl->maxt = 0;
    return (xlnx_time_logger_t) tl;
}

static inline void xlnx_tl_destroy(xlnx_time_logger_t aTl)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    if (tl) {
        free(tl);
    }
}

static inline int32_t xlnx_tl_start(xlnx_time_logger_t aTl)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    assert(tl->started != 1);
    tl->started = 1;
    gettimeofday(&tl->startTime, NULL);
    return 0;
}

static inline long int xlnx_tl_pause(xlnx_time_logger_t aTl)
{
    struct timeval endTime;
    long int diff;
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    assert(tl->started == 1);
    if (tl->started != 1) {
        return 0;
    }

    tl->started = 0;
    gettimeofday(&endTime, NULL);
    diff = getUElapsedTime(&tl->startTime, &endTime);
    tl->tt += diff;
    if (diff > tl->maxt) {
        tl->maxt = diff;
    }
    if (diff < tl->mint) {
        tl->mint = diff;
    }
    return diff;
}

static inline long int xlnx_tl_get_tt(xlnx_time_logger_t aTl)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    return tl->tt;
}

static inline int32_t xlnx_tl_get_avg_msec(xlnx_time_logger_t aTl,
        uint64_t count)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    if (count == 0) {
        return -1;
    }
    return (tl->tt * MSEC)/count;
}

static inline int32_t xlnx_tl_get_avg_fps(xlnx_time_logger_t aTl,
        uint64_t count)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    if (tl->tt == 0) {
        return -1;
    }
    return (USEC * count)/tl->tt;
}

static inline int32_t xlnx_tl_dump_results(xlnx_time_logger_t aTl,
        const char *aFileName,
        uint64_t count)
{
    xlnx_time_logger *tl = (xlnx_time_logger *)aTl;
    FILE *perfF = fopen(aFileName, "w");
    if (perfF) {
        if (tl->tt == 0) {
            fprintf(perfF, "Total time 0\n");
            fclose(perfF);
            //printf("Total time 0\n");
            return 0;
        }
        //fwrite(&inst->total_hw_cycles, sizeof(uint64_t), 1, fCycles);
        fprintf(perfF, "FPS : %lf\n", (double)(USEC * count)/tl->tt);
        fprintf(perfF, "Average Time : %lf msecs\n", (double)tl->tt/(count*MSEC));
        fprintf(perfF, "(MIN,MAX) Time : (%lf, %lf) msecs\n", (double)tl->mint/MSEC,
                (double)tl->maxt/MSEC);
        /*printf("%s Count=%lu FPS : %lf\n", aFileName, count,
               (double)(USEC * count)/tl->tt);
        printf("%s Count=%lu Average Time : %lf msecs\n", aFileName, count,
               (double)tl->tt/(count* MSEC));
        printf("(MIN,MAX) Time : (%lf, %lf) msecs\n", (double)tl->mint/MSEC,
               (double)tl->maxt/MSEC);*/
        fflush(perfF);
        fclose(perfF);
    } else {
        return -1;
    }
    return 0;
}

#define XLNX_TL_CREATE(H)                       \
    do {                                        \
        H = xlnx_tl_create();                   \
    } while(0);                                 \

#define XLNX_TL_DESTROY(H)                      \
    do {                                        \
        if (H) {                                \
            xlnx_tl_destroy(H);                 \
        }                                       \
    } while(0);

#define XLNX_TL_START(H)                        \
    do {                                        \
        if (H) {                                \
            xlnx_tl_start(H);                   \
        }                                       \
    } while(0);                                 \

#define XLNX_TL_PAUSE(H)                        \
    do {                                        \
        if (H) {                                \
            xlnx_tl_pause(H);                   \
        }                                       \
    } while(0);

#define XLNX_TL_START_RET(R, H)                 \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_start(H);               \
        }                                       \
    } while(0);                                 \

#define XLNX_TL_PAUSE_RET(R, H)                 \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_pause(H);               \
        }                                       \
    } while(0);

#define XLNX_TL_GET_TT(R, H)                    \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_get_tt(H);              \
        }                                       \
    } while(0);

#define XLNX_TL_GET_AVG_MSEC(R, H, C)           \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_get_avg_msec(H, C);     \
        }                                       \
    } while(0);

#define XLNX_TL_GET_AVG_FPS(R, H, C)            \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_get_avg_fps(X, C);      \
        }                                       \
    } while(0);

#define XLNX_TL_DUMP_RESULTS(H, F, C)           \
    do {                                        \
        if (H) {                                \
            xlnx_tl_dump_results(H, F, C);      \
        }                                       \
    } while(0);

#define XLNX_TL_DUMP_RESULTS_RET(R, H, F, C)    \
    do {                                        \
        if (H) {                                \
            R = xlnx_tl_dump_results(H, F, C);  \
        }                                       \
    } while(0);

#else //ENABLE_XLNX_TIME_LOGGER

#define XLNX_TL_CREATE(H)                       \
    do {                                        \
        H = NULL;                               \
    } while(0);                                 \

#define XLNX_TL_DESTROY(H)
#define XLNX_TL_START(H)
#define XLNX_TL_PAUSE(H)
#define XLNX_TL_START_RET(R, H)  R = 0;
#define XLNX_TL_PAUSE_RET(R, H)  R = 0;
#define XLNX_TL_GET_TT(R, H) R = 0;
#define XLNX_TL_GET_AVG_MSEC(R, H, C) R = 0;
#define XLNX_TL_GET_AVG_FPS(R, H, C) R = 0;
#define XLNX_TL_DUMP_RESULTS(H, F, C)
#define XLNX_TL_DUMP_RESULTS_RET(R, H, F, C) R = 0;

#endif//ENABLE_XLNX_TIME_LOGGER
#endif //XLNX_TIME_LOGGER_H
