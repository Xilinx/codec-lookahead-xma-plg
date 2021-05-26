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
#include <stdio.h>
#include <pthread.h>
#include "xlnx_thread.h"
//#define ENABLE_XLNX_TIME_LOGGER
#include "xlnx_time_logger.h"

#define LOCK_S pthread_mutex_lock(&t->lock)
#define UNLOCK_S pthread_mutex_unlock(&t->lock)
#define WAIT_FOR_STATE_CHANGE pthread_cond_wait(&t->state_changed, &t->lock)
#define SIGNAL_STATE_CHANGED pthread_cond_signal(&t->state_changed)

static const char *state_str[] = {
    "EXlnxThreadCreate",
    "EXlnxThreadCreated",
    "EXlnxThreadStart",
    "EXlnxThreadStarted",
    "EXlnxThreadPause",
    "EXlnxThreadStop",
    "EXlnxThreadStopped",
    "EXlnxThreadError"
};

typedef struct
{
    pthread_t t;
    xlnx_thread_state_t state;
    xlnx_thread_param param;
    pthread_mutex_t lock;
    pthread_cond_t state_changed;
    xlnx_time_logger_t thread_tl;
} xlnx_thread_ctx;


static void *xlnx_thread_run(void *arg)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *) arg;
    xlnx_thread_func_ret_t ret = ERetError;
    LOCK_S;
    if (t->state == EXlnxThreadCreate) {
        t->state = EXlnxThreadCreated;
        SIGNAL_STATE_CHANGED;
    }
    UNLOCK_S;
    do {
        LOCK_S;
        while (t->state == EXlnxThreadCreated) {
            //printf("[%p]:xlnx_thread_run Created!! %s %s %d \n", t, __FILE__, __FUNCTION__, __LINE__);
            WAIT_FOR_STATE_CHANGE;
        }

        if ((t->state == EXlnxThreadStart) || (t->state == EXlnxThreadStarted)) {
            //printf("[%p]:Thread in EXlnxThreadStarted state!! %s %s %d \n", t, __FILE__, __FUNCTION__, __LINE__);
            if (t->param.func == NULL) {
                //printf("Error[%p]: %s %s Nothing to execute!!\n", t, __FILE__, __FUNCTION__);
                t->state = EXlnxThreadError;
                SIGNAL_STATE_CHANGED;
                UNLOCK_S;
                return NULL;
            }
            if (t->state == EXlnxThreadStart) {
                t->state = EXlnxThreadStarted;
                SIGNAL_STATE_CHANGED;
            }
            UNLOCK_S;
            ret = t->param.func(t->param.arg);
            if (ret == ERetError) {
                //printf("Error[%p]: %s %s Execution failed!!\n", t, __FILE__, __FUNCTION__);
                LOCK_S;
                t->state = EXlnxThreadError;
                SIGNAL_STATE_CHANGED;
                UNLOCK_S;
                return NULL;
            } else if (ret == ERetDone) {
                LOCK_S;
                t->state = EXlnxThreadCreated;
                SIGNAL_STATE_CHANGED;
                XLNX_TL_PAUSE(t->thread_tl);
                UNLOCK_S;
                break;
            }
        } else if (t->state == EXlnxThreadPause) {
            t->state = EXlnxThreadCreated;
            SIGNAL_STATE_CHANGED;
            UNLOCK_S;
        } else if (t->state == EXlnxThreadStop) {
            t->state = EXlnxThreadStopped;
            SIGNAL_STATE_CHANGED;
            XLNX_TL_PAUSE(t->thread_tl);
            UNLOCK_S;
            break;
        } else {
            /*printf("Error[%p]: %s %s Thread in %s %d state!!\n", t, __FILE__,
            __FUNCTION__, t->state == EXlnxThreadError? "EXlnxThreadError" :
            "Unknown",
            t->state);*/
            t->state = EXlnxThreadError;
            UNLOCK_S;
            return NULL;
        }
    } while(1);
    LOCK_S;
    t->state = EXlnxThreadStopped;
    UNLOCK_S;
    //printf("[%p]:xlnx_thread_run Exit!! %s %s %d \n", t, __FILE__, __FUNCTION__, __LINE__);
    return NULL;
}

xlnx_thread_t xlnx_thread_create()
{
    int32_t ret = -1;
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)calloc(1, sizeof(xlnx_thread_ctx));
    if (NULL == t) {
        //printf("Error: Out of Memory! %s : %s\n", __FILE__, __FUNCTION__);
        return t;
    }
    t->state = EXlnxThreadCreate;
    if (pthread_mutex_init(&t->lock, NULL) < 0) {
        free(t);
        //printf("Error: pthread_mutex_init failed %s : %s\n", __FILE__, __FUNCTION__);
        return NULL;
    }
    //t->state_changed = PTHREAD_COND_INITIALIZER;
    t->state = EXlnxThreadCreated;
    ret = pthread_create(&t->t, NULL, xlnx_thread_run, t);
    if (ret != 0) {
        //printf("Error: %s %s pthread_create failed!!\n", __FILE__, __FUNCTION__);
        free(t);
        return NULL;
    }
    LOCK_S;
    while (t->state != EXlnxThreadCreated) {
        WAIT_FOR_STATE_CHANGE;
    }
    UNLOCK_S;
    //XLNX_TL_CREATE(t->thread_tl);
    return (xlnx_thread_t)t;
}

int32_t xlnx_thread_start(xlnx_thread_t thread, xlnx_thread_param *param)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if (t == NULL) {
        return -1;
    }
    LOCK_S;
    if (t->state == EXlnxThreadStarted) {
        UNLOCK_S;
        return 0;
    }
    if (t->state != EXlnxThreadCreated) {
        /*printf("Error[%p]: %s %s xlnx_thread_start in %d State!!\n", t, __FILE__,
        __FUNCTION__, t->state);*/
        UNLOCK_S;
        return -1;
    }
    if (param) {
        t->param = *param;
    }
    t->state = EXlnxThreadStart;
    SIGNAL_STATE_CHANGED;
    UNLOCK_S;

    LOCK_S;
    while (t->state != EXlnxThreadStarted && t->state != EXlnxThreadError) {
        WAIT_FOR_STATE_CHANGE;
        //printf("[%p] : xlnx_thread_start State Changed to [%d] = %s\n", t, t->state, state_str[t->state]);
    }
    if (t->state == EXlnxThreadError) {
        //printf("Error[%p] : xlnx_thread_start failed!!\n", t);
        UNLOCK_S;
        return -1;
    }
    XLNX_TL_START(t->thread_tl);
    UNLOCK_S;
    return 0;
}

int32_t xlnx_thread_pause(xlnx_thread_t thread)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if (t == NULL) {
        return -1;
    }
    LOCK_S;
    if (t->state == EXlnxThreadCreated) {
        UNLOCK_S;
        return 0;
    } else if (t->state == EXlnxThreadError) {
        UNLOCK_S;
        return -1;
    }
    t->state = EXlnxThreadPause;
    SIGNAL_STATE_CHANGED;
    UNLOCK_S;

    LOCK_S;
    while (t->state != EXlnxThreadCreated && t->state != EXlnxThreadError) {
        WAIT_FOR_STATE_CHANGE;
        //printf("[%p] : xlnx_thread_pause State Changed to %d\n", t, t->state);
    }
    if (t->state == EXlnxThreadError) {
        //printf("Error[%p] : xlnx_thread_pause failed!!\n", t);
        UNLOCK_S;
        return -1;
    }
    XLNX_TL_PAUSE(t->thread_tl);
    UNLOCK_S;
    return 0;
}

int32_t xlnx_thread_stop(xlnx_thread_t thread)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if (t == NULL) {
        return -1;
    }
    LOCK_S;
    if (t->state == EXlnxThreadStop) {
        UNLOCK_S;
        return 0;
    } else if (t->state == EXlnxThreadError) {
        UNLOCK_S;
        return -1;
    }
    t->state = EXlnxThreadStop;
    SIGNAL_STATE_CHANGED;
    UNLOCK_S;

    LOCK_S;
    while ((t->state == EXlnxThreadStart) || (t->state == EXlnxThreadStarted)) {
        WAIT_FOR_STATE_CHANGE;
        //printf("[%p] : xlnx_thread_stop State Changed to %d\n", t, t->state);
    }
    if (t->state == EXlnxThreadError) {
        //printf("Error[%p] : xlnx_thread_pause failed!!\n", t);
        UNLOCK_S;
        return -1;
    }
    UNLOCK_S;
    return 0;
}

static int32_t xlnx_thread_wait(xlnx_thread_t thread)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if (t == NULL) {
        return -1;
    }
    pthread_join(t->t, NULL);
    return 0;
}

int32_t xlnx_thread_get_state(xlnx_thread_t thread, xlnx_thread_state_t *state)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if ((t == NULL) || (state == NULL)) {
        return -1;
    }
    LOCK_S;
    *state = t->state;
    UNLOCK_S;
    return 0;
}

const char *xlnx_thread_get_state_str(xlnx_thread_t thread,
                                      const xlnx_thread_state_t state)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if ((t == NULL) ||
            (state > (sizeof(xlnx_thread_state_t)/sizeof(int)))) {
        return NULL;
    }
    return state_str[state];
}

int32_t xlnx_thread_destroy(xlnx_thread_t thread)
{
    xlnx_thread_ctx *t = (xlnx_thread_ctx *)thread;
    if (t == NULL) {
        return -1;
    }
    /*
    LOCK_S;
    if ((EXlnxThreadStarted != t->state) && (EXlnxThreadStart != t->state)) {
        UNLOCK_S;
        xlnx_thread_stop(t);
        LOCK_S;
    }
    UNLOCK_S;
    */
    xlnx_thread_stop(t);
    xlnx_thread_wait(t);
    if (t->thread_tl) {
        char strbuf[512];
        sprintf(strbuf, "la_thread_perf_%p", t);
        XLNX_TL_DUMP_RESULTS(t->thread_tl, &strbuf[0], 1200);
        XLNX_TL_DESTROY(t->thread_tl);
        t->thread_tl = NULL;
    }
    pthread_mutex_destroy(&t->lock);
    free(t);
    return 0;
}

