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
#ifndef XLNX_THREAD_H
#define XLNX_THREAD_H

#include <sys/types.h>

typedef void *xlnx_thread_t;
typedef void *xlnx_thread_func_args_t;

typedef enum
{
    ERetError,
    ERetDone,
    ERetRunAgain
} xlnx_thread_func_ret_t;

typedef xlnx_thread_func_ret_t (*xlnx_thread_run_func_t) (
    xlnx_thread_func_args_t);

typedef enum
{
    EXlnxThreadCreate,
    EXlnxThreadCreated,
    EXlnxThreadStart,
    EXlnxThreadStarted,
    EXlnxThreadPause,
    EXlnxThreadStop,
    EXlnxThreadStopped,
    EXlnxThreadError
} xlnx_thread_state_t;

typedef struct
{
    xlnx_thread_run_func_t func;
    void *arg;
} xlnx_thread_param;

xlnx_thread_t xlnx_thread_create();
int32_t xlnx_thread_start(xlnx_thread_t thread, xlnx_thread_param *param);
int32_t xlnx_thread_pause(xlnx_thread_t thread);
int32_t xlnx_thread_stop(xlnx_thread_t thread);
int32_t xlnx_thread_get_state(xlnx_thread_t thread, xlnx_thread_state_t *state);
const char *xlnx_thread_get_state_str(xlnx_thread_t thread,
                                      const xlnx_thread_state_t state);
int32_t xlnx_thread_destroy(xlnx_thread_t thread);

#endif //XLNX_THREAD_H
