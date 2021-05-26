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
#ifndef XLNX_TS_QUEUE_H
#define XLNX_TS_QUEUE_H

#include "xlnx_queue.h"

typedef void *xlnx_ts_queue;

#define XLNX_TS_QUEUE_ERROR -1
#define XLNX_TS_QUEUE_INACTIVE -2

xlnx_ts_queue createTSQ(size_t capacity, size_t itemSize);
void destroyTSQ(xlnx_ts_queue q);
int isFullTSQ(xlnx_ts_queue q);
int isEmptyTSQ(xlnx_ts_queue q);
size_t getSizeTSQ(xlnx_ts_queue q);
int enqueueTSQ(xlnx_ts_queue q, XItem item);
int enqueueTSQ_b(xlnx_ts_queue q, XItem item);
int dequeueTSQ(xlnx_ts_queue q, XItem item);
int dequeueTSQ_b(xlnx_ts_queue q, XItem item);
int frontTSQ(xlnx_ts_queue q, XItem item);
int frontTSQ_b(xlnx_ts_queue q, XItem item);
int rearTSQ(xlnx_ts_queue q, XItem item);
int rearTSQ_b(xlnx_ts_queue q, XItem item);
int waitForSizeChangeTSQ(xlnx_ts_queue q, size_t currSize);

int PushTSQ(xlnx_ts_queue q, XItem buff);
int PushTSQ_b(xlnx_ts_queue q, XItem buff);
int PopTSQ(xlnx_ts_queue q, XItem buff);
int PopTSQ_b(xlnx_ts_queue q, XItem buff);
int PeepFrontTSQ(xlnx_ts_queue q, XItem item);
int PeepFrontTSQ_b(xlnx_ts_queue q, XItem item);
int PeepRearTSQ(xlnx_ts_queue q, XItem item);
int PeepRearTSQ_b(xlnx_ts_queue q, XItem item);

int unBlockTSQ(xlnx_ts_queue q);

#endif // XLNX_TS_QUEUE_H