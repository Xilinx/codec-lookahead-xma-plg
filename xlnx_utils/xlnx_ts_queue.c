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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>

#include "xlnx_ts_queue.h"

#define LOCK_Q pthread_mutex_lock(&queue->lock)
#define UNLOCK_Q pthread_mutex_unlock(&queue->lock)

#define WAIT_FOR_ENQUEUE                                           \
    do {                                                           \
        while (isEmpty(queue->q) && queue->isActive) {             \
            pthread_cond_wait(&queue->condNotEmpty, &queue->lock); \
        }                                                          \
    } while (0)

#define SIGNAL_ENQUEUE pthread_cond_signal(&queue->condNotEmpty)

#define WAIT_FOR_DEQUEUE                                            \
    do {                                                            \
        while (isFull(queue->q) && queue->isActive) {               \
            pthread_cond_wait(&queue->condNotFull, &queue->lock);   \
        }                                                           \
    } while(0)
#define SIGNAL_DEQUEUE pthread_cond_signal(&queue->condNotFull)

#define WAIT_FOR_SIZE_CHANGE(currSize)                                \
    do {                                                              \
        while ((getSize(queue->q) == currSize) && queue->isActive) {  \
            pthread_cond_wait(&queue->condSizeChanged, &queue->lock); \
        }                                                             \
    } while(0)
#define SIGNAL_SIZE_CHANGED pthread_cond_signal(&queue->condSizeChanged)

#define RETURN_IF_INACTIVE                                            \
    do {                                                              \
        if (queue->isActive == 0) return XLNX_TS_QUEUE_INACTIVE;      \
    } while (0)                                                       \

typedef struct my_ts_queue
{
    pthread_mutex_t lock;
    pthread_cond_t condNotEmpty;
    pthread_cond_t condNotFull;
    pthread_cond_t condSizeChanged;
    uint8_t isActive;
    xlnx_queue q;
} my_ts_queue;

xlnx_ts_queue createTSQ(size_t capacity, size_t itemSize)
{
    xlnx_queue queue;
    my_ts_queue *q = (my_ts_queue *)calloc(1, sizeof(my_ts_queue));
    if (NULL == q) {
        //printf("Error: createTSQ OOM\n");
        return q;
    }
    queue = createQueue(capacity, itemSize);
    if (NULL == queue) {
        //printf("Error: createTSQ OOM\n");
        free(q);
        return NULL;
    }
    q->q = queue;
    if (pthread_mutex_init(&q->lock, NULL) < 0) {
        destroyQueue(queue);
        free(q);
        //printf("Error: createTSQ Failed!!");
        return NULL;
    }
    pthread_cond_init(&q->condNotEmpty, NULL);
    pthread_cond_init(&q->condNotFull, NULL);
    q->isActive = 1;
    return (xlnx_ts_queue)q;
}

void destroyTSQ(xlnx_ts_queue q)
{
    my_ts_queue *queue = (my_ts_queue *)q;
    if (NULL == queue) {
        return;
    }
    pthread_cond_destroy(&queue->condNotEmpty);
    pthread_cond_destroy(&queue->condNotFull);
    pthread_mutex_destroy(&queue->lock);
    destroyQueue(queue->q);
    free(queue);
    return;
}

int isFullTSQ(xlnx_ts_queue q)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = isFull(queue->q);
    UNLOCK_Q;
    return ret;
}

int isEmptyTSQ(xlnx_ts_queue q)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = isEmpty(queue->q);
    UNLOCK_Q;
    return ret;
}

size_t getSizeTSQ(xlnx_ts_queue q)
{
    size_t size;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    size = getSize(queue->q);
    UNLOCK_Q;
    return size;
}

int enqueueTSQ(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = enqueue(queue->q, item);
    if (ret == 0) {
        SIGNAL_ENQUEUE;
        SIGNAL_SIZE_CHANGED;
    }
    UNLOCK_Q;
    return ret;
}

int enqueueTSQ_b(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    WAIT_FOR_DEQUEUE;
    ret = enqueue(queue->q, item);
    if (ret == 0) {
        SIGNAL_ENQUEUE;
        SIGNAL_SIZE_CHANGED;
    }
    UNLOCK_Q;
    return ret;
}

int dequeueTSQ(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = dequeue(queue->q, item);
    if (ret == 0) {
        SIGNAL_DEQUEUE;
        SIGNAL_SIZE_CHANGED;
    }
    UNLOCK_Q;
    return ret;
}

int dequeueTSQ_b(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    WAIT_FOR_ENQUEUE;
    ret = dequeue(queue->q, item);
    if (ret == 0) {
        SIGNAL_DEQUEUE;
        SIGNAL_SIZE_CHANGED;
    }
    UNLOCK_Q;
    return ret;
}

int frontTSQ(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = front(queue->q, item);
    UNLOCK_Q;
    return ret;
}

int frontTSQ_b(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    WAIT_FOR_ENQUEUE;
    ret = front(queue->q, item);
    UNLOCK_Q;
    return ret;
}

int rearTSQ(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    ret = rear(queue->q, item);
    UNLOCK_Q;
    return ret;
}

int rearTSQ_b(xlnx_ts_queue q, XItem item)
{
    int ret;
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    WAIT_FOR_ENQUEUE;
    ret = rear(queue->q, item);
    UNLOCK_Q;
    return ret;
}

int waitForSizeChangeTSQ(xlnx_ts_queue q, size_t currSize)
{
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    WAIT_FOR_SIZE_CHANGE(currSize);
    UNLOCK_Q;
    return 0;
}

int PushTSQ(xlnx_ts_queue q, XItem item)
{
    return enqueueTSQ(q, item);
}

int PushTSQ_b(xlnx_ts_queue q, XItem item)
{
    return enqueueTSQ_b(q, item);
}

int PopTSQ(xlnx_ts_queue q, XItem item)
{
    int empty = 0;
    if(dequeueTSQ(q, item) < 0) {
        empty = 1;
    }
    return empty;
}

int PopTSQ_b(xlnx_ts_queue q, XItem item)
{
    int empty = 0;
    if(dequeueTSQ_b(q, item) < 0) {
        empty = 1;
    }
    return empty;
}

int PeepFrontTSQ(xlnx_ts_queue q, XItem item)
{
    return frontTSQ(q, item);
}

int PeepFrontTSQ_b(xlnx_ts_queue q, XItem item)
{
    return frontTSQ_b(q, item);
}

int PeepRearTSQ(xlnx_ts_queue q, XItem item)
{
    return rearTSQ(q, item);
}

int PeepRearTSQ_b(xlnx_ts_queue q, XItem item)
{
    return rearTSQ_b(q, item);
}

int unBlockTSQ(xlnx_ts_queue q)
{
    my_ts_queue *queue = (my_ts_queue *)q;
    assert(queue != NULL);
    LOCK_Q;
    queue->isActive = 0;
    SIGNAL_ENQUEUE;
    SIGNAL_DEQUEUE;
    SIGNAL_SIZE_CHANGED;
    UNLOCK_Q;
    return 0;
}
