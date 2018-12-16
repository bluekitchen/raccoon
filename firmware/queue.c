/*******************************************************************************
 *
 *      Copyright (c) 2018, Raccon BLE Sniffer
 *      All rights reserved.
 *
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of "btlejack2" nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *************************************************************n******************/

#include <assert.h>
#include <stdbool.h>
#include "queue.h"

void queue_init( msgQueue_t *q ) {
    q->rdIdx = 0;
    q->wrIdx = 0;
}

uint8_t *queue_peek( msgQueue_t *q ) {
    assert( queue_getSize( q ) > 0 );
    uint32_t idx = (q->rdIdx & (q->elems-1));
    return q->queue + idx * q->elemSize;
}

uint8_t *queue_get( msgQueue_t *q ) {
    assert( queue_getSize( q ) > 0 );
    uint32_t idx = q->rdIdx++ & (q->elems-1);
    return q->queue + idx * q->elemSize;
}

uint8_t *queue_alloc( msgQueue_t *q ) {
    assert( queue_getSize( q ) <= q->elems );
    uint32_t idx = q->wrIdx & (q->elems-1);
    return q->queue + idx * q->elemSize;
}

uint8_t *queue_put( msgQueue_t *q ) {
    assert( queue_getSize( q ) <= q->elems );
    uint32_t idx = q->wrIdx++ & (q->elems-1);
    return q->queue + idx * q->elemSize;
}

uint32_t queue_getSize( msgQueue_t *q ) {
    return ((uint32_t)( q->wrIdx - q->rdIdx ));
}

bool queue_full( msgQueue_t *q ) {
    return queue_getSize( q ) >= q->elems;
}
