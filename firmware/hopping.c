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
 *******************************************************************************/

#include <string.h>
#include <strings.h>
#include <assert.h>

#include "debug.h"
#include "hopping.h"

#define GET_BIT( b, n )  ((b[(n&UINT32_C(0xFFFFFFF8))>>3]>>(n&0x7))&1)

void hopping_init( hopping_t *c ) {
    assert( c != NULL );

    memset( c, 0, sizeof(hopping_t) );
}

uint8_t hopping_get_next_channel( hopping_t *c ) {
    assert( c != NULL );

    c->currentCh = (c->currentCh + c->hopIncrement) % 37;
    if( 1 == GET_BIT( c->chMap, c->currentCh ) ) {
        return c->currentCh;
    } else {
        return c->chRemap[ c->currentCh % c->chCnt ];
    }
}

void hopping_set_channel_map( hopping_t *c, const uint8_t *chm, uint8_t hopIncrement ) {
    assert( c != NULL );
    assert( chm != NULL );

    memcpy( c->chMap, chm, 5 );
    c->hopIncrement = hopIncrement;

    c->chCnt = 0;
    for(int i=0; i<37; ++i) {
        LOG_DBG("%d(%d)\n", i, (i&UINT32_C(0xFFFFFFF8))>>3 );
        LOG_DBG("%d(%d)\n", i, GET_BIT( c->chMap, i ) );
        if( 1 == GET_BIT( c->chMap, i ) ) {
            c->chRemap[c->chCnt++] = i;
        }
    }

//    for(int i=0; i<c->chCnt; ++i)
//        printf("%d\n", c->chRemap[i] );

//    printf("chCnt: %d\n", c->chCnt );
}



