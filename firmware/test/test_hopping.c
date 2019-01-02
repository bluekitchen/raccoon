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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


#include "hopping.h"

static uint8_t channel_selection_2(uint16_t counter, uint16_t chan_id, uint8_t *chan_map, uint8_t chan_count){
    hopping_t h;
    hopping_init( &h );
    hopping_set_channel_map( &h, chan_map );
    h.channelIdentifier = chan_id;
    uint8_t channel = hopping_csa2_get_channel_for_counter(&h, counter);
    printf("Counter %u, chan_id %04x, chan_count %2u -> %2u\n", counter, chan_id, chan_count, channel);
    return channel;
}

static void channel_selection_2_unit_test(void)
{
    static uint8_t chan_map_1[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x1F};
    static uint8_t chan_map_2[] = {0x00, 0x06, 0xE0, 0x00, 0x1E};
    uint8_t m;

    m = channel_selection_2(1, 0x305F, chan_map_1, 37);
    assert(m == 20);

    m = channel_selection_2(2, 0x305F, chan_map_1, 37);
    assert(m == 6);

    m = channel_selection_2(3, 0x305F, chan_map_1, 37);
    assert(m == 21);

    m = channel_selection_2(6, 0x305F, chan_map_2, 9);
    assert(m == 23);

    m = channel_selection_2(7, 0x305F, chan_map_2, 9);
    assert(m == 9);

    m = channel_selection_2(8, 0x305F, chan_map_2, 9);
    assert(m == 34);
}

int main(int argc, char *args[]) {

    // CSA #2 unit test
    channel_selection_2_unit_test();

//    uint8_t chm[] = "\xFF\x1F\x00\x00\x18";
    uint8_t chm[] = "\xFF\xFF\xFF\xFF\x1F";
//    uint8_t hopIncrement = 5;
    uint8_t hopIncrement = 3;
    hopping_t h;

    printf("%02x%02x%02x%02x%02x - %d\n", chm[0], chm[1], chm[2], chm[3], chm[4], hopIncrement );

    hopping_init( &h );

    hopping_set_channel_map( &h, chm );
    hopping_csa1_set_hop_increment( &h, hopIncrement );

    for(int i=0; i<sizeof(h.chRemap); ++i) {
        printf("%3d", h.chRemap[i] );
    }
    printf("\n");


    for(int i=0; i<20; ++i) {
        printf("%d\n", hopping_csa1_get_next_channel( &h ) );
    }

    return EXIT_SUCCESS;
}

