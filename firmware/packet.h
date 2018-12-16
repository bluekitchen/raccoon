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

#ifndef __PACKET_H_
#define __PACKET_H_

#include <stdint.h>

#include "pdu.h"

enum {
    TAG_DATA                  = 0,
    TAG_MSG_RESET_COMPLETE    = 0x40,
    TAG_MSG_CONNECT_REQUEST   = 0x41,
    TAG_MSG_CONNECTION_EVENT  = 0x42,
    TAG_MSG_CONN_PARAM_UPDATE = 0x43,
    TAG_MSG_CHAN_MAP_UPDATE   = 0x44,
    TAG_MSG_LOG               = 0x50,
    TAG_MSG_TERMINATE         = 0x45,
    TAG_CMD_RESET             = 0x80,
    TAG_CMD_GET_VERSION       = 0x81,
    TAG_CMD_SNIFF_CHANNEL     = 0x82,
};

enum {
    DIRECTION_DONT_KNOW = 0,
    DIRECTION_MASTER    = 1,
    DIRECTION_SLAVE     = 2,
};

typedef union {
    uint8_t value[0];
    struct {
        uint8_t  initiator[6];
        uint8_t  advertiser[6];
        uint32_t aa;
        uint32_t interval_us;
        uint32_t timeout_us;
        uint16_t latency;
    } __packed connect_request;
    struct {
        uint16_t count;
    } __packed connection_event;
    struct {
        uint8_t reason; // sniffer timeout vs. orderly disconnect
    } __packed terminate;
    struct {
        uint32_t interval_us;
        uint32_t timeout_us;
        uint16_t latency;
    } __packed conn_param_update;
    struct {
        uint8_t map[5];
    } __packed chan_map_update;
    struct {
        uint8_t channel;
        uint32_t aa;
        uint32_t crc_init;
        uint8_t mac[6];
    } __packed cmd_sniff_channel;
} __packed msg_data_t;

typedef struct {
    uint32_t   timestamp;
    msg_data_t data;
} __packed msg_t;

typedef struct {
    uint32_t timestamp;
    uint8_t  channel;
    uint8_t  flags;      // bits 0+1: direction, bit 2: CRC OK, bit 3: packet(s) missed
    uint8_t  rssi;
    uint8_t  _reserved;  // needed to align RX buffer after aa for radio DMA
    uint32_t aa;
    union {
        uint8_t value[0];
        struct pdu_adv adv;
        struct pdu_data data;
    } pdu;
} __packed radio_t;

typedef struct {
    uint8_t  tag;
    uint16_t length;
    union {
        // raw data access
        uint8_t value[0];

        // interprete as message
        msg_t msg;
        
        // interprete as radio packet
        radio_t payload;
    };
} __packed packet_t;

#endif
