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

#include "radio.h"

#include "nrf.h"

/**
 * channel_to_freq(int channel)
 *
 * Convert a BLE channel number into the corresponding frequency offset
 * for the nRF51822.
 **/

static uint8_t channel_to_freq(int channel) {
    if (channel == 37) {
        return 2;
    } else if (channel == 38) {
        return 26;
    } else if (channel == 39) {
        return 80;
    } else if (channel < 11) {
        return 2*(channel + 2);
    } else {
        return 2*(channel + 3);
    }
}


/**
 * radio_disable()
 *
 * Disable the radio.
 **/

void radio_disable(void) {
    if (NRF_RADIO->STATE > 0) {
        NVIC_DisableIRQ(RADIO_IRQn);
        NRF_RADIO->EVENTS_DISABLED = 0;
        NRF_RADIO->TASKS_DISABLE = 1;
        while (NRF_RADIO->EVENTS_DISABLED == 0);
    }
}


void radio_init() {
    radio_disable();

    // Enable the High Frequency clock on the processor. This is a pre-requisite for
    // the RADIO module. Without this clock, no communication is possible.
    NRF_CLOCK->EVENTS_HFCLKSTARTED = 0;
    NRF_CLOCK->TASKS_HFCLKSTART = 1;
    while (NRF_CLOCK->EVENTS_HFCLKSTARTED == 0);

    // power should be one of: -30, -20, -16, -12, -8, -4, 0, 4
    NRF_RADIO->TXPOWER = (RADIO_TXPOWER_TXPOWER_0dBm << RADIO_TXPOWER_TXPOWER_Pos);

    /* Set BLE data rate. */
    NRF_RADIO->MODE = (RADIO_MODE_MODE_Ble_1Mbit << RADIO_MODE_MODE_Pos);

    NRF_RADIO->TXADDRESS = 0; // transmit on logical address 0
    NRF_RADIO->RXADDRESSES = 1; // a bit mask, listen only to logical address 0

    NRF_RADIO->PCNF0 = (
                           (((1UL) << RADIO_PCNF0_S0LEN_Pos) & RADIO_PCNF0_S0LEN_Msk) |  /* Length of S0 field in bytes 0-1.    */
                           (((0UL) << RADIO_PCNF0_S1LEN_Pos) & RADIO_PCNF0_S1LEN_Msk) |  /* Length of S1 field in bits 0-8.     */
                           (((8UL) << RADIO_PCNF0_LFLEN_Pos) & RADIO_PCNF0_LFLEN_Msk)    /* Length of length field in bits 0-8. */
                       );

    /* Packet configuration */
    NRF_RADIO->PCNF1 = (
                           (((250UL) << RADIO_PCNF1_MAXLEN_Pos) & RADIO_PCNF1_MAXLEN_Msk)   |                      /* Maximum length of payload in bytes [0-255] */
                           (((0UL) << RADIO_PCNF1_STATLEN_Pos) & RADIO_PCNF1_STATLEN_Msk)   |                      /* Expand the payload with N bytes in addition to LENGTH [0-255] */
                           (((3UL) << RADIO_PCNF1_BALEN_Pos) & RADIO_PCNF1_BALEN_Msk)       |                      /* Base address length in number of bytes. */
                           (((RADIO_PCNF1_ENDIAN_Little) << RADIO_PCNF1_ENDIAN_Pos) & RADIO_PCNF1_ENDIAN_Msk) |  /* Endianess of the S0, LENGTH, S1 and PAYLOAD fields. */
                           (((1UL) << RADIO_PCNF1_WHITEEN_Pos) & RADIO_PCNF1_WHITEEN_Msk)                         /* Enable packet whitening */
                       );

    /* We enable CRC check. */
    NRF_RADIO->CRCCNF  = (RADIO_CRCCNF_LEN_Three << RADIO_CRCCNF_LEN_Pos) |
                         (RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos); /* Skip Address when computing CRC */
    // configure interrupts
    NRF_RADIO->INTENSET = 0x00000008;

    // Radio Ready -> Start, Address Received -> Measure RSSI
    NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | RADIO_SHORTS_ADDRESS_RSSISTART_Msk;

    NVIC_SetPriority(RADIO_IRQn, 0);
}


/**
 * radio_follow_conn(uint32_t accessAddress, int channel, uint32_t crcInit)
 *
 * Configure the nRF51 to prepare to follow an existing connection (AA+CRCInit).
 **/

void radio_follow_conn(uint32_t accessAddress, int channel, uint32_t crcInit) {
    /* We reconfigure the radio to use our new parameters. */
    radio_disable();

    /* Listen on channel 6 (2046 => index 1 in BLE). */
    NRF_RADIO->FREQUENCY = channel_to_freq(channel);
    NRF_RADIO->DATAWHITEIV = channel;

    /* Set default access address used on advertisement channels. */
    NRF_RADIO->PREFIX0 = (accessAddress & 0xff000000)>>24;
    NRF_RADIO->BASE0 = (accessAddress & 0x00ffffff)<<8;

    NRF_RADIO->CRCINIT = crcInit;                                                  /* Initial value of CRC */
    NRF_RADIO->CRCPOLY = 0x00065B;                                                  /* CRC polynomial function */

    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);

    // enable receiver (once enabled, it will listen)
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_RXEN = 1;
}

void radio_set_channel_fast(int channel) {
    /* Go listening on the new channel. */
    radio_disable();

    NRF_RADIO->FREQUENCY = channel_to_freq(channel);
    NRF_RADIO->DATAWHITEIV = channel;

    NVIC_ClearPendingIRQ(RADIO_IRQn);
    NVIC_EnableIRQ(RADIO_IRQn);

    // enable receiver (once enabled, it will listen)
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_RXEN = 1;
}

void radio_filter_configure(uint8_t bitmask_enable, uint8_t bitmask_addr_type, uint8_t *bdaddr) {
    uint8_t index;

    for (index = 0; index < 8; index++) {
        NRF_RADIO->DAB[index] = ((uint32_t)bdaddr[3] << 24) |
                                ((uint32_t)bdaddr[2] << 16) |
                                ((uint32_t)bdaddr[1] << 8) |
                                bdaddr[0];
        NRF_RADIO->DAP[index] = ((uint32_t)bdaddr[5] << 8) | bdaddr[4];
        bdaddr += 6;
    }

    NRF_RADIO->DACNF = ((uint32_t)bitmask_addr_type << 8) | bitmask_enable;
}

void radio_filter_disable(void) {
    NRF_RADIO->DACNF &= ~(0x000000FF);
}

void radio_filter_status_reset(void) {
    NRF_RADIO->EVENTS_DEVMATCH = 0;
}

uint32_t radio_filter_has_match(void) {
    return (NRF_RADIO->EVENTS_DEVMATCH != 0);
}

uint32_t radio_filter_match_get(void) {
    return NRF_RADIO->DAI;
}
