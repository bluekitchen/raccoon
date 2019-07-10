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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#include <string.h>

//
// Development options, disabled by default
//

// Undef DEBUG for Segger RTT debug output
// #define DEBUG

// PCA10040 - P0.09 + P0.10
// #define GPIO_DURING_RADIO 9
// #define GPIO_DURING_TIMER 10

#include "nrf.h"
#include "nrfx_uart.h"
#include "sniffer_config.h"

#ifdef BOARD_PCA10059
#include "nrf_drv_usbd.h"
#include "nrf_drv_clock.h"
#include "nrf_gpio.h"
#include "nrf_delay.h"
#include "nrf_drv_power.h"
#include "nrf_queue.h"

#include "app_error.h"
#include "app_util.h"
#include "app_usbd_core.h"
#include "app_usbd.h"
#include "app_usbd_string_desc.h"
#include "app_usbd_cdc_acm.h"
#include "app_usbd_serial_num.h"
#endif

#include "debug.h"
#include "packet.h"
#include "bsp.h"

#include "pdu.h"
#include "radio.h"
#include "timer.h"
#include "hopping.h"
#include "queue.h"


#ifdef BOARD_PCA10059
#define LED_USB_RESUME      (BSP_LED_0_MASK)
#define LED_CDC_ACM_OPEN    (BSP_LED_1_MASK)
#define LED_CDC_ACM_RX      (BSP_LED_2_MASK)
#define LED_CDC_ACM_TX      (BSP_LED_3_MASK)

#define BTN_CDC_DATA_SEND       0
#define BTN_CDC_NOTIFY_SEND     1

#define BTN_CDC_DATA_KEY_RELEASE        (bsp_event_t)(BSP_EVENT_KEY_LAST + 1)

/**
 * @brief Enable power USB detection
 *
 * Configure if example supports USB port connection
 */
#ifndef USBD_POWER_DETECTION
#define USBD_POWER_DETECTION true
#endif


static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const * p_inst,
                                    app_usbd_cdc_acm_user_event_t event);

#define CDC_ACM_COMM_INTERFACE  0
#define CDC_ACM_COMM_EPIN       NRF_DRV_USBD_EPIN2

#define CDC_ACM_DATA_INTERFACE  1
#define CDC_ACM_DATA_EPIN       NRF_DRV_USBD_EPIN1
#define CDC_ACM_DATA_EPOUT      NRF_DRV_USBD_EPOUT1

/**
 * @brief CDC_ACM class instance
 * */
APP_USBD_CDC_ACM_GLOBAL_DEF(m_app_cdc_acm,
                            cdc_acm_user_ev_handler,
                            CDC_ACM_COMM_INTERFACE,
                            CDC_ACM_DATA_INTERFACE,
                            CDC_ACM_COMM_EPIN,
                            CDC_ACM_DATA_EPIN,
                            CDC_ACM_DATA_EPOUT,
                            APP_USBD_CDC_COMM_PROTOCOL_AT_V250
);

NRF_QUEUE_DEF(uint8_t,
              m_rx_queue,
              2*NRF_DRV_USBD_EPSIZE,
              NRF_QUEUE_MODE_OVERFLOW);

static char m_rx_buffer[NRF_DRV_USBD_EPSIZE];

#endif

// read unaligned 16+24 bit
#define READ_LE_16(a) ( ((*(((uint8_t*)a)+0))<<0) | ((*(((uint8_t*)a)+1))<<8) )
#define READ_LE_24(a) ( ((*(((uint8_t*)a)+0))<<0) | ((*(((uint8_t*)a)+1))<<8) | ((*(((uint8_t*)a)+2))<<16))
#define READ_LE_32(a) ( ((*(((uint8_t*)a)+0))<<0) | ((*(((uint8_t*)a)+1))<<8) | ((*(((uint8_t*)a)+2))<<16) | ((*(((uint8_t*)a)+3))<<24))

// bluetooth.h
#define ADVERTISING_RADIO_ACCESS_ADDRESS 0x8E89BED6
#define ADVERTISING_CRC_INIT             0x555555

// from SDK UART example
#define UART_TX_BUF_SIZE 128                         /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1                           /**< UART RX buffer size. */

#define PDU_META_OFFSET (offsetof(packet_t, payload.pdu))

#define CRC_LEN 3

// sync hop delay
#define SYNC_HOP_DELAY_US 1250

static nrfx_uart_t uart_inst = NRFX_UART_INSTANCE(0);

static msgQueue_t * rxQ =  QUEUE_ALLOC( 64, PDU_META_OFFSET + 255 + CRC_LEN );
static msgQueue_t * msgQ = QUEUE_ALLOC( 16, PDU_META_OFFSET + 80 );

//#define USE_RTT_OUTPUT
//#define AUTO_START

enum {
    IDLE             = 0,
    FOLLOW_CONNECT   = 1,
    SYNC_CONNECTION  = 2,
    FOLLOW_DATA      = 3,
};

struct {
    int mode;
    volatile bool     synced;
    volatile uint16_t packet_nr_in_connection_event;
    volatile uint32_t interval_us;
    volatile uint32_t timeout_us;
    volatile uint32_t latency;

    // connection filter - address is stored in little-endian for fast compare in radio IRQ
    bool              connection_filter_active;
    uint8_t           connection_filter_address[6];

    // start of current connection event
    volatile uint32_t acnhor_us;

    // current channel
    volatile uint8_t  channel;

    // min rssi (negative)
    volatile uint8_t rssi_min_negative;

    // access address
    volatile uint32_t aa;

    // cache last advertisement - to check if CSA #2 is supported
    uint8_t  advertisement_cache_address[6];
    uint16_t advertisement_cache_csa2_supported;

    // channels selection algorithm index (1 for csa #2)
    volatile uint8_t channel_selection_algorithm;

    // current connection event, first one starts with 0
    // - needed for connection param and channel map updates as well as encryption
    volatile uint16_t connection_event;

    // next expected packet in same connection event
    volatile uint32_t next_expected_packet_us;

    // simple supervision timeout
    volatile uint32_t time_without_any_packets_us;

    // track direction: 0 - master to slave packet, 1- slave to master packet
    volatile uint8_t  direction;

    // track buffer overrun
    volatile uint8_t  buffer_overrun;

    // pending channel map update
    volatile uint8_t  channel_map_update_pending;
    volatile uint16_t channel_map_update_instant;
    volatile uint8_t  channel_map_update_map[5];

    // pending connection param update
    volatile uint8_t  conn_param_update_pending;
    volatile uint16_t conn_param_update_instant;
    volatile uint8_t  conn_param_update_win_size;
    volatile uint16_t conn_param_update_win_offset;
    volatile uint32_t conn_param_update_interval_us;
    volatile uint16_t conn_param_update_latency;
    volatile uint32_t conn_param_update_timeout_us;

} ctx = { .synced = false, .channel_map_update_pending = 0, .conn_param_update_pending = 0 };

hopping_t h;
uint16_t hop;

void printf_hexdump( void *buf, size_t l ) {
#ifdef DEBUG
    uint8_t *d = buf;
    for(size_t i=0; i<l; ++i) {
        printf("%02x ", d[i] );
    }
    printf("\n");
#else
    (void) buf;
    (void) l;
#endif
}

static void abort_following(void) {
    timer_stop( hop );
    ctx.synced  = false;
    ctx.mode = IDLE;
    radio_disable();
}

static void insert_log_message(const char * msg) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_LOG;
    pkt->msg.timestamp = timer_get_timestamp();
    pkt->length = 4 + strlen( msg );
    strcpy((char*)pkt->msg.data.value, msg);
    queue_put( msgQ );
}

static void insert_connect_request_message(const uint8_t * initiator, const uint8_t * advertiser, uint32_t aa, uint32_t interval_us, uint32_t timeout_us, uint16_t latency) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_CONNECT_REQUEST;
    pkt->msg.timestamp = timer_get_timestamp();
    memcpy(pkt->msg.data.connect_request.initiator,  initiator,  6);
    memcpy(pkt->msg.data.connect_request.advertiser, advertiser, 6);
    pkt->msg.data.connect_request.aa = aa;
    pkt->msg.data.connect_request.interval_us = interval_us;
    pkt->msg.data.connect_request.timeout_us  = timeout_us;
    pkt->msg.data.connect_request.latency     = latency;
    pkt->length = 4 + 26;
    queue_put( msgQ );
}

static void insert_connection_event_message(uint16_t count) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_CONNECTION_EVENT;
    pkt->msg.timestamp = timer_get_timestamp();
    pkt->msg.data.connection_event.count = count;
    pkt->length = 4 + 2;
    queue_put( msgQ );
}

static void insert_terminate_message(uint8_t reason) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_TERMINATE;
    pkt->msg.timestamp = timer_get_timestamp();
    pkt->msg.data.terminate.reason = reason;
    pkt->length = 4 + 1;
    queue_put( msgQ );
}

static void insert_channel_map_update_message(const uint8_t * map) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_CHAN_MAP_UPDATE;
    pkt->msg.timestamp = timer_get_timestamp();
    memcpy(&pkt->msg.data.chan_map_update, map, 5);
    pkt->length = 4 + 5;
    queue_put( msgQ );
}

static void insert_conn_param_update_message(uint32_t conn_interval, uint32_t timeout_us, uint16_t latency) {
    if( queue_full( msgQ ) ) {
        return;
    }

    packet_t *pkt = (packet_t *)queue_alloc( msgQ );
    pkt->tag = TAG_MSG_CONN_PARAM_UPDATE;
    pkt->msg.timestamp = timer_get_timestamp();
    pkt->msg.data.conn_param_update.interval_us = conn_interval;
    pkt->msg.data.conn_param_update.timeout_us  = timeout_us;
    pkt->length = 4 + 10;
    queue_put( msgQ );
}

static void sync_hop_channel() {

    if (ctx.mode == IDLE) {
        return;
    }

#ifdef GPIO_DURING_TIMER
    nrf_gpio_pin_write(GPIO_DURING_TIMER, 1);
#endif

    ctx.connection_event++;
    ctx.time_without_any_packets_us += ctx.interval_us;
    ctx.acnhor_us += ctx.interval_us;
    ctx.packet_nr_in_connection_event = 0;

    if (ctx.time_without_any_packets_us > ctx.timeout_us) {
        printf("Timeout\n");
        insert_terminate_message(1);
        abort_following();
        return;
    }

    if (ctx.channel_map_update_pending && (ctx.channel_map_update_instant == ctx.connection_event)) {
        insert_channel_map_update_message( (const uint8_t *) &ctx.channel_map_update_map);
        hopping_set_channel_map( &h, (const uint8_t *) &ctx.channel_map_update_map );
        ctx.channel_map_update_pending = 0;
    }

    if ( ctx.conn_param_update_pending && ((ctx.conn_param_update_instant) == ctx.connection_event) ) {
        insert_conn_param_update_message(ctx.conn_param_update_interval_us, ctx.conn_param_update_timeout_us, ctx.conn_param_update_latency);
        ctx.interval_us = ctx.conn_param_update_interval_us;
        ctx.timeout_us  = ctx.conn_param_update_timeout_us;
        ctx.latency     = ctx.conn_param_update_latency;
        ctx.conn_param_update_pending = 0;

        timer_stop( hop );
        ctx.synced = false;
    }

    insert_connection_event_message(ctx.connection_event);

    switch (ctx.channel_selection_algorithm){
        case 0:
            ctx.channel = hopping_csa1_get_next_channel( &h );
            break;
        case 1:
            ctx.channel = hopping_csa2_get_channel_for_counter( &h,  ctx.connection_event);
            break;
        default:
            break;
    }

    radio_set_channel_fast( ctx.channel );

#ifdef GPIO_DURING_TIMER
    nrf_gpio_pin_write(GPIO_DURING_TIMER, 0);
#endif
}

void RADIO_IRQHandler(void) {

#ifdef GPIO_DURING_RADIO
    nrf_gpio_pin_write(GPIO_DURING_RADIO, 1);
#endif

    // IRQ only triggered on EVENTS_END so far
    NRF_RADIO->EVENTS_END = 0;

    uint8_t *curBuf = (uint8_t*)NRF_RADIO->PACKETPTR;
    packet_t *p   = (void*)(curBuf - PDU_META_OFFSET);

    /* get meta data from radio */

    // check CRC
    bool crcOk = (NRF_RADIO->CRCSTATUS & RADIO_CRCSTATUS_CRCSTATUS_Msk) ==
                 (RADIO_CRCSTATUS_CRCSTATUS_CRCOk << RADIO_CRCSTATUS_CRCSTATUS_Pos);

    // 1 mbps header: 1 byte preamble + 4 byte AA + 1 byte header + 1 byte len + len bytes
    // PPI: TIMER0->TASKS_CAPTURE[3] - Trigger Timer 0 Capture 3 on AA reception
    uint32_t packet_start_us = NRF_TIMER0->CC[3] - (5 * 8);

    // RSSI
    uint8_t  rssi_negative = NRF_RADIO->RSSISAMPLE;


    // actions
    int queue_packet = 1;
    int ignore_adv   = 0;

    // ignore advertisements and connection requests with low rssi
    if (ctx.mode == FOLLOW_CONNECT && rssi_negative > ctx.rssi_min_negative){
        queue_packet = 0;
        ignore_adv   = 1;
    }

    // check if packet can be queued
    if (queue_packet && queue_full( rxQ )) {
        queue_packet = 0;
    } else {
        // note: the current packet is already in buffer and could theoretically be send to the host (containing invalid meta data)
        // however, if we got here, the rx buffer is full and the main loop needs to transfer RX_BUF_CNT-1 packets first
        ctx.buffer_overrun = 1;
    }

    if (queue_packet) {

        /**
         *  switches to a new buffer immediately, only allowed if consumer has lower priority then producer.
         *  Otherwise this leads to partial updated queue data. Normal behavior, queue_alloc to get a block of memory to work with
         *  and queue_put to signal the consumer that a new message is ready.
         */
        queue_put( rxQ );
        NRF_RADIO->PACKETPTR = (uint32_t)(queue_alloc( rxQ )+PDU_META_OFFSET);

        // store meta data
        p->tag = TAG_DATA;
        p->payload.channel       = ctx.channel;
        p->payload.timestamp     = packet_start_us;
        p->payload.rssi_negative = rssi_negative;
        p->payload.aa            = ctx.aa;
        p->payload.flags         = 0;
        // length for adv or data pdu
        p->length = 12 + 2 + p->payload.pdu.adv.len + CRC_LEN;

        // append crc - rbit flips a 32-bit word using a single arm instruction
        uint32_t crc_received = __RBIT( NRF_RADIO->RXCRC );
        uint8_t * crc_storage = &p->payload.pdu.adv.payload[p->payload.pdu.adv.len];
        *crc_storage++ = (crc_received >>  8) & 0xff;
        *crc_storage++ = (crc_received >> 16) & 0xff;
        *crc_storage++ = (crc_received >> 24) & 0xff;

        // set crc ok flag
        if (crcOk) {
            p->payload.flags |= (1 << 2);
        }

        // indicate packet loss and reset overrun flag
        if (ctx.buffer_overrun) {
            ctx.buffer_overrun = 0;
            p->payload.flags |= (1 << 3);
        }

    }

    // Restart receiver
    NRF_RADIO->TASKS_START = 1;

    // reset 'supervision timeout'
    ctx.time_without_any_packets_us = 0;

    bool update_timer = false;

    switch( ctx.mode ) {
        case FOLLOW_CONNECT:
            // don't process control packets if CRC invalid or RSSI filter
            if( !crcOk || ignore_adv) {
                break;
            }
            
            if( p->payload.pdu.adv.type == PDU_ADV_TYPE_CONNECT_IND ) {
                struct pdu_adv *adv = &p->payload.pdu.adv;
                uint8_t *init_addr  = adv->connect_ind.init_addr;
                uint8_t *adv_addr   = adv->connect_ind.adv_addr;

                // check filter - continue if one of the conditions are false (i.e. filter not active or address matches)
                if (ctx.connection_filter_active &&
                        memcmp(init_addr, ctx.connection_filter_address, 6) &&
                        memcmp(adv_addr, ctx.connection_filter_address, 6) ) {
                    break;
                }

                ctx.interval_us = READ_LE_16(&adv->connect_ind.interval) * 1250;
                ctx.timeout_us  = READ_LE_16(&adv->connect_ind.timeout)  * 10000;
                ctx.latency     = READ_LE_16(&adv->connect_ind.latency);
                ctx.connection_event = 0;
                uint32_t crcInit = READ_LE_24(&adv->connect_ind.crc_init);
                ctx.aa = READ_LE_32(&adv->connect_ind.access_addr);

                // init hopping
                hopping_init( &h );
                hopping_set_channel_map( &h, adv->connect_ind.chan_map );
                ctx.channel_selection_algorithm = ctx.advertisement_cache_csa2_supported & adv->chan_sel;
                switch (ctx.channel_selection_algorithm){
                    case 0:
                        hopping_csa1_set_hop_increment(  &h, adv->connect_ind.hop );
                        ctx.channel = hopping_csa1_get_next_channel( &h );
                        break;
                    case 1:
                        hopping_csa2_set_access_address( &h, ctx.aa);
                        ctx.channel = hopping_csa2_get_channel_for_counter( &h,  ctx.connection_event);
                        break;
                    default:
                        break;
                }
                radio_follow_conn( ctx.aa, ctx.channel, crcInit );
                ctx.mode = SYNC_CONNECTION;
                printf("Follow connection: hop %u, timeout %u us, interval %u, csa #%u\n", adv->connect_ind.hop, ctx.timeout_us, ctx.interval_us, ctx.channel_selection_algorithm + 1);
                insert_connect_request_message(init_addr, adv_addr, ctx.aa, ctx.interval_us, ctx.timeout_us, ctx.latency);
            } else {
                // cache advertising address and header
                struct pdu_adv *adv = &p->payload.pdu.adv;
                memcpy(ctx.advertisement_cache_address, adv->adv_ind.addr, 6);
                ctx.advertisement_cache_csa2_supported = adv->chan_sel;
                // printf("Adv: %02x - ", ctx.advertisement_cache_csa2_supported);
                // printf_hexdump( ctx.advertisement_cache_address, 6 );
            }
            break;

        case SYNC_CONNECTION:

            // compare packet start against existing anchor for first packet in connection event
            if ((ctx.packet_nr_in_connection_event == 0) && ctx.synced) {
                int32_t delta = (int32_t) (ctx.acnhor_us - packet_start_us);
                if ( delta < 0) {
                    delta = -delta;
                }
                if (delta < 100) {
                    update_timer = true;
                } else {
                    insert_log_message("Packet out of sync");
                    // we don't know if we missed the master or if the master is just way to loate
                    ctx.direction = DIRECTION_DONT_KNOW;
                }
            }

            // set new anchor
            if (!ctx.synced || update_timer) {
                ctx.acnhor_us = packet_start_us;
                timer_stop( hop );
                int ret = timer_start_absolut( hop, ctx.acnhor_us - SYNC_HOP_DELAY_US, ctx.interval_us, sync_hop_channel );
                assert( ret == 0 );
                ctx.synced = true;
                // master to slave packet
                ctx.direction = DIRECTION_MASTER;
            }

            // validate time
            if (ctx.packet_nr_in_connection_event && ctx.synced) {
                int32_t delta = (int32_t) (ctx.next_expected_packet_us - packet_start_us);
                if ( delta < 0) {
                    delta = -delta;
                }
                if (delta > 100) {
                    // we've missed at least one packet and lost the ability to track direction
                    insert_log_message("Missed packet");
                    ctx.direction = DIRECTION_DONT_KNOW;
                }
            }

            // count
            ctx.packet_nr_in_connection_event++;

            // store direction in packet
            if (queue_packet) {
                p->payload.flags |= ctx.direction;
            }

            // flip direction
            if (ctx.direction != DIRECTION_DONT_KNOW) {
                if (ctx.direction == DIRECTION_MASTER) {
                    ctx.direction = DIRECTION_SLAVE;
                } else {
                    ctx.direction = DIRECTION_MASTER;
                }
            }

            // calculate ETA for next packet (1 Preambel, 4 AA, 2 Header, Payload, 3 CRC) + t_ifs
            ctx.next_expected_packet_us = packet_start_us + ((10 + p->payload.pdu.adv.len) << 3) + 150;

            // don't process control packets if CRC invalid
            if( !crcOk ) {
                break;
            }

            if( p->payload.pdu.data.ll_id == PDU_DATA_LLID_CTRL ) {
                struct pdu_data *data = &p->payload.pdu.data;
                switch (data->llctrl.opcode) {
                    case PDU_DATA_LLCTRL_TYPE_CONN_UPDATE_IND:
                        ctx.conn_param_update_win_size    = data->llctrl.conn_update_ind.win_size;
                        ctx.conn_param_update_win_offset  = READ_LE_16(&data->llctrl.conn_update_ind.win_offset);
                        ctx.conn_param_update_interval_us = READ_LE_16(&data->llctrl.conn_update_ind.interval) * 1250;
                        ctx.conn_param_update_latency     = READ_LE_16(&data->llctrl.conn_update_ind.latency);
                        ctx.conn_param_update_timeout_us  = READ_LE_16(&data->llctrl.conn_update_ind.timeout) * 10000;
                        ctx.conn_param_update_instant     = READ_LE_16(&data->llctrl.conn_update_ind.instant);
                        ctx.conn_param_update_pending     = true;
                        break;
                    case PDU_DATA_LLCTRL_TYPE_CHAN_MAP_IND:
                        memcpy((uint8_t *) ctx.channel_map_update_map, &data->llctrl.chan_map_ind.chm, 5);
                        ctx.channel_map_update_instant   = READ_LE_16(&data->llctrl.chan_map_ind.instant);
                        ctx.channel_map_update_pending   = true;
                        break;
                    case PDU_DATA_LLCTRL_TYPE_TERMINATE_IND:
                        abort_following();
                        insert_terminate_message(0);
                        printf("Terminate\n");
                        break;
                    case PDU_DATA_LLCTRL_TYPE_PHY_UPD_IND:
                        // TODO: parse
                        break;
                    default:
                        break;
                }
            }
            break;

        default:
            break;
    }

#ifdef GPIO_DURING_RADIO
    nrf_gpio_pin_write(GPIO_DURING_RADIO, 0);
#endif
}

void test_uart(void) {
    const char * msg = "abcdefghijklmnopqrstuvwxyz";
    uint8_t buffer[50];
    packet_t *packet = (packet_t*) buffer;
    packet->tag = TAG_MSG_LOG;
    packet->msg.timestamp = timer_get_timestamp();
    packet->length = 4 + strlen( msg );
    strcpy((char*)packet->msg.data.value, msg);
    while (1) {
#ifdef DEBUG
        static uint32_t i=0;
        printf("0x%08x\n", i++);
#endif
        nrfx_uart_tx( &uart_inst, (uint8_t*)packet, packet->length + 3);
    }
}


void __assert_fail (const char *__assertion, const char *__file,
                    unsigned int __line, const char *__function) {
    printf("%s:%d:%s: Assertion %s failed.\n", __file, __line, __function, __assertion );
    for(;;);
}


#ifdef BOARD_PCA10059

void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    uint32_t err = ((error_info_t*)info)->err_code;

    LEDS_ON(BSP_LED_1_MASK);
    nrf_delay_ms(1000);
    LEDS_OFF(LEDS_MASK);
    nrf_delay_ms(1000);

    while (err)
    {
        for (int i=0; i<=err%10; i++)
        {
            LEDS_OFF(LEDS_MASK);
            nrf_delay_ms(100);
            LEDS_ON(BSP_LED_0_MASK);
            nrf_delay_ms(100);
        }
        nrf_delay_ms(500);
        err /= 10;
    }

    //while (1)
    {
        LEDS_OFF(LEDS_MASK);
        nrf_delay_ms(1000);
        LEDS_ON(BSP_LED_1_MASK);
        nrf_delay_ms(1000);
    }
}


/**
 * @brief Set new buffer and process any data if already present
 *
 * This is internal function.
 * The result of its execution is the library waiting for the event of the new data.
 * If there is already any data that was returned from the CDC internal buffer
 * it would be processed here.
 */
static void cdc_acm_process_and_prepare_buffer(app_usbd_cdc_acm_t const * p_cdc_acm)
{
    for (;;)
    {
        ret_code_t ret = app_usbd_cdc_acm_read_any(p_cdc_acm,
                                                   m_rx_buffer,
                                                   sizeof(m_rx_buffer));
        if (ret == NRF_SUCCESS)
        {
            size_t size = app_usbd_cdc_acm_rx_size(p_cdc_acm);
            size_t qsize = nrf_queue_in(&m_rx_queue, m_rx_buffer, size);
            ASSERT(size == qsize);
            UNUSED_VARIABLE(qsize);
        }
        else if (ret == NRF_ERROR_IO_PENDING)
        {
            break;
        }
        else
        {
            APP_ERROR_CHECK(ret);
            break;
        }
    }
}

/**
 * @brief User event handler @ref app_usbd_cdc_acm_user_ev_handler_t (headphones)
 * */
static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const * p_inst,
                                    app_usbd_cdc_acm_user_event_t event)
{
    app_usbd_cdc_acm_t const * p_cdc_acm = app_usbd_cdc_acm_class_get(p_inst);
    
    switch (event)
    {
        case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
        {
            LEDS_ON(LED_CDC_ACM_OPEN);

            /*Setup first transfer*/
            cdc_acm_process_and_prepare_buffer(p_cdc_acm);

            break;
        }
        case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
            LEDS_OFF(LED_CDC_ACM_OPEN);
            break;
        case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
            LEDS_INVERT(LED_CDC_ACM_TX);
            break;
        case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
        {
            LEDS_INVERT(LED_CDC_ACM_TX);

            /*Get amount of data transfered*/
            size_t size = app_usbd_cdc_acm_rx_size(p_cdc_acm);
            size_t qsize = nrf_queue_in(&m_rx_queue, m_rx_buffer, size);
            ASSERT(size == qsize);
            UNUSED_VARIABLE(qsize);

            /*Setup next transfer*/
            cdc_acm_process_and_prepare_buffer(p_cdc_acm);
            break;
        }
        default:
            break;
    }
}

static void usbd_user_ev_handler(app_usbd_event_type_t event)
{
    switch (event)
    {
        case APP_USBD_EVT_DRV_SUSPEND:
            LEDS_OFF(LED_USB_RESUME);
            break;
        case APP_USBD_EVT_DRV_RESUME:
            LEDS_ON(LED_USB_RESUME);
            break;
        case APP_USBD_EVT_STARTED:
            break;
        case APP_USBD_EVT_STOPPED:
            app_usbd_disable();
            LEDS_OFF(LEDS_MASK);
            break;
        case APP_USBD_EVT_POWER_DETECTED:

            if (!nrf_drv_usbd_is_enabled())
            {
                app_usbd_enable();
            }
            break;
            app_usbd_stop();
            break;
        case APP_USBD_EVT_POWER_READY:
            app_usbd_start();
            break;
        default:
            break;
    }
}

int transport_ready (void)
{
    while(app_usbd_event_queue_process());
    
    return !nrf_queue_is_empty(&m_rx_queue);
}

nrfx_err_t transport_read(void* pbuf, size_t len)
{
    size_t read = 0;

    do
    {
        while(app_usbd_event_queue_process());
        read += nrf_queue_out(&m_rx_queue, pbuf+read, len);
    } while (read < len);

    return NRFX_SUCCESS;
}

nrfx_err_t transport_write(void* pbuf, size_t len)
{
    while (app_usbd_event_queue_process());
    // this is an uggly fix for random cdc failure
    while (app_usbd_cdc_acm_write(&m_app_cdc_acm, pbuf, len) != NRF_SUCCESS);

    return NRF_SUCCESS;
}
#endif

int main(void) {
    
    LEDS_CONFIGURE(LEDS_MASK);
    LEDS_OFF(LEDS_MASK);
    //LEDS_ON(LEDS_MASK);

    // gpio debugging
#ifdef GPIO_DURING_RADIO
    nrf_gpio_cfg_output(GPIO_DURING_RADIO);
#endif
#ifdef GPIO_DURING_TIMER
    nrf_gpio_cfg_output(GPIO_DURING_TIMER);
#endif

    timer_init();

    hop = timer_create( TIMER_REPEATED );

#ifdef TX_PIN_NUMBER
    nrfx_uart_config_t config = {
        TX_PIN_NUMBER,
        RX_PIN_NUMBER,
        CTS_PIN_NUMBER,
        RTS_PIN_NUMBER,
        NULL,
        SNIFFER_UART_FLOWCONTROL,
        NRF_UART_PARITY_EXCLUDED,
        SNIFFER_UART_BAUDRATE,
        6,
    };

    nrfx_err_t err_code;
    err_code = nrfx_uart_init(&uart_inst, &config, NULL);
    assert( err_code == NRFX_SUCCESS );

    // Turn on receiver
    nrfx_uart_rx_enable(&uart_inst);
#endif

#ifdef BOARD_PCA10059
    ret_code_t ret;
    static const app_usbd_config_t usbd_config = {
        .ev_state_proc = usbd_user_ev_handler
    };

    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);
    
    nrf_drv_clock_lfclk_request(NULL);

    while(!nrf_drv_clock_lfclk_is_running())
    {
        /* Just waiting */
    }

    app_usbd_serial_num_generate();

    ret = app_usbd_init(&usbd_config);
    APP_ERROR_CHECK(ret);

    app_usbd_class_inst_t const * class_cdc_acm = app_usbd_cdc_acm_class_inst_get(&m_app_cdc_acm);
    ret = app_usbd_class_append(class_cdc_acm);
    APP_ERROR_CHECK(ret);

    if (USBD_POWER_DETECTION)
    {
        ret = app_usbd_power_events_enable();
        APP_ERROR_CHECK(ret);
    }
    else
    {
        app_usbd_enable();
        app_usbd_start();
    }

#endif

    printf("BLE sniffer up and running!\n");

    // start listening
    radio_init();

    // configure PPI: RADIO->EVENTS_ADDRESS => TIMER0->TASKS_CAPTURE[3]
    NRF_PPI->CH[0].EEP = (uint32_t)&NRF_RADIO->EVENTS_ADDRESS;
    NRF_PPI->CH[0].TEP = (uint32_t)&NRF_TIMER0->TASKS_CAPTURE[3];
    NRF_PPI->CHENSET = PPI_CHENSET_CH0_Set << UINT32_C(0);

    queue_init( rxQ );
    queue_init( msgQ );
    NRF_RADIO->PACKETPTR = (uint32_t)(queue_alloc( rxQ ) + PDU_META_OFFSET);

    radio_filter_disable();

    // uncomment next line to test uart throughput
    // test_uart();

#ifdef AUTO_START
    // start sniffing on channel 37 without host control
    ctx.channel = 37;
    ctx.aa = 0x8E89BED6;
    uint32_t crc_init = 0x555555;
    ctx.connection_filter_active = false;
    ctx.mode = FOLLOW_CONNECT;
    radio_follow_conn( ctx.aa, ctx.channel, crc_init );
#endif

#ifdef USE_RTT_OUTPUT
    uint32_t curTimeStamp = 0;
#endif

    while (1) {
#ifdef BOARD_PCA10059
        packet_t cmd = { 0 };
        if( transport_ready() ) {
            ret = transport_read( &cmd.tag, 3 );
            if( NRFX_SUCCESS != ret ) {
                printf("Read Header error: %x\n", ret);
                continue;
            }

            if( cmd.length > 0 ) {
                APP_ERROR_CHECK(cmd.length);
                ret = transport_read((uint8_t*)cmd.value, cmd.length );
                if(NRFX_SUCCESS != ret ) {
                    printf("Read Payload error: %x\n", ret);
                    continue;
                }
            }

            // printf("TAG: %02x, len %u\n", cmd.tag, cmd.length);

            switch( cmd.tag ) {
                case TAG_CMD_RESET:
                    // stop sniffing
                    abort_following();

                    // reset time
                    NRF_TIMER0->TASKS_CLEAR = UINT32_C(1);

                    // reset queues
                    queue_init( rxQ );
                    queue_init( msgQ );
                    printf("TAG_CMD_RESET\n");
                    break;
                case TAG_CMD_GET_VERSION: {
                    uint8_t t = TAG_CMD_GET_VERSION;
                    ret = transport_write(&t, sizeof(t) );
                    assert( ret == NRFX_SUCCESS );

                    const char *v = VERSION;
                    uint16_t l = strlen(v);
                    ret = transport_write((uint8_t*)&l, sizeof(l) );
                    assert( ret == NRFX_SUCCESS );
                    ret = transport_write((uint8_t*)v, l );
                    assert( ret == NRFX_SUCCESS );
                    printf("TAG_CMD_GET_VERSION\n");
                    break;
                }
                case TAG_CMD_SNIFF_CHANNEL: {
                    uint8_t empty_mac[6] = { 0 };
                    ctx.channel = cmd.msg.data.cmd_sniff_channel.channel;
                    ctx.rssi_min_negative = cmd.msg.data.cmd_sniff_channel.rssi_min_negative;
                    ctx.aa = cmd.msg.data.cmd_sniff_channel.aa;
                    uint32_t crc_init = cmd.msg.data.cmd_sniff_channel.crc_init;
                    memcpy( ctx.connection_filter_address, cmd.msg.data.cmd_sniff_channel.mac, 6 );
                    ctx.connection_filter_active = false;
                    if( memcmp( empty_mac, ctx.connection_filter_address, 6 ) ) {
                        ctx.connection_filter_active = true;
                    }
                    ctx.mode = FOLLOW_CONNECT;
                    NRF_RADIO->PACKETPTR = (uint32_t)(queue_alloc( rxQ ) + PDU_META_OFFSET);
                    radio_follow_conn( ctx.aa, ctx.channel, crc_init );
                    printf("TAG_CMD_SNIFF_CHANNEL #%u, filter: ", ctx.channel);
                    printf_hexdump( ctx.connection_filter_address, 6 );
                    break;
                }
                default:
                    break;
            }
        }


#endif

#ifdef TX_PIN_NUMBER
        packet_t cmd = { 0 };
        if( nrfx_uart_rx_ready( &uart_inst ) ) {
            err_code = nrfx_uart_rx( &uart_inst, &cmd.tag, 3 );
            if( NRFX_SUCCESS != err_code ) {
                printf("Read Header error: %x\n", err_code);
                continue;
            }

            if( cmd.length > 0 ) {
                err_code = nrfx_uart_rx( &uart_inst, (uint8_t*)cmd.value, cmd.length );
                if(NRFX_SUCCESS != err_code ) {
                    printf("Read Payload error: %x\n", err_code);
                    continue;
                }
            }

            // printf("TAG: %02x, len %u\n", cmd.tag, cmd.length);

            switch( cmd.tag ) {
                case TAG_CMD_RESET:
                    // stop sniffing
                    abort_following();

                    // reset time
                    NRF_TIMER0->TASKS_CLEAR = UINT32_C(1);

                    // reset queues
                    queue_init( rxQ );
                    queue_init( msgQ );
                    printf("TAG_CMD_RESET\n");
                    break;
                case TAG_CMD_GET_VERSION: {
                    uint8_t t = TAG_CMD_GET_VERSION;
                    err_code = nrfx_uart_tx( &uart_inst, &t, sizeof(t) );
                    assert( err_code == NRFX_SUCCESS );

                    const char *v = VERSION;
                    uint16_t l = strlen(v);
                    err_code = nrfx_uart_tx( &uart_inst, (uint8_t*)&l, sizeof(l) );
                    assert( err_code == NRFX_SUCCESS );
                    err_code = nrfx_uart_tx( &uart_inst, (uint8_t*)v, l );
                    assert( err_code == NRFX_SUCCESS );
                    printf("TAG_CMD_GET_VERSION\n");
                    break;
                }
                case TAG_CMD_SNIFF_CHANNEL: {
                    uint8_t empty_mac[6] = { 0 };
                    ctx.channel = cmd.msg.data.cmd_sniff_channel.channel;
                    ctx.rssi_min_negative = cmd.msg.data.cmd_sniff_channel.rssi_min_negative;
                    ctx.aa = cmd.msg.data.cmd_sniff_channel.aa;
                    uint32_t crc_init = cmd.msg.data.cmd_sniff_channel.crc_init;
                    memcpy( ctx.connection_filter_address, cmd.msg.data.cmd_sniff_channel.mac, 6 );
                    ctx.connection_filter_active = false;
                    if( memcmp( empty_mac, ctx.connection_filter_address, 6 ) ) {
                        ctx.connection_filter_active = true;
                    }
                    ctx.mode = FOLLOW_CONNECT;
                    NRF_RADIO->PACKETPTR = (uint32_t)(queue_alloc( rxQ ) + PDU_META_OFFSET);
                    radio_follow_conn( ctx.aa, ctx.channel, crc_init );
                    printf("TAG_CMD_SNIFF_CHANNEL #%u, filter: ", ctx.channel);
                    printf_hexdump( ctx.connection_filter_address, 6 );
                    break;
                }
                default:
                    break;
            }
        }
#endif

        // decide what to send first: packet or message
        uint32_t rxBufEntries = queue_getSize( rxQ );
        uint32_t msgBufEntries = queue_getSize( msgQ );
        packet_t *packet  = NULL;

        uint32_t rxTimestamp  = 0;
        uint32_t msgTimestamp = 0;

        msgQueue_t *queue = NULL;
        if( rxBufEntries > 0 ) {
            queue = rxQ;
            packet = (void *)queue_peek( rxQ );
            rxTimestamp = packet->payload.timestamp;
        }

        if( msgBufEntries > 0 ) {
            packet_t *message = (void*)queue_peek( msgQ );
            msgTimestamp = message->msg.timestamp;

            if( ( queue == NULL ) || (((int32_t)(rxTimestamp - msgTimestamp)) > 0) ) {
                queue = msgQ;
                packet = message;
            }
        }


        if( queue != NULL ) {
#ifdef USE_RTT_OUTPUT
            uint32_t delta = rxTimestamp - curTimeStamp;
            curTimeStamp = rxTimestamp;

            switch( packet->tag ) {
                case TAG_DATA: {
                    uint8_t *data = packet->payload.pdu.value;
                    struct pdu_adv *adv = &packet->payload.pdu.adv;
                    printf("%3u %6u %6d %2d dir %u (%4d dBm) ", rxBufEntries, rxTimestamp, delta, packet->payload.channel & 0x3f, packet->payload.channel  >> 6, -packet->payload.rssi );
                    printf_hexdump( data, adv->len + 2 );
                    break;
                }
                case TAG_MSG_LOG: {
                    const char * msg = (const char *) packet->msg.data.value;
                    LOG_DBG("%3u %6u %6d - %s\n", msgBufEntries, msgTimestamp, delta, msg);
                    break;
                }
                default:
                    break;
            }

#else

#ifdef TX_PIN_NUMBER
            // printf("%06u ", packet->payload.timestamp); printf_hexdump((uint8_t*)packet, packet->length + 3 );
            nrfx_uart_tx( &uart_inst, (uint8_t*)packet, packet->length + 3 );
#endif

#ifdef BOARD_PCA10059
            transport_write((void*)packet, packet->length + 3);
#endif

#endif
            queue_get( queue );
        }
    }
}


/** @} */
