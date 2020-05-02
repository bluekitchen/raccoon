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

#include "transport.h"

#include "nrf.h"
#include "boards.h"

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


#define LED_USB_RESUME      (BSP_LED_0_MASK)
#define LED_CDC_ACM_OPEN    (BSP_LED_1_MASK)
#define LED_CDC_ACM_RX      (BSP_LED_2_MASK)
#define LED_CDC_ACM_TX      (BSP_LED_3_MASK)
#define LED_ERROR           (BSP_LED_1_MASK)

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

static bool cdc_port_open = false;

void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    while(1)
    {
        LEDS_OFF(LEDS_MASK);
        nrf_delay_ms(500);
        LEDS_ON(LED_ERROR);
        nrf_delay_ms(500);
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

            cdc_port_open = true;

            /*Setup first transfer*/
            cdc_acm_process_and_prepare_buffer(p_cdc_acm);

            break;
        }
        case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
            LEDS_OFF(LED_CDC_ACM_OPEN);
            LEDS_OFF(LED_CDC_ACM_TX);
            LEDS_OFF(LED_CDC_ACM_RX);

            cdc_port_open = false;

            /*Free queue */
            nrf_queue_reset(&m_rx_queue);
            break;
        case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
            LEDS_INVERT(LED_CDC_ACM_TX);
            break;
        case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
        {
            LEDS_INVERT(LED_CDC_ACM_RX);

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


nrfx_err_t transport_init(void)
{
    ret_code_t ret;
    static const app_usbd_config_t usbd_config = {
        .ev_state_proc = usbd_user_ev_handler
    };

    if ((ret = nrf_drv_clock_init()) != NRF_SUCCESS)
        return ret;
    
    nrf_drv_clock_lfclk_request(NULL);

    while(!nrf_drv_clock_lfclk_is_running());

    app_usbd_serial_num_generate();

    if ((ret = app_usbd_init(&usbd_config)) != NRF_SUCCESS)
        return ret;

    app_usbd_class_inst_t const * class_cdc_acm = app_usbd_cdc_acm_class_inst_get(&m_app_cdc_acm);
    if ((ret = app_usbd_class_append(class_cdc_acm)) != NRF_SUCCESS)
        return ret;

    if (USBD_POWER_DETECTION)
    {
        if ((ret = app_usbd_power_events_enable()) != NRF_SUCCESS)
            return ret;
    }
    else
    {
        app_usbd_enable();
        app_usbd_start();
    }

    LEDS_OFF(LEDS_MASK);

    return ret;
}


bool transport_isready (void)
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
    while ((app_usbd_cdc_acm_write(&m_app_cdc_acm, pbuf, len) != NRF_SUCCESS) && cdc_port_open);

    return NRF_SUCCESS;
};
