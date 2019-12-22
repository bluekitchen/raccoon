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

#include <assert.h>

#include "nrf.h"
#include "boards.h"
#include "nrfx_uart.h"

#include "sniffer_config.h"

// from SDK UART example
#define UART_TX_BUF_SIZE 128                         /**< UART TX buffer size. */
#define UART_RX_BUF_SIZE 1                           /**< UART RX buffer size. */

#ifdef TX_PIN_NUMBER
static nrfx_uart_t uart_inst = NRFX_UART_INSTANCE(0);
#endif

nrfx_err_t transport_init(void)
{
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
    return NRF_SUCCESS;
}


bool transport_isready (void)
{
#ifdef TX_PIN_NUMBER
    return nrfx_uart_rx_ready( &uart_inst );
#else
    return false;
#endif
}


nrfx_err_t transport_read(void* pbuf, size_t len)
{
#ifdef TX_PIN_NUMBER
    return nrfx_uart_rx( &uart_inst, pbuf,len );
#else
    return NRF_ERROR_NOT_SUPPORTED;
#endif
}


nrfx_err_t transport_write(void* pbuf, size_t len)
{
#ifdef TX_PIN_NUMBER
    return nrfx_uart_tx( &uart_inst, pbuf,len );
#else
    return NRF_ERROR_NOT_SUPPORTED;
#endif
};
