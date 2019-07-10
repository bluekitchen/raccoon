#include "transport.h"

#include "nrf.h"
#include "nrfx_uart.h"

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