#ifndef BTFRIEND32_H
#define BTFRIEND32_H

#ifdef __cplusplus
extern "C" {
#endif

#define LEDS_NUMBER    2

#define LED_1          18
#define LED_2          19

#define LEDS_LIST { LED_1, LED_2 }

#define LEDS_ACTIVE_STATE 1

#define BSP_LED_0      LED_1
#define BSP_LED_1      LED_2

#define LEDS_INV_MASK  LEDS_MASK

#define BUTTONS_NUMBER 2

#define SW_1           1
#define SW_2           7
#define BUTTON_PULL    NRF_GPIO_PIN_PULLUP

#define BUTTONS_LIST { SW_1, SW_2 }

#define BUTTONS_ACTIVE_STATE 0

#define BSP_BUTTON_0   SW_1
#define BSP_BUTTON_1   SW_2

#define RX_PIN_NUMBER  11
#define TX_PIN_NUMBER   9
#define CTS_PIN_NUMBER 10
#define RTS_PIN_NUMBER  8
#define HWFC           false

#define SER_CON_RX_PIN              11
#define SER_CON_TX_PIN               9
#define SER_CON_CTS_PIN             10
#define SER_CON_RTS_PIN              8


#ifdef __cplusplus
}
#endif

#endif
