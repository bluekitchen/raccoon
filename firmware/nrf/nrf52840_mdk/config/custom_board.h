#ifndef MDK_DONGLE_H
#define MDK_DONGLE_H

#ifdef __cplusplus
extern "C" {
#endif

#define LEDS_NUMBER    3

#define LED_1          22
#define LED_2          23
#define LED_3          24

#define LEDS_LIST { LED_1, LED_2, LED_3 }

#define LEDS_ACTIVE_STATE 0

#define BSP_LED_0      LED_1
#define BSP_LED_1      LED_2
#define BSP_LED_2      LED_3

#define LEDS_INV_MASK  LEDS_MASK

#define BUTTONS_NUMBER 1

#define SW_1           32
#define BUTTON_PULL    NRF_GPIO_PIN_PULLUP

#define BUTTONS_LIST { SW_1 }

#define BUTTONS_ACTIVE_STATE 0

#define BSP_BUTTON_0   SW_1

#define RX_PIN_NUMBER  20
#define TX_PIN_NUMBER  19
#define CTS_PIN_NUMBER 3
#define RTS_PIN_NUMBER 2
#define HWFC           false


#ifdef __cplusplus
}
#endif

#endif
