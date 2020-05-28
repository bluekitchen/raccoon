#ifndef MDK_DONGLE_H
#define MDK_DONGLE_H

#ifdef __cplusplus
extern "C" {
#endif

#define LEDS_NUMBER    3

#define LED_1          43
#define LED_2          42
#define LED_3          44

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

#define RX_PIN_NUMBER  27
#define TX_PIN_NUMBER  26
#define CTS_PIN_NUMBER 31
#define RTS_PIN_NUMBER 30
#define HWFC           false


#ifdef __cplusplus
}
#endif

#endif
