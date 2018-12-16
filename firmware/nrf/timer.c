/**
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2013 Paulo B. de Oliveira Filho <pauloborgesfilho@gmail.com>
 *  Copyright (c) 2013 Claudio Takahasi <claudio.takahasi@gmail.com>
 *  Copyright (c) 2013 João Paulo Rechi Vita <jprvita@gmail.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "nrf.h"
#include "timer.h"
#include "debug.h"

#define TIMER               NRF_TIMER0
#define IRQ_HANDLER         TIMER0_IRQHandler

#define TIMER_PRESCALER	    4		/* 1 MHz */
#define MAX_TIMERS          3

#define BIT(n)				(1 << n)

struct timer {
    volatile uint32_t ticks;
    volatile timer_cb_t cb;
    volatile uint8_t enabled:1;
    volatile uint8_t active:1;
    volatile uint8_t type:1;
};

static struct timer timers[MAX_TIMERS];

static __inline void get_clr_set_masks(uint8_t id, uint32_t *clr, uint32_t *set) {
    *clr = TIMER_INTENCLR_COMPARE0_Msk << id;
    *set = TIMER_INTENSET_COMPARE0_Msk << id;
}

uint32_t timer_get_timestamp(void) {
    uint32_t ticks;
    uint32_t cc;

    cc = TIMER->CC[MAX_TIMERS-1];
    TIMER->TASKS_CAPTURE[MAX_TIMERS-1] = UINT32_C(1);
    ticks = TIMER->CC[MAX_TIMERS-1];
    TIMER->CC[MAX_TIMERS-1] = cc;

    return ticks;
}

static __inline void update_cc(uint8_t id, uint32_t ticks) {
    uint32_t clr_mask = 0;
    uint32_t set_mask = 0;

    get_clr_set_masks(id, &clr_mask, &set_mask);

    TIMER->CC[id] = ticks;
    TIMER->EVENTS_COMPARE[id] = UINT32_C(0);
    TIMER->INTENSET = set_mask;
}


void IRQ_HANDLER (void) {
    uint8_t id_mask = 0;
    uint8_t id;
    for (id = 0; id < MAX_TIMERS; id++) {
        if (TIMER->EVENTS_COMPARE[id]) {
            TIMER->EVENTS_COMPARE[id] = UINT32_C(0);
            if (timers[id].active) {
                id_mask |= BIT(id);
            }
        }
    }

    for (id = 0; id < MAX_TIMERS; id++) {
        if (id_mask & BIT(id)) {
            if (timers[id].type == TIMER_REPEATED) {
                update_cc(id, TIMER->CC[id] + timers[id].ticks);
            } else if (timers[id].type == TIMER_SINGLESHOT) {
                timers[id].active = 0;
            }
            timers[id].cb();
        }
    }
}


int timer_init(void) {
    if (NRF_CLOCK->EVENTS_HFCLKSTARTED == UINT32_C(0)) {
        NRF_CLOCK->TASKS_HFCLKSTART = UINT32_C(1);
        while (NRF_CLOCK->EVENTS_HFCLKSTARTED == UINT32_C(0));
    }

    TIMER->MODE = TIMER_MODE_MODE_Timer;
    TIMER->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
    TIMER->PRESCALER = TIMER_PRESCALER;

    TIMER->INTENCLR = TIMER_INTENCLR_COMPARE0_Msk
                      | TIMER_INTENCLR_COMPARE1_Msk
                      | TIMER_INTENCLR_COMPARE2_Msk
                      | TIMER_INTENCLR_COMPARE3_Msk;

    NVIC_SetPriority(TIMER0_IRQn, IRQ_PRIORITY_HIGHEST);
    NVIC_EnableIRQ(TIMER0_IRQn);

    memset(timers, 0, sizeof(timers));

    TIMER->TASKS_CLEAR = UINT32_C(1);
    TIMER->TASKS_START = UINT32_C(1);

    return 0;
}

int timer_create(int type) {
    int16_t id;

    if (type != TIMER_SINGLESHOT && type != TIMER_REPEATED) {
        return -EINVAL;
    }

    for (id = 0; id < MAX_TIMERS; id++) {
        if (!timers[id].enabled) {
            goto create;
        }
    }

    return -ENOMEM;

create:
    timers[id].enabled = 1;
    timers[id].active = 0;
    timers[id].type = type;

    return id;
}

int timer_destroy(int id) {
    if (id<0 || id>2) {
        return -EINVAL;
    }

    timers[id].enabled = 0;
    timers[id].active = 0;

    return 0;
}

int timer_start_absolut(int id, uint32_t curr, uint32_t us, timer_cb_t cb) {

    if (id < 0) {
        return -EINVAL;
    }

    if (!timers[id].enabled) {
        return -EINVAL;
    }

    if (timers[id].active) {
        return -EALREADY;
    }

    timers[id].active = 1;
    timers[id].ticks = us;
    timers[id].cb = cb;

    update_cc(id, curr + us);

    return 0;
}

int timer_start(int id, uint32_t us, timer_cb_t cb) {
    uint32_t curr = timer_get_timestamp();
    if (id < 0) {
        return -EINVAL;
    }

    if (!timers[id].enabled) {
        return -EINVAL;
    }

    if (timers[id].active) {
        return -EALREADY;
    }

    timers[id].active = 1;
    timers[id].ticks = us;
    timers[id].cb = cb;

    update_cc(id, curr + us);

    return 0;
}

int timer_stop(int id) {
    uint32_t clr_mask = 0;
    uint32_t set_mask = 0;

    if (id < 0) {
        return -EINVAL;
    }

    if (!timers[id].active) {
        return -EINVAL;
    }

    get_clr_set_masks(id, &clr_mask, &set_mask);
    TIMER->INTENCLR = clr_mask;

    timers[id].active = 0;

    return 0;
}

int32_t timer_get_remaining_us(int id) {
    uint32_t curr = timer_get_timestamp();

    if (!timers[id].active) {
        return 0;
    }

    return (int32_t)(TIMER->CC[id] - curr);
}

