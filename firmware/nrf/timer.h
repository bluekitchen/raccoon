/**
 * NRF51822 accurate timer library from blessed BLE stack
 * (https://github.com/pauloborges/blessed/)
 *
 **/

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

#include <stdint.h>

#ifndef _TIMER_H_
#define _TIMER_H_

#define IRQ_PRIORITY_HIGHEST    0
#define IRQ_PRIORITY_HIGH       1
#define IRQ_PRIORITY_MEDIUM     2
#define IRQ_PRIORITY_LOW        3

#define TIMER_SINGLESHOT        0
#define TIMER_REPEATED          1

typedef void (*timer_cb_t) (void);

int timer_init(void);
int timer_create(int type);
int timer_destroy(int id);
int timer_start_absolut(int id, uint32_t curr, uint32_t us, timer_cb_t cb);
int timer_start(int id, uint32_t us, timer_cb_t cb);
int timer_stop(int id);
int32_t timer_get_remaining_us(int id);
uint32_t timer_get_timestamp();

#endif // _TIMER_H_
