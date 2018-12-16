CFLAGS += -std=c99 -Wall -Werror
CFLAGS += -MMD -I../nrf -I..
VPATH = ..

all: test_hopping test_queue

test_hopping: hopping.o

test_queue: queue.o

-include *.d

.PHONY: clean
clean:
	rm -rf test_hopping test_queue *.o *.d

