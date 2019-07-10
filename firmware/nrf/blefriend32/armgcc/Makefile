export GNU_INSTALL_ROOT ?=

PROJECT_NAME     := uart_btfriend32
TARGETS          := nrf51822_xxac
OUTPUT_DIRECTORY := _build

SDK_ROOT ?= ../../../../nRF5_SDK_15.3.0_59ac345
PROJ_DIR := ../../..

$(OUTPUT_DIRECTORY)/nrf51822_xxac.out: \
  LINKER_SCRIPT  := nrf51_xxac.ld

# Source files common to all targets
SRC_FILES += \
  $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_uart.c \
  $(PROJ_DIR)/SEGGER_RTT_V640/RTT/SEGGER_RTT.c \
  $(PROJ_DIR)/SEGGER_RTT_V640/RTT/SEGGER_RTT_printf.c \
  $(SDK_ROOT)/modules/nrfx/mdk/gcc_startup_nrf51.S \
  $(SDK_ROOT)/modules/nrfx/mdk/system_nrf51.c \
  $(PROJ_DIR)/hopping.c \
  $(PROJ_DIR)/queue.c \
  $(PROJ_DIR)/nrf/main.c \
  $(PROJ_DIR)/nrf/transport_uart.c \
  $(PROJ_DIR)/nrf/radio.c \
  $(PROJ_DIR)/nrf/timer.c \

# Include folders common to all targets
INC_FOLDERS += \
  $(SDK_ROOT)/components \
  $(SDK_ROOT)/components/toolchain/gcc \
  ../config \
  $(PROJ_DIR)/SEGGER_RTT_V640/RTT \
  $(PROJ_DIR)/ \
  $(PROJ_DIR)/nrf \
  $(SDK_ROOT)/modules/nrfx \
  $(SDK_ROOT)/components/drivers_nrf/nrf_soc_nosd \
  $(SDK_ROOT)/modules/nrfx/mdk \
  $(SDK_ROOT)/components/libraries/bsp \
  $(SDK_ROOT)/components/libraries/util \
  $(SDK_ROOT)/components/toolchain \
  $(SDK_ROOT)/components/boards \
  $(SDK_ROOT)/modules/nrfx/drivers/include \
  $(SDK_ROOT)/components/toolchain/cmsis/include \
  $(SDK_ROOT)/modules/nrfx/hal \
  $(SDK_ROOT)/integration/nrfx \

# Libraries common to all targets
LIB_FILES += \

# Optimization flags
OPT = -Os -ggdb3
#OPT = -Og -ggdb3
# Uncomment the line below to enable link time optimization
#OPT += -flto

GIT_VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)

# C flags common to all targets
CFLAGS += $(OPT)
CFLAGS += -DVERSION=\"$(GIT_VERSION)\"
CFLAGS += -DNRF51
CFLAGS += -DNRF51822
CFLAGS += -DBOARD_CUSTOM
CFLAGS += -DBSP_DEFINES_ONLY
CFLAGS += -mcpu=cortex-m0
CFLAGS += -mthumb -mabi=aapcs
CFLAGS +=  -Wall -Werror 
CFLAGS += -mfloat-abi=soft
# make no unaligned access explicit
CFLAGS += -mno-unaligned-access
# keep every function in separate section, this allows linker to discard unused ones
CFLAGS += -ffunction-sections -fdata-sections -fno-strict-aliasing
CFLAGS += -fno-builtin --short-enums 


# C++ flags common to all targets
CXXFLAGS += $(OPT)

# Assembler flags common to all targets
ASMFLAGS += -DNRF51
ASMFLAGS += -DNRF51822
ASMFLAGS += -DBOARD_CUSTOM
ASMFLAGS += -DBSP_DEFINES_ONLY
# causes warning if enabled, already set by Makefile.common
# ASMFLAGS += -x assembler-with-cpp

# Linker flags
LDFLAGS += $(OPT)
LDFLAGS += -mthumb -mabi=aapcs -L$(SDK_ROOT)/modules/nrfx/mdk -T$(LINKER_SCRIPT)
LDFLAGS += -mcpu=cortex-m0
# let linker to dump unused sections
LDFLAGS += -Wl,--gc-sections
# use newlib in nano version
LDFLAGS += --specs=nano.specs -lc -lnosys

.PHONY: $(TARGETS) default all clean help flash 

# Default target - first one defined
default: nrf51822_xxac

# Print all targets that can be built
help:
	@echo following targets are available:
	@echo 		nrf51822_xxac
	@echo		nrfx_config - starting external tool for editing nrfx_config.h
	@echo		flash      - flashing binary

TEMPLATE_PATH := $(SDK_ROOT)/components/toolchain/gcc

include $(TEMPLATE_PATH)/Makefile.common

$(foreach target, $(TARGETS), $(call define_target, $(target)))

.PHONY: flash erase

# Flash the program
flash: $(OUTPUT_DIRECTORY)/nrf51822_xxac.hex
	@echo Flashing: $<
	nrfjprog --program $< -f nrf51 --sectorerase
	nrfjprog --reset -f nrf51

erase:
	nrfjprog -f nrf51 --eraseall

SDK_CONFIG_FILE := ../config/nrfx_config.h
CMSIS_CONFIG_TOOL := $(SDK_ROOT)/external_tools/cmsisconfig/CMSIS_Configuration_Wizard.jar
sdk_config:
	java -jar $(CMSIS_CONFIG_TOOL) $(SDK_CONFIG_FILE)
