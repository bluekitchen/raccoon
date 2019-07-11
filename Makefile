# nRF5 SDK Repo
NRF5_SDK		 ?= nRF5_SDK_15.3.0_59ac345
NRF5_SDK_ROOT     = $(NRF5_SDK)/
NRF5_SDK_ARCHIVE  = $(NRF5_SDK).zip
NRF5_SDK_MAJOR    = $(shell echo $(NRF5_SDK) | sed -e "s/nRF5_SDK_\([0-9]*\)\..*/\1/g")
NRF5_SDK_URL      = https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v$(NRF5_SDK_MAJOR).x.x/$(NRF5_SDK_ARCHIVE)

all: subdirs | $(NRF5_SDK_ROOT)

SUBDIRS = firmware/nrf/blefriend32/armgcc/ \
		  firmware/nrf/pca10028/armgcc/    \
		  firmware/nrf/pca10040/armgcc/    \
		  firmware/nrf/pca10059/armgcc/

SUBDIRS_CLEAN := $(addsuffix clean,$(SUBDIRS))

.PHONY: subdirs $(SUBDIRS)

subdirs: $(NRF5_SDK_ROOT)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

.SECONDARY: $(NRF5_SDK_ARCHIVE)
.PRECIOUS: $(NRF5_SDK_ARCHIVE)

$(NRF5_SDK_ROOT): | $(NRF5_SDK_ARCHIVE)
	unzip $(NRF5_SDK_ARCHIVE)
ifneq "$(findstring $(NRF5_SDK).patch,$(wildcard *.patch))" ""
	patch -Nup0 --binary < $(NRF5_SDK).patch
endif

$(NRF5_SDK_ARCHIVE):
	@echo sdk archive not found, downloading now...
	wget -c $(NRF5_SDK_URL)


.PHONY: clean

clean: $(SUBDIRS_CLEAN)

%clean:
	$(MAKE) -C $* clean

clean:
	rm -rf *.o *.d

distclean: clean
	rm -rf $(NRF5_SDK_ROOT)
	rm -f $(NRF5_SDK_ARCHIVE)

ASTYLE_OPTIONS=--style=attach --add-braces --indent-switches --suffix=none --exclude="firmware/SEGGER_RTT_V640" --exclude="nRF5_SDK_15.2.0_9412b96"

format:
	astyle ${ASTYLE_OPTIONS} --recursive "*.c"
	astyle ${ASTYLE_OPTIONS} --recursive "*.c"

