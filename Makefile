# nRF5 SDK Repo
NRF5_SDK_URL      = https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v15.x.x/nRF5_SDK_15.2.0_9412b96.zip
NRF5_SDK_ROOT    ?= nRF5_SDK_15.2.0_9412b96/
NRF5_SDK_ARCHIVE ?= nRF5_SDK_15.2.0_9412b96.zip

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

$(NRF5_SDK_ARCHIVE):
	@echo sdk archive not found, downloading now...
	wget -c $(NRF5_SDK_URL)


.PHONY: clean

clean: $(SUBDIRS_CLEAN)

%clean:
	$(MAKE) -C $* clean

clean:
	rm -rf *.o *.d

ASTYLE_OPTIONS=--style=attach --add-braces --indent-switches --suffix=none --exclude="firmware/SEGGER_RTT_V640" --exclude="nRF5_SDK_15.2.0_9412b96"

format:
	astyle ${ASTYLE_OPTIONS} --recursive "*.c"
	astyle ${ASTYLE_OPTIONS} --recursive "*.c"

