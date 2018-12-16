target extended-remote localhost:2331

# JLink only
#monitor exec SetRTTSearchRanges 0x20000000 0x8000

file armgcc/_build/nrf51822_xxac.out
load

# openocd RTT only
#monitor rtt setup 0x20000000 0x8000 "SEGGER RTT"
#monitor rtt start
#monitor rttserver start 7777 0

