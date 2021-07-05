#!/usr/bin/env python3

##############################################################################
#
#      Copyright (c) 2018, Raccon BLE Sniffer
#      All rights reserved.
#
#      Redistribution and use in source and binary forms, with or without
#      modification, are permitted provided that the following conditions are
#      met:
#      
#      # Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      # Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following disclaimer
#        in the documentation and/or other materials provided with the
#        distribution.
#      # Neither the name of "btlejack2" nor the names of its
#        contributors may be used to endorse or promote products derived from
#        this software without specific prior written permission.
#      
#      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##############################################################################

import argparse
import os
import queue
import serial
import signal
import sys
import threading
import time
import uuid

from serial.tools.list_ports import comports

from struct import *
from pcap import *
from pklg import *
from air_to_hci import *

# tags from packet.h
TAG_DATA                  = 0
TAG_MSG_RESET_COMPLETE    = 0x40
TAG_MSG_CONNECT_REQUEST   = 0x41
TAG_MSG_CONNECTION_EVENT  = 0x42
TAG_MSG_CONN_PARAM_UPDATE = 0x43
TAG_MSG_CHAN_MAP_UPDATE   = 0x44
TAG_MSG_LOG               = 0x50
TAG_MSG_TERMINATE         = 0x45
TAG_CMD_RESET             = 0x80
TAG_CMD_GET_VERSION       = 0x81
TAG_CMD_SNIFF_CHANNEL     = 0x82

ADVERTISING_RADIO_ACCESS_ADDRESS = 0x8E89BED6
ADVERTISING_CRC_INIT             = 0x555555


config_template = '''# Raccoon BLE Sniffer Config

# Output format
# pick one of the following logging formats by uncommenting the format line

# PKLG format minimics HCI data to/from a Bluetooth Controller. It can be opened with Wireshark and Apple's PacketLogger
# format  = 'pklg'

# PCAP format uses Bluetooth BLE Trace format defined by libbt/Ubertooth for use with CrackLE. It can be opened with Wireshark
# format = 'crackle'

# PCAP format uses Bluetooth BLE Trace format defined by Nordic. It can be opened with Wireshark.
format = 'pcap'


# Available Sniffer devices
# List of detected serial ports, please uncomment your Raccoon BLE Sniffer devices
sniffers = [
SNIFFERS
]

'''

config_name = 'config.py'

# vid/pid/baud/rtscts
sniffer_uart_config = [
    # PCA10028
    {  0x1366, 0x1015, 1000000, 1},
    # PCA10040
    # {  0x1366, 0x1015, 1000000, 1},
    # Adafruit BLEFriend32
    {  0x10c4, 0xea60, 1000000, 1},
]

def as_hex(data):
    str_list = []
    for byte in data:
        str_list.append("{0:02x} ".format(byte))
    return ''.join(str_list)

def addr_str(addr):
    return ':'.join([('%02x' % a) for a in addr[::-1]])

def adv_parser(adv_data):
    while len(adv_data):
        if len(adv_data) < 2:
            return
        item_len  = adv_data[0]
        item_type = adv_data[1]
        if len(adv_data) < 1 + item_len:
            return
        item_data = adv_data[2:1+item_len]
        yield (item_type, item_data)
        adv_data = adv_data[1+item_len:]

def adv_info_for_data(adv_data):
    info = []
    for (item_type, item_data) in adv_parser(adv_data):
        if item_type == 8 or item_type == 9:
            info.append( "Name: '%s'" % item_data.decode('utf-8'))
        if item_type == 2 or item_type == 3:
            info.append ("UUID16: %04X" % unpack_from('<H', item_data))
        if item_type == 4 or item_type == 5:
            info.append ("UUID32: %08X" % unpack_from('<I', item_data))
        if item_type == 6 or item_type == 7:
            uuid128 = uuid.UUID(bytes_le=item_data)
            info.append ("UUID128: " + str(uuid128))
    return ', '.join(info)

def create_config_template(config_path):
    # get connected devices
    ports = ""
    for (device, name, some_id) in comports():
        ports += "#   { 'port':'%s', 'baud':1000000, 'rtscts':1 },  # %s - %s}\n" % (device, name, some_id) 

    print ("Creating default config")
    with open (config_path, 'wt') as fout:
        fout.write(config_template.replace("SNIFFERS", ports))

"""
User Interface
"""
class ConsoleUI(object):
    def __init__(self):
        self.devices = {}
        self.advertisements = 0
        self.packets = 0
        self.status_shown = True
        self.connection_event = 0

    def print_line(self, line):
        sys.stdout.write( "\r\x1b[K" + line)

    def set_status(self, message):
        self.print_line(message)

    def print_line_with_newline(self, line):
        self.print_line(line + "\n")

    def log_debug(self, message):
        self.print_line_with_newline("[-] %s" % message)

    def log_info(self, message):
        self.print_line_with_newline("[+] %s" % message)

    def log_error(self, message):
        self.print_line_with_newline("[!] %s" % message)


    def process_advertisement(self, packet, rssi):

        self.advertisements += 1
        self.set_status("Advertisements: %u" % self.advertisements)

        # get header
        (adv_header, payload_len) = unpack_from('BB', packet)
        pdu_type = adv_header & 0x0f

        # decode pdu type
        adv_type = ["ADV_IND","ADV_DIRECT_IND","ADV_NONCONN_IND",None,"SCAN_RSP",None,"ADV_SCAN_IND",None,None,None,None,None,None,None,None,None][pdu_type]
        if adv_type == None:
            return

        # get payload
        payload = packet[2:]

        # get addr (as big endian) and adv_data
        addr = addr_str(payload[0:6])
        adv_data = payload [6:]

        # adv data <= 31
        if len(adv_data) > 31:
            return

        # use addr+type
        addr_and_type = "%s %15s" % (addr, adv_type)

        # check if in set
        if addr_and_type in self.devices:
            return

        adv_info = adv_info_for_data(adv_data)

        self.devices[addr_and_type] = adv_data
        rssi = -rssi
        self.log_info("%2u" % len(self.devices) + ". " + addr_and_type + " %4d dBm, " % rssi + adv_info)

    def process_packet(self, tag, data):
        if tag == TAG_DATA:
            # parse header
            timestamp_sniffer_us, channel, flags, rssi, aa = unpack_from( "<IBBBxI", data )
            # ignore packets with CRC errors for now
            if flags & 4 == 0:
                return
            packet  = data[12:-3]
            if aa == 0x8E89BED6:
                self.process_advertisement(packet, rssi)
            else:
                if len(packet) > 2:
                    self.packets  += 1
                self.set_status("Connection event %5u, data packets: %u" % (self.connection_event, self.packets))

        if tag == TAG_MSG_CONNECT_REQUEST:
            timestamp, = unpack_from("<I", data)
            initiator  = data[4:10]
            advertiser = data[10:16]
            aa, interval_us, timeout_us, latency = unpack_from("<IIIH", data[16:])
            self.log_info("CONNECTION %s -> %s -- aa %08x, interval %.2f ms, timeout_us %.2f ms, latency %u" % (addr_str(initiator), addr_str(advertiser), aa, interval_us / 1000, timeout_us / 1000, latency))
            self.connection_event = 0

        if tag == TAG_MSG_CONNECTION_EVENT:
            timestamp, self.connection_event = unpack_from("<IH", data)

        if tag == TAG_MSG_TERMINATE:
            timestamp, reason = unpack_from("<IB", data)
            if reason == 0:
                self.log_info("TERMINATE, disconnect")
            if reason == 1:
                self.log_info("TERMINATE, timeout")

        if tag == TAG_MSG_CHAN_MAP_UPDATE:
            timestamp, ch0, ch1, ch2, ch3, ch4= unpack_from("<IBBBBB", data)
            self.log_info("Channel Map Update: %02x%02x%02x%02x%02x" % (ch4, ch3, ch2, ch1, ch0))

        if tag == TAG_MSG_CONN_PARAM_UPDATE:
            timestamp, interval_us, timeout_us, latency = unpack_from("<IIIH", data)
            self.log_info("Connection Parameter Update: interval %.2f ms, timeout %.2f ms, latency %u" % (interval_us / 1000, timeout_us / 1000, latency))


"""
Sniffer connection
"""
class Sniffer(object):

    aborted    = False
    next_event = None

    def __init__(self, timebase_sec, port, baud, rtscts):
        (self.port, self.baud, self.rtscts) = port, baud, rtscts

        # open serial port, use 0.1 timeout for sync
        self.ser = serial.Serial(self.port, self.baud, timeout=None, rtscts=self.rtscts )

        # with Nordic devkits, UART is only activated after setting DTR
        self.ser.dtr = True

        # try to sync with sniffer
        tries = 0
 
        # reset sniffer
        self.write( pack('<BH', TAG_CMD_RESET, 0 ) )
        time.sleep( .250 )
        while self.ser.in_waiting:

            # reset input buffer
            self.ser.reset_input_buffer()
        
        # track start offset
        self.start_offset_us = int ((time.time() -  timebase_sec) * 1000000)

    def write(self, packet):
        self.ser.write(packet)

    def read_packet(self):
        data = self.ser.read(3)
        if self.aborted:
            return None
        if len(data) < 3:
            while (1):
                print("data len %u" % len(data))
        tag, length = unpack( "<BH", data )
        data = self.ser.read( length )
        if self.aborted:
            return None
        return (tag, data)

    def read_until_abort(self, queue):
        while not self.aborted:
            event = self.read_packet()
            if event != None:
                (tag, data) = event
                queue.put((time.time(), self.start_offset_us, tag, data))

    def start_reader_thread(self):
        # create event queue
        self.queue = queue.Queue()
        threading.Thread(target=self.read_until_abort,args=[self.queue]).start()

    def peek_event(self):
        if self.next_event == None:
            if self.queue.empty():
                return None
            self.next_event = self.queue.get()
        return self.next_event

    def get_event(self):
        if self.next_event == None:
            self.next_event = self.queue.get()
        event = self.next_event
        self.next_event = None
        return event

    def abort(self):
        self.aborted = True
        self.ser.cancel_read()


"""
Main application
"""

def signal_handler(sig, frame):
    global cfg
    global ui
    ui.log_info('\nThanks for using raccoon.')
    for sniffer in sniffers:
        sniffer.abort()
    sys.exit(0)


ui = ConsoleUI()
filter_mac = bytearray(6)

# configuration options
format = 'pcap'
rtscts = 1
log_delay = 0.1
rssi_min  = -80

# command parser
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--addr", help="follow only connections of device with bd_addr, e.g. 11:22:33:44:55:66")
parser.add_argument("-r", "--rssi", help="set minimum RSSI, default = %d" % rssi_min)
args = parser.parse_args()
if args.addr:
    # strip '-' and ':', store address in little endian
    stripped = args.addr.replace(":","").replace("-","")
    if len(stripped) != 12:
        ui.log_error("Invalid BD_ADDR %s" % args.addr)
        sys.exit(10)
    for i in range(0,6):
        filter_mac[5-i] = int(stripped[i*2:i*2+2], 16)
if args.rssi:
    rssi_min = int(args.rssi)

# get path to config file
script_path = os.path.dirname(sys.argv[0])
if len(script_path) == 0:
    config_path = config_name
else:
    config_path = script_path + '/' + config_name

# check config
if not os.path.isfile(config_path):
    ui.log_error("Config file %s does not exist" % config_path)
    create_config_template(config_path) 
    sys.exit(10)

# TODO: process command line arguments for:
# - minimum rssi

# load config
sys.path.insert(0, script_path)

import config as cfg

if not cfg.sniffers:
    ui.log_error("No sniffers object in Config file")
    create_config_template(config_path) 
    sys.exit(10)

# open log writer
cfg.format = cfg.format.lower()
if cfg.format == 'pcap':
    filename = 'trace.pcap'
    output = PcapNordicTapWriter(filename)
elif cfg.format == 'crackle':
    filename = 'trace.pcap'
    output = PcapLeLlWithPhdrWriter(filename)
elif cfg.format == 'pklg':
    filename = 'trace.pklg'
    output = PklgAirWriter(filename)
else:
    print('Unknown logging format %s' % cfg.format)
    sys.exit(10)

cfg_summary = "Config: output %s (%s), min rssi %d dBm" % (filename, cfg.format, rssi_min)
if args.addr:
    cfg_summary += "- filter: %s" % args.addr
ui.log_info(cfg_summary)


signal.signal(signal.SIGINT, signal_handler)

event_cnt = 0

# log start
log_start_sec = int(time.time())

sniffer_id = 0
sniffers = []
for sniffer in cfg.sniffers:
    # get config
    port   = sniffer['port']
    baud   = sniffer['baud']
    rtscts = sniffer['rtscts']
    channel = 37 + sniffer_id

    try:

        # create sniffer and start reading
        sniffer = Sniffer(log_start_sec, port, baud, rtscts)
        sniffer.start_reader_thread()

        # could be part of constructor call
        sniffer.channel = channel
        
        # check version
        sniffer.write( pack('<BH', TAG_CMD_GET_VERSION, 0 ) )
        (arrival_time, start_offset_us, tag, data) = sniffer.get_event()
        version = ''
        if tag == TAG_CMD_GET_VERSION:
            version = data.decode("utf-8")

        # sniffer info
        ui.log_debug("Sniffer #%x: port %s, baud %u, rtscts %u, channel %u, version %s" % (sniffer_id, port, baud, rtscts, channel, version))

        # start listening
        if channel < 40:
            rssi_min_neg = - rssi_min
            sniffer.write( pack('<BHIBII6sB', TAG_CMD_SNIFF_CHANNEL, 20, 0, channel, ADVERTISING_RADIO_ACCESS_ADDRESS, ADVERTISING_CRC_INIT, filter_mac, rssi_min_neg ) )            

        sniffer_id += 1
        sniffers.append(sniffer)

    except (serial.SerialException, FileNotFoundError):
        ui.log_error("Failed to connect to sniffer at port %s with %u baud" % (port, baud))

if len(sniffers) == 0:
    ui.log_error("No working sniffer found. Please connect sniffer and/or update config.py")
    sys.exit(0)

last_timestamp_us = 0;
direction_count = [ 0, 0, 0 ]

# process input
while 1:

    # log earliest event that has been received at least log_delay seconds ago
    earliest_event_sniffer      = None
    earliest_event_timestamp_us = None
    earliest_event_arrival_time = None

    for sniffer in sniffers:
        event = sniffer.peek_event()
        if event == None:
            continue

        # get event time
        (arrival_time, start_offset_us, tag, data) = event
        (timestamp_sniffer_us, ) = unpack_from( "<I", data )
        timestamp_log_us = start_offset_us + timestamp_sniffer_us

        # store if earlier
        if (earliest_event_timestamp_us == None ) or (timestamp_log_us < earliest_event_timestamp_us):
            earliest_event_sniffer = sniffer
            earliest_event_timestamp_us      = timestamp_log_us
            earliest_event_arrival_time = arrival_time

    # check if log_delay old
    if (earliest_event_timestamp_us == None) or ((time.time() - earliest_event_arrival_time) < log_delay):
        time.sleep(0.1)
        continue

    # finally, log event
    (arrival_time, start_offset_us, tag, data) = earliest_event_sniffer.get_event()
    timestamp_log_us = earliest_event_timestamp_us
    length = len(data)

    if tag == TAG_MSG_TERMINATE:
        ui.log_info("Restart sniffer on channel #%u" % earliest_event_sniffer.channel)
        earliest_event_sniffer.write( pack('<BHIBII6sB', TAG_CMD_SNIFF_CHANNEL, 20, 0, earliest_event_sniffer.channel, ADVERTISING_RADIO_ACCESS_ADDRESS, ADVERTISING_CRC_INIT, filter_mac, rssi_min_neg ) )

    if tag == TAG_DATA:

        # parse header
        timestamp_sniffer_us, channel, flags, rssi_negative, aa = unpack_from( "<IBBBxI", data )
        packet  = data[8:]

        # dump packet
        # print( tag, length, timestamp_log_us, channel, flags, rssi, as_hex(packet) )

        # direction count - what is it used for?
        direction = flags & 0x3
        direction_count[ direction ] += 1

        # delta and event count needed for pcap
        delta_ts = timestamp_log_us - last_timestamp_us
        last_timestamp_us = timestamp_log_us + 5 * 8 + ( length - 12 ) * 8; # ts is at start of message, move it to the end
        event_cnt += 1

        # write packet
        ts_sec  = log_start_sec + int(timestamp_log_us/1000000)
        ts_usec = timestamp_log_us % 1000000
        output.write_packet( ts_sec, ts_usec, flags, channel, rssi_negative, event_cnt, delta_ts, packet )

    # forward packets to ui, too
    ui.process_packet(tag, data)
