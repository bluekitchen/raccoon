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

"""
Bluetooth AD parser
"""

from struct import *
import uuid

def as_hex(data):
    str_list = []
    for byte in data:
        str_list.append("{0:02x} ".format(byte))
    return ''.join(str_list)

def adv_parser(adv_data):
    while len(adv_data):
        item_len  = adv_data[0]
        item_type = adv_data[1]
        item_data = adv_data[2:1+item_len]
        yield (item_type, item_data)
        adv_data = adv_data[1+item_len:]


def adv_info_for_data(adv_data):
    info = []
    for (item_type, item_data) in adv_parser(adv_data):
        if item_type == 8 or item_type == 9:
            info.append( "Name: %s" % item_data.decode('utf-8'))
        if item_type == 2 or item_type == 3:
            info.append ("UUID16: %04X" % unpack_from('<H', item_data))
        if item_type == 4 or item_type == 5:
            info.append ("UUID32: %08X" % unpack_from('<I', item_data))
        if item_type == 6 or item_type == 7:
        	uuid = UUID(bytes_le=item_data)
            info.append ("UUID128: " + str(uuid128))
    return ', '.join(info)

adv_data  =  bytearray( [0x02, 0x01, 0x06, 0x0b, 0x09, 0x4c, 0x45, 0x20, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x03, 0x02, 0x10, 0xff, ])

print(adv_info_for_data(adv_data))
