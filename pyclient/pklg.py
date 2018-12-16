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
PKLG Writer for Apple's PacketLogger format:

typedef struct {
    uint32_t    len;    // header + payload
    uint32_t    ts_sec;
    uint32_t    ts_usec;
    uint8_t     type;   // 0xfc for note
} packet_log_entry_t;

"""

from struct import *

class PklgWriter(object):

    # packet types
    PACKET_TYPE_LOG     = 0xfc
    PACKET_TYPE_CMD     = 0x00
    PACKET_TYPE_EVT     = 0x01
    PACKET_TYPE_ACL_OUT = 0x02
    PACKET_TYPE_ACL_IN  = 0x03
    PACKET_TYPE_SCO_OUT = 0x09
    PACKET_TYPE_SCO_IN  = 0x08

    def __init__(self, output):
        self.output = open(output,'wb')

    def write_hci_packet(self, ts_sec, ts_usec, packet_type, data):

        packet_size = 9 + len(data)

        pkt_header = pack(
            '>IIIB',
            packet_size,
            ts_sec,
            ts_usec,
            packet_type
        )
        self.output.write(pkt_header)
        self.output.write(data)

    def write_log_message(self, ts_sec, ts_usec, message):
        self.write_hci_packet(ts_sec, ts_usec, self.PACKET_TYPE_LOG, message.encode('ascii'))
