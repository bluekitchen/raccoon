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
PCAP Writer for Nordic's BLE Tap Format
"""

from struct import pack

class PcapNordicTapWriter(object):
    DLT = 272 # DLT_NORDIC_BLE
    BOARD_ID = 0x00

    def __init__(self, output=None):
        self.output = open(output,'wb')

        # write file header
        header = pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.DLT)
        self.output.write(header)

    def write_packet_header(self, ts_sec, ts_usec, packet_size):
        pkt_header = pack( '<IIII', ts_sec, ts_usec, packet_size, packet_size)
        self.output.write(pkt_header)

    def payload(self, flags, channel, rssi, ecount, delta, packet):
        payload_data = pack( '<BBBBHI',  10,  flags,  channel,  rssi,  ecount,  delta ) + packet
        pkt_size = len(payload_data)
        if pkt_size > 255:
            pkt_size = 255
        payload_header = pack( '<BBBBHB', self.BOARD_ID, 6, pkt_size, 1, 0, 0x06)
        return payload_header + payload_data[:pkt_size]
    
    def write_packet(self, ts_sec, ts_usec, flags, channel, rssi, ecount, delta, packet):
        # map direction to pcap master/slave flag
        oflags = 1
        if (flags & 0x3) == 1:
            oflags |= 2

        payload = self.payload( oflags, channel, rssi, ecount, delta, packet)
        self.write_packet_header(ts_sec, ts_usec, len(payload))
        self.output.write(payload)

    def close(self):
        self.output.close()
