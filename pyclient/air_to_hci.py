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
Construct HCI Trace from adv and link layer packets received by radio sniffer
"""

from struct import *
from pklg import *

# internal debugging
def as_hex(data):
    str_list = []
    for byte in data:
        str_list.append("{0:02x} ".format(byte))
    return ''.join(str_list)

class PklgAirWriter(PklgWriter):

    # direction
    DIRECTION_DONT_KNOW = 0
    DIRECTION_MASTER    = 1
    DIRECTION_SLAVE     = 2

    def __init__(self, output):
        super().__init__(output)
        self.con_handle = 0xffff
        self.master_next_sn  = 0
        self.slave_next_sn   = 0

    """
    Write HCI Event based on Advertisement PDU
    """

    def write_advertisement_event(self, ts_sec, ts_usec, rssi, packet):
        # RSSI used unsigned byte, but is negative
        rssi    = -rssi

        # get header
        (adv_header, payload_len) = unpack_from('BB', packet)
        pdu_type = adv_header & 0x0f

        # map pdu type to adv_type
        adv_type = [0,1,3,None,4,None,2,None,None,None,None,None,None,None,None,None][pdu_type]
        if adv_type == None:
            return

        # get advertiser_addr_type
        if adv_header & 0x40:
            advertiser_addr_type = 1
        else:
            advertiser_addr_type = 0

        # get payload
        payload = packet[2:]

        # get addr and adv_data
        addr = payload[0:6]
        adv_data = payload [6:]

        # adv data <= 31
        if len(adv_data) > 31:
            return

        # create HCI LE Advertisement Event
        event = pack('BBBBBB', 0x3e, 12 + len(adv_data), 0x02, 1, adv_type, advertiser_addr_type) + addr + pack('B', len(adv_data)) + adv_data + pack('b', rssi)
        self.write_hci_packet(ts_sec, ts_usec, self.PACKET_TYPE_EVT, event)

    def write_connection_event(self, ts_sec, ts_usec, packet):
        # get header
        (adv_header, payload_len) = unpack_from('BB', packet)

        if self.con_handle != 0xffff:
            return
        
        self.con_handle = 0x0001
        self.master_next_sn  = 0
        self.slave_next_sn   = 0

        # get advertiser_addr_type
        if adv_header & 0x80:
            advertiser_addr_type = 1
        else:
            advertiser_addr_type = 0

        # get initiator_addr_type
        if adv_header & 0x40:
            initiator_addr_type = 1
        else:
            initiator_addr_type = 0

        # get payload
        payload = packet[2:]

        # split into InitA, AdvA, LLData
        initA  = payload[0:6]
        advA   = payload[6:12]
        LLData = payload[12:]

        # explode LLData
        (AA, CRCInit_0, CRCInit_1, CRCInit_2, WinSize, WinOffset, Interval, Latency, Timeout, ChM_0, ChM_1, ChM_2, ChM_3, ChM_4, Hop_SCA) = unpack('<IBBBBHHHHBBBBBB', LLData)
        Hop = Hop_SCA & 0x1f
        SCA = Hop_SCA >> 5

        # create HCI LE Connection Complete Event - we're master
        event = pack('<BBBBHBB', 0x3e, 18, 0x01, 0, self.con_handle, 0, advertiser_addr_type) + advA + pack('<HHHB', Interval, Latency, Timeout, SCA)
        self.write_hci_packet(ts_sec, ts_usec, self.PACKET_TYPE_EVT, event)

    def write_disconnection_event(self, ts_sec, ts_usec, reason):
        if self.con_handle == 0xffff:
            return
        event = pack('<BBBHB', 0x05, 4, 0, self.con_handle, reason)
        self.write_hci_packet(ts_sec, ts_usec, self.PACKET_TYPE_EVT, event)

    def write_adv_packet(self, ts_sec, ts_usec, flags, rssi, data):
        # ignore packets with CRC errors for now
        if flags & 4 == 0:
            return

        # get packet from data
        packet = data[:-3]

        # get header
        (adv_header, payload_len) = unpack_from('BB', packet)
        pdu_type = adv_header & 0x0f


        # CONNECT_IND
        if pdu_type == 5:
            self.write_connection_event(ts_sec, ts_usec, packet)

        else:
            self.write_advertisement_event(ts_sec, ts_usec, rssi, packet)

    def write_control_pdu(self, ts_sec, ts_usec, packet):
        (data_header, payload_len) = unpack_from('BB', packet)
        payload = packet[2:]

        Opcode = payload[0]
        CtrData = payload[1:]

        if Opcode == 0x02:
            ErrorCode = CtrData[0]
            self.write_disconnection_event(ts_sec, ts_usec, ErrorCode)

    def write_data_packet(self, ts_sec, ts_usec, flags, rssi, data):
        # ignore packets with CRC errors for now
        if flags & 4 == 0:
            return

        # get packet from data
        packet = data[:-3]

        # get header
        (data_header, payload_len) = unpack_from('BB', packet)

        LLID = data_header & 0x03
        NESN = (data_header >> 2) & 1
        SN   = (data_header >> 3) & 1
        MD   = (data_header >> 4) & 1


        # self.write_log_message(ts_sec, ts_usec, "Flags 0x%02x, LLID %u, PB %u, SN %u, expected SN %u, MD %u" % (flags, LLID, PB, SN, expected_sn, MD))

        # get direction from flags
        direction = flags & 3

        # deal with direction unknown: 
        # - log packet as hexdump
        # - reset SN tracker for both directions
        if direction == self.DIRECTION_DONT_KNOW:
            self.master_next_sn = -1;
            self.slave_next_sn  = -1;
            self.write_log_message(ts_sec, ts_usec, as_hex(packet))
            return

        # handle LL Control PDUs
        if LLID == 0x03:
            self.write_control_pdu(ts_sec, ts_usec, packet)
            return

        # use direction to pick correct ACL packet type
        if flags & 3 == self.DIRECTION_MASTER:
            packet_type = self.PACKET_TYPE_ACL_OUT
        else:
            packet_type = self.PACKET_TYPE_ACL_IN

        # map LLID to HCI Packet Boundary Flags and validate
        PB = [None, 1, 2, None][LLID]
        if PB == None:
            return

        # verify SN
        if flags & 3 == self.DIRECTION_MASTER:
            if self.master_next_sn >= 0 and SN != self.master_next_sn:
                return
            self.master_next_sn = SN ^ 1
        else:
            if self.slave_next_sn >= 0 and SN != self.slave_next_sn:
                return
            self.slave_next_sn = SN ^ 1

        # get L2CAP payload and skip empty packets
        payload = packet[2:]
        if len(payload) == 0:
            return

        # create fake HCI header
        hci_header = pack('HH', self.con_handle | (PB << 12), len(payload))
        hci_packet = hci_header + payload
        self.write_hci_packet(ts_sec, ts_usec, packet_type, hci_packet)

    def write_packet(self, ts_sec, ts_usec, flags, channel, rssi, ecount, delta, packet):
        # detect adv by accesss address
        (aa, ) = unpack_from("<I", packet)
        packet = packet[4:]
        if aa == 0x8E89BED6:
            self.write_adv_packet( ts_sec, ts_usec, flags, rssi, packet)
        else:
            self.write_data_packet(ts_sec, ts_usec, flags, rssi, packet)



