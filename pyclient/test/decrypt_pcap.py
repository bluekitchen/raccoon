#!/usr/bin/env python3

import sys
import os
from Cryptodome.Cipher import AES
from struct import pack, unpack, unpack_from

def as_hex(data):
    str_list = []
    for byte in data:
        str_list.append("{0:02x} ".format(byte))
    return ''.join(str_list)

def dump(name, value):
    print(("%10s: " % name) + ' '.join([("%02x" % x) for x in value]) + ' (MSO to LSO)')

def process_ll_enq_req(packet):
    ctr_data = packet[3:]
    skd_m = ctr_data[17:9:-1]
    iv_m  = ctr_data[21:17:-1]
    return (skd_m, iv_m)

def process_ll_enq_rsp(packet):
    ctr_data = packet[3:]
    skd_s = ctr_data[7::-1]
    iv_s  = ctr_data[11:7:-1]
    return (skd_s, iv_s)

def calc_sk(ltk, skd_m, skd_s):
    # combine SKD of master and slave
    dump('ltk', ltk)
    SKD = skd_s + skd_m
    dump('skd', SKD)
    # calculate SK = E(LTK, SKD)
    sk_cipher = AES.new(ltk, AES.MODE_ECB)
    SK = sk_cipher.encrypt(SKD)
    dump('sk', SK)
    return SK

def calc_iv(iv_m, iv_s):
    iv = iv_s + iv_m
    dump('IV', iv)
    return iv

def encrypt(sk, packet_counter, direction, iv, packet):
    llid    = packet[0] & 3
    payload = packet[2:]
    nonce   = bytes( pack("<IB", packet_counter & 0xffff, ((packet_counter >> 32) & 0x7f) | (direction << 7) ) + iv[::-1])
    data_cipher = AES.new(sk, AES.MODE_CCM, nonce=nonce, mac_len=4)
    data_cipher.update( bytes([llid]) )
    ciphertext, mic = data_cipher.encrypt_and_digest(payload)
    dump("cipher", ciphertext)
    dump("mic", mic)
    encrypted = packet[0:2] + ciphertext + mic
    return encrypted

def decrypt(sk, packet_counter, direction, iv, packet):
    llid    = packet[0] & 3
    payload = packet[2:-4]
    mic     = packet[-4:]
    dump('mic', mic)
    dump('cipher', payload)
    nonce   = bytes( pack("<IB", packet_counter & 0xffff, ((packet_counter >> 32) & 0x7f) | (direction << 7) ) + iv[::-1])
    dump('nonce', nonce)
    data_cipher = AES.new(sk, AES.MODE_CCM, nonce=nonce, mac_len=4)
    data_cipher.update( bytes([llid]) )
    plaintext = data_cipher.decrypt(payload)
    try:
        data_cipher.verify(mic)
    except ValueError:
        print("MIC mismatch")
    decrypted = bytes( [packet[0], packet[1] -4]) + plaintext
    return decrypted


if len(sys.argv) < 3:
    print('Usage: ', sys.argv[0], 'trace.pcap 0123456789abcdef')
    print('Decrypt trace.pcap using link key 0123456789abcdef and creating trace.decrypted.pcap')
    exit(0)

infile  = sys.argv[1]
outfile = os.path.splitext(infile)[0] + ".decrypted.pcap"
linkkey = bytes.fromhex( sys.argv[2])

print("Decrypting %s into %s using link key: %s" % (infile, outfile, sys.argv[2]) )

last_aa = 0
encrypted = False
packet_count_master = 0
packet_count_slave  = 0
tx_encrypted_master = False
tx_encrypted_slave  = False

with open (outfile, 'wb') as fout:
    with open (infile, 'rb') as fin:

        # read file header
        file_header = fin.read(24)
        fout.write(file_header)

        while True:

            # read packet header
            packet_header = fin.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_usec, packet_size, _ = unpack('<IIII', packet_header)
            # ignore payload header
            payload_header = fin.read(7)
            # read payload meta
            payload_info  = fin.read(10)
            _, flags, channel, rssi, ecount, delta = unpack('<BBBBHI', payload_info)
            master_to_slave = (flags & 2) == 2
            payload = fin.read(packet_size - 17)
            aa, header, length = unpack('<IBB', payload[:6])

            # reset encryption state
            if aa != last_aa:
                encrypted = False
                last_aa = aa

            if channel < 37:

                # dump
                if aa != 0x8e89bed6:
                    print('%6u.%06u: header %02x %02x - %s' % (ts_sec, ts_usec, header, length, as_hex(payload[6:-3])))

                if length >= 4:
                    encrypted = payload[4:-3]
                    update_packet = False
                    if master_to_slave and tx_encrypted_master:
                        # decrypt packet (dirction 1 = master to slave)
                        print('encrypted: %s' % as_hex(encrypted))
                        decrypted = decrypt(SK, packet_count_master, 1, IV, encrypted)
                        print('decrypted: %s' % as_hex(decrypted))
                        tx_encrypted_slave = True
                        packet_count_master += 1
                        update_packet = True
    
                    if not master_to_slave and tx_encrypted_slave:
                        # decrypt packet (dirction 1 = master to slave)
                        print('encrypted: %s' % as_hex(encrypted))
                        decrypted = decrypt(SK, packet_count_slave, 0, IV, encrypted)
                        print('decrypted: %s' % as_hex(decrypted))
                        packet_count_slave += 1
                        update_packet = True

                    if update_packet:
                        payload = payload[0:4] + decrypted + payload[-3:]
                        packet_header  = pack( '<IIII', ts_sec, ts_usec, packet_size-4, packet_size-4)
                        payload_header = pack( '<BBBBHB', 0, 6, packet_size-4-7, 1, 0, 0x06)

                llid = header & 3
                if llid == 3:
                    opcode = payload[6]
                    ctr_data = payload[7:-3]
                    if opcode == 3:
                        # LL_ENC_REQ
                        (skd_m, iv_m) = process_ll_enq_req(encrypted)
                        print("LL_ENC_REQ: SKDm %s, IVm %s" % ( as_hex(skd_m), as_hex(iv_m) ))
                    if opcode == 4:
                        # LL_ENC_RSP
                        (skd_s, iv_s) = process_ll_enq_rsp(encrypted)
                        print("LL_ENC_RSP: SKDs %s, IVs %s" % ( as_hex(skd_s), as_hex(iv_s) ))

                        # setup SK + IV
                        SK = calc_sk(linkkey, skd_m, skd_s)
                        IV = calc_iv(iv_m, iv_s)
                        packet_count_master = 0
                        packet_count_slave  = 0

                        # next packet from master will be encrytped
                        tx_encrypted_master = True

                    if opcode == 5:
                        # LL_START_ENC_REQ
                        print('LL_START_ENC_REQ')

            # write packet
            fout.write(packet_header)
            fout.write(payload_header)
            fout.write(payload_info)
            fout.write(payload)
