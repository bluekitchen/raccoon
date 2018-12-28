#!/usr/bin/env python3
from base64 import b64decode
from Cryptodome.Cipher import AES
from struct import pack

def parse_hex(string):
    return bytes.fromhex( string.replace("0x",""))

def dump(name, value):
    print(("%18s: " % name) + ' '.join([("%02x" % x) for x in value]))

def calc_sk(skd_m, skd_s):
    # combine SKD of master and slave
    SKD = skd_s + skd_m
    # calculate SK = E(LTK, SKD)
    sk_cipher = AES.new(LTK, AES.MODE_ECB)
    SK = sk_cipher.encrypt(SKD)
    return SK

def calc_iv(iv_m, iv_s):
    return iv_s + iv_m

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
    data_cipher = AES.new(sk, AES.MODE_CCM, nonce=nonce, mac_len=4)
    data_cipher.update( bytes([llid]) )
    plaintext = data_cipher.decrypt_and_verify(payload, mic)
    deccrypted = packet[0:2] + plaintext
    return deccrypted

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

# setup values
# EDIV = 0x2474 (MSO to LSO)
# RAND = 0xABCDEF1234567890 (MSO to LSO)
LTK  = parse_hex("0x4C68384139F574D836BCF34E9DFB01BF")

# LL_ENQ_REQ
LL_ENQ_REQ = parse_hex("03 17 03 90 78 56 34 12 ef cd ab 74 24 13 02 f1 e0 df ce bd ac 24 ab dc ba")
dump("LL_ENQ_REQ", LL_ENQ_REQ)
(SKDm, IVm) = process_ll_enq_req(LL_ENQ_REQ)

# LL_ENQ_RSP
LL_ENQ_RSP = parse_hex("0b 0d 04 79 68 57 46 35 24 13 02 be ba af de")
dump("LL_ENQ_RSP", LL_ENQ_RSP)
(SKDs, IVs) = process_ll_enq_rsp(LL_ENQ_RSP)

# get SK from received SKDs
SK = calc_sk(SKDm, SKDs)
dump('sk', SK)

# get IV from received IVs
IV = calc_iv(IVm, IVs)
dump('iv', IV)

# LL_START_ENC_REQ

# LL_START_ENC_RSP1, master to slave
# master->slave = 1, slave->master = 0
packet_counter_master = 0
direction = 1  
LL_START_ENC_RSP1 = parse_hex("0f 05 9f cd a7 f4 48")
dump("LL_START_ENC_RSP1", LL_START_ENC_RSP1)
decrypted = decrypt(SK, packet_counter_master, direction, IV, LL_START_ENC_RSP1)
dump('decrypted', decrypted)

# LL_START_ENC_RSP, slave to master
packet_counter_slave = 0
direction = 0
LL_START_ENC_RSP2 = parse_hex("07 05 a3 4c 13 a4 15")
dump("LL_START_ENC_RSP2", LL_START_ENC_RSP2)
decrypted = decrypt(SK, packet_counter_slave, direction, IV, LL_START_ENC_RSP2)
dump('decrypted', decrypted)

# Data packet 1, master to slave
# master->slave = 1, slave->master = 0
packet_counter_master += 1
direction = 1  
DATA1_MASTER = parse_hex("0e 1f 7a 70 d6 64 15 22 6d f2 6b 17 83 9a 06 04 05 59 6b d6 56 4f 79 6b 5b 9c e6 ff 32 f7 5a 6d 33")
dump("DATA1_MASTER", DATA1_MASTER)
decrypted = decrypt(SK, packet_counter_master, direction, IV, DATA1_MASTER)
dump('decrypted', decrypted)

# Data packet 1, slave to master
# master->slave = 1, slave->master = 0
packet_counter_slave += 1
direction = 0
DATA1_SLAVE = parse_hex("06 1f f3 88 81 e7 bd 94 c9 c3 69 b9 a6 68 46 dd 47 86 aa 8c 39 ce 54 0d 0d ae 3a dc df 89 b9 60 88")
dump("DATA1_SLAVE", DATA1_SLAVE)
decrypted = decrypt(SK, packet_counter_master, direction, IV, DATA1_SLAVE)
dump('decrypted', decrypted)
