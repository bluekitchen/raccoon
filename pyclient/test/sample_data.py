from base64 import b64decode
from Cryptodome.Cipher import AES
from struct import pack

def parse_hex(string):
	return bytes.fromhex( string.replace("0x",""))

def dump(name, value):
	print(("%10s: " % name) + ' '.join([("%02x" % x) for x in value]) + ' (MSO to LSO)')

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


# setup values
# EDIV = 0x2474 (MSO to LSO)
# RAND = 0xABCDEF1234567890 (MSO to LSO)
LTK  = parse_hex("0x4C68384139F574D836BCF34E9DFB01BF")
SKDm = parse_hex("0xACBDCEDFE0F10213")
SKDs = parse_hex("0x0213243546576879")
IVm  = parse_hex("0xBADCAB24")
IVs  = parse_hex("0xDEAFBABE")

# get SK from received SKDs
SK = calc_sk(SKDm, SKDs)

# get IV from received IVs
IV = calc_iv(IVm, IVs)


# LL_START_ENC_RSP, master to slave
# master->slave = 1, slave->master = 0
packet_counter_master = 0
direction = 1  
LL_START_ENC_RSP1 = parse_hex("0f0506")
print('LL_START_ENC_RSP1 ENC')
dump('orig', LL_START_ENC_RSP1)
encrypted = encrypt(SK, packet_counter_master, direction, IV, LL_START_ENC_RSP1)
dump('encrypted', encrypted)
print('LL_START_ENC_RSP1 DEC')
decrypted = decrypt(SK, packet_counter_master, direction, IV, encrypted)
dump('decrypted', decrypted)

# LL_START_ENC_RSP, slave to master
packet_counter_slave = 0
print('LL_START_ENC_RSP2 ENC')
direction       = 0
LL_START_ENC_RSP2 = parse_hex("070506")
dump('orig', LL_START_ENC_RSP2)
encrypted = encrypt(SK, packet_counter_slave, direction, IV, LL_START_ENC_RSP2)
dump('encrypted', encrypted)
print('LL_START_ENC_RSP2 DEC')
decrypted = decrypt(SK, packet_counter_slave, direction, IV, encrypted)
dump('decrypted', decrypted)

# Data packet 1, master to slave
# master->slave = 1, slave->master = 0
packet_counter_master += 1
direction = 1  
DATA1_MASTER = parse_hex("0e1f1700636465666768696A6B6C6D6E6F707131323334353637383930")
print('DATA1_MASTER ENC')
dump('orig', DATA1_MASTER)
encrypted = encrypt(SK, packet_counter_master, direction, IV, DATA1_MASTER)
dump('encrypted', encrypted)
print('DATA1_MASTER DEC')
decrypted = decrypt(SK, packet_counter_master, direction, IV, encrypted)
dump('decrypted', decrypted)

# Data packet 1, slave to master
# master->slave = 1, slave->master = 0
packet_counter_slave += 1
direction = 0
DATA1_SLAVE = parse_hex("061f170037363534333231304142434445464748494A4B4C4D4E4F5051")
print('DATA1_SLAVE ENC')
dump('orig', DATA1_SLAVE)
encrypted = encrypt(SK, packet_counter_master, direction, IV, DATA1_SLAVE)
dump('encrypted', encrypted)
print('DATA1_SLAVE DEC')
decrypted = decrypt(SK, packet_counter_master, direction, IV, encrypted)
dump('decrypted', decrypted)
