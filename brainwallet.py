#!/usr/bin/env python
import hashlib, binascii
from hashlib import sha256
import ecdsa

DEBUG = True
DEBUG = False

"""
# secp256k1 T = (p, a, b, G, n, h)
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1 # The proven prime
gX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 # generator point
gY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # generator point
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
a = 0; b = 7 # from elliptic curve equation y^2 = x^3 + a*x + b

secp256k1curve = ecdsa.ellipticcurve.CurveFp(p, a, b)
secp256k1point = ecdsa.ellipticcurve.Point(secp256k1curve, gX,	gY, n)
CURVE_TYPE = ecdsa.curves.Curve('secp256k1', secp256k1curve, secp256k1point, (1, 3, 132, 0, 10))
#"""
CURVE_TYPE = ecdsa.curves.SECP256k1

BASE_58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE_58_CHARS_LEN = len(BASE_58_CHARS)
MAINNET_PREFIX = '80'

def numToWIF(numPriv):
	privKeyHex = MAINNET_PREFIX+hex(numPriv)[2:].strip('L').zfill(64)
	privKeySHA256Hash = sha256(binascii.unhexlify(privKeyHex)).hexdigest()
	privKeyDoubleSHA256Hash = sha256(binascii.unhexlify(privKeySHA256Hash)).hexdigest()
	checksum = privKeyDoubleSHA256Hash[:8]
	wifNum = int(privKeyHex + checksum, 16)

	# convert number to base58
	base58CharList = []
	for i in range(100):
		base58CharList.append(BASE_58_CHARS[wifNum/(BASE_58_CHARS_LEN**i)%BASE_58_CHARS_LEN])

	# convert character list to string, reverse string, and strip extra leading 1's
	return ''.join(base58CharList)[::-1].lstrip('1')


def WIFToNum(wifPriv):
	numPriv = 0
	for i in range(len(wifPriv)):
		numPriv += BASE_58_CHARS.index(wifPriv[::-1][i])*(BASE_58_CHARS_LEN**i)

	numPriv = numPriv/(2**32)%(2**256)
	return numPriv


def isValidWIF(wifPriv):
	return numToWIF(WIFToNum(wifPriv)) == wifPriv


def numToAddress(numPriv):
	pko = ecdsa.SigningKey.from_secret_exponent(numPriv, CURVE_TYPE)
	pubkey = binascii.hexlify(pko.get_verifying_key().to_string())
	pubkeySHA256Hash = sha256(binascii.unhexlify('04' + pubkey)).hexdigest()
	pubkeySHA256RIPEMD160Hash = hashlib.new('ripemd160', binascii.unhexlify(pubkeySHA256Hash)).hexdigest()

	hash1 = sha256(binascii.unhexlify('00' + pubkeySHA256RIPEMD160Hash)).hexdigest()
	hash2 = sha256(binascii.unhexlify(hash1)).hexdigest()
	checksum = hash2[:8]

	encodedPubKeyHex = pubkeySHA256RIPEMD160Hash + checksum
	encodedPubKeyNum = int(encodedPubKeyHex, 16)

	base58CharIndexList = []
	while encodedPubKeyNum != 0:
		base58CharIndexList.append(encodedPubKeyNum % BASE_58_CHARS_LEN)
		encodedPubKeyNum /= BASE_58_CHARS_LEN

	m = 0
	while encodedPubKeyHex[0 + m : 2 + m] == '00':
  		base58CharIndexList.append(0);
  		m = m + 2;

	address = ''
	for i in base58CharIndexList:
		address = BASE_58_CHARS[i] + address
	
	return '1' + address

passPhrase = raw_input()
if DEBUG: passPhrase = "test"

num = int(sha256(passPhrase).hexdigest(), 16)
privateKey = numToWIF(num)
address = numToAddress(num)
assert isValidWIF(privateKey) == True
print privateKey
print address
if DEBUG: print privateKey == '5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh'
if DEBUG: print address == '1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE'
