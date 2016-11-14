#!/usr/bin/python3

import hmac
import hashlib
import struct
import time
import base64
import sys

comp = "059036"
key_google2 = "JBSWY3DPEHPK3PXP"
key_google = 'TRSCA5XBPDTSZCI2WNQWBX623XPBV6YB'

def test_hotp(secret, counter):
    key_byte = base64.b32decode(key_google, True)
    counter_byte = struct.pack(">Q", counter)
    hasher = hmac.new(key_byte, counter_byte, hashlib.sha1)
    hasher_digest = hasher.digest()
    offset = hasher_digest[19] & 15
    result = str((struct.unpack(">I", hasher_digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000)
    while len(result) < 6:
        result = '0' + result
    return result

def hotp(key, counter, digits=6, digest=hashlib.sha1):
    hmac_digest = hmac.new(key_to_byte(key), counter_to_byte(counter), digest)
    hmac_byte = bytearray(hmac_digest.digest())
    offset = hmac_byte[19] & 15
    result = ((hmac_byte[offset] & 0x7F) << 24 |
            (hmac_byte[offset + 1] & 0xFF) << 16 |
            (hmac_byte[offset + 2] & 0xFF) << 8 |
            (hmac_byte[offset + 3] & 0xFF))
    str_result = str(result % 10 ** digits)
    while len(str_result) < digits:
        str_result = '0' + str_result
    return str_result

def totp(key, digits=6, window=30, clock=None, digest=hashlib.sha1):
    if clock is None:
        clock = int(time.time())
    counter = int(clock / window)
    return hotp(key_google, counter)

def test_totp(key, digits=6, window=30, clock=None, digest=hashlib.sha1):
    if clock is None:
        clock = int(time.time())
    counter = int(clock / window)
    return test_hotp(key_google, counter)

def key_to_byte(key):
    padding = len(key) % 8
    if padding != 0:
        key += '=' * (8 - padding)
    return base64.b32decode(key, casefold=True)

def counter_to_byte(counter):
    result = bytearray()
    while counter != 0:
        result.append(counter & 0xFF)
        counter >>= 8
    return bytes(bytearray(reversed(result)).rjust(8, b'\0'))

if __name__ == '__main__':
    print(test_hotp(key_google, 0))
    print(hotp(key_google, 0))
    print(test_totp(key_google))
    print(totp(key_google))
