#!/usr/bin/env python
import base64, hashlib, hmac, json, sys, getpass
from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD, SHA256

base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def prompt(p):
    return getpass.getpass(p + ": ")

def decrypt(encrypted, password):
    encrypted = base64.b64decode(encrypted)
    iv, encrypted = encrypted[:16], encrypted[16:]
    length = len(encrypted)
    encrypted += ' ' * (15 - (length-1)%16)
    hash = (hmac.new(password, iv + "\x00\x00\x00\x01", hashlib.sha1).digest() +
            hmac.new(password, iv + "\x00\x00\x00\x02", hashlib.sha1).digest())[:32]
    clear = AES.new(hash, AES.MODE_OFB, iv).decrypt(encrypted)[:length]
    return clear

def base58_decode(v):
  value = 0; ret = ''
  for c in v: value = value*58 + base58_chars.find(c)
  for i in range(32):
      ret = "%c"%(value%256) + ret; value /= 256
  return ret

def base58_encode(v):
    value = 0; ret = ''
    for c in v: value = value*256 + ord(c)
    while value > 0:
        ret = base58_chars[value%58] + ret; value /= 58
    return ret

def to_sipa(s):
    version = 128 # or 239 for testnet
    key = chr(version) + base58_decode(s)
    return base58_encode(key + SHA256.new(SHA256.new(key).digest()).digest()[:4])

clear = decrypt(prompt("encrypted wallet"), prompt("password"))
print clear
obj = json.loads(clear)

if (obj.has_key('double_encryption')):
    print("wallet uses double encryption")
    password = obj['sharedKey'].encode('ascii') + prompt("2nd password")
    for key in obj['keys']: key['priv'] = decrypt(key['priv'], password)
for key in obj['keys']: key['priv_sipa'] = to_sipa(key['priv'])
print(json.dumps(obj, indent=4, sort_keys = True))
