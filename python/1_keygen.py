from tasks import via_openssl_keygen
import os
import json
import sys
import base64

# 1. Request for generating cert  and write a privte key into a file
id = 'alice'
passphrase = 'hello'

priv_key = via_openssl_keygen(id, passphrase)
bkey = base64.b64decode(priv_key)
skey = bkey.decode('utf-8')
print(skey)

prv_key_file=f'{id}.pem'
with open(prv_key_file, 'wb') as key_file:
     binary_format = bytearray(bkey)
     key_file.write(binary_format)
     key_file.close()

