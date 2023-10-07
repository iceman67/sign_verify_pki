from tasks import via_pyopenssl_sign256_key,via_pyopenssl_verify, via_pyopenssl_sign256
import os
import json
import sys
import base64

# 1. Request for generating cert  and write a privte key into a file

# 2  Reqest a signature for the messge by ME  and fet a signature 
message = b"asdf"
id ='alice'
signature = via_pyopenssl_sign256(id, message.decode('utf-8'), digest="sha256")
print (signature)

#3. Verify a message with a signature
#message = b"XXXX"
message = b"asdf"
#message = base64.b64encode(message)
status = via_pyopenssl_verify(id, signature, message.decode('utf-8'), digest="sha256")
print ("verifying status = {}".format(status))
