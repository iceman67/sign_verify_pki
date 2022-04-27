from tasks import via_pyopenssl_sign256
import os
import json
import sys
import base64

# 1. Request for generating cert  and write a privte key into a file

# 2  Reqest a signature for the messge by ME
message = b"asdf"

# Get a signature 
message = b"asdf"
id ='alice'
signature = via_pyopenssl_sign256(id, message.decode('utf-8'), digest="sha256")
print (signature)
