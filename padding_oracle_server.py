import sys
import os
import base64
import binascii
import json
import urllib
import re
import random
import logging
import hexdump
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from flask import Flask, request, redirect

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

backend = default_backend()
cipher = algorithms.TripleDES
key_file = 'keys.bin'
cipher_key = None
cipher_block_bytelen = cipher.block_size // 8
cipher_key_bytelen = cipher_block_bytelen
if cipher == algorithms.TripleDES:
    cipher_key_bytelen = cipher_block_bytelen * 3

if os.path.exists(key_file):
    with open(key_file, 'rb') as f:
        cipher_key = f.read(cipher_key_bytelen)
else:
    cipher_key = os.urandom(cipher_key_bytelen)
    with open(key_file, 'wb') as f:
        f.write(cipher_key)

@app.route('/', methods=['POST', 'GET'])
def main():
    if type(cipher_key) != str or len(cipher_key) != cipher_key_bytelen:
        return "no key", 500

    auth = request.args.get('auth', None)
    if auth is None:
        cleartext = '{"userid":%d,"is_admin":0}' % random.randint(1000000, 2000000)
        iv = os.urandom(cipher_block_bytelen)
        padder = padding.PKCS7(cipher.block_size).padder()
        padded_data = padder.update(cleartext) + padder.finalize()
        encryptor = Cipher(cipher(cipher_key), modes.CBC(iv), backend=backend).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return redirect('/?auth=' + binascii.hexlify(iv + ciphertext))

    try:
        received = binascii.unhexlify(auth)
    except:
        return "hex error", 400
    print "received"
    hexdump.hexdump(received)
    sys.stdout.flush()

    if len(received) < cipher_block_bytelen * 2:
        return "input too short", 400
    iv, ciphertext = received[:cipher_block_bytelen], received[cipher_block_bytelen:]

    decryptor = Cipher(cipher(cipher_key), modes.CBC(iv), backend=backend).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    print "decrypted"
    hexdump.hexdump(decrypted)
    sys.stdout.flush()

    unpadder = padding.PKCS7(cipher.block_size).unpadder()
    unpadded = unpadder.update(decrypted)
    try:
        unpadded += unpadder.finalize()
    except ValueError:
        return "padding error", 400
    print "unpadded"
    hexdump.hexdump(unpadded)
    sys.stdout.flush()

    try:
        decoded = unpadded.decode('utf-8')
        parsed = json.loads(decoded)
    except:
        return "parsing error", 400

    if type(parsed) != dict or 'userid' not in parsed or 'is_admin' not in parsed:
        return "parsing error", 400

    if parsed['is_admin']:
        return "Hello user #%d, you are admin!" % parsed['userid']
    else:
        return "Hello user #%d!" % parsed['userid']

if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
