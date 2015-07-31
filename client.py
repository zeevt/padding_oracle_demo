from urlparse import urlparse, parse_qs
from binascii import hexlify, unhexlify
import requests

block_bytelen = 8
BASE_URL = 'http://localhost:8000/'

total_requests = 0
def get_content(ints):
    global total_requests
    total_requests += 1
    params={'auth': hexlify(''.join([chr(x) for x in ints]))}
    response = session.get(BASE_URL, params=params)
    return response.content    

def is_padding_error(ints):
    return get_content(ints) == 'padding error'

def decrypt_block_using_padding_oracle(bytes):
    assert len(bytes) == block_bytelen
    assert type(bytes[0]) == int
    ints = [0]*block_bytelen + bytes
    decrypted_block = [0]*block_bytelen
    for byte_idx in range(block_bytelen - 1, -1, -1):
        padding_byte = block_bytelen - byte_idx
        for i in range(block_bytelen - 1, byte_idx, -1):
            ints[i] = decrypted_block[i] ^ padding_byte
        for i in range(256):
            ints[byte_idx] = i
            if not is_padding_error(ints):
                decrypted_block[byte_idx] = padding_byte ^ i
                break
    return decrypted_block

def xor_blocks(b1, b2):
    return [a^b for a,b in zip(b1, b2)]

def decrypt_block_with_iv_using_padding_oracle(bytes):
    assert len(bytes) == block_bytelen * 2
    assert type(bytes[0]) == int
    iv, ciphertext_block = bytes[:block_bytelen], bytes[block_bytelen:]
    decrypted_block = decrypt_block_using_padding_oracle(ciphertext_block)
    return xor_blocks(iv, decrypted_block)

def decrypt_message_using_padding_oracle(bytes):
    assert len(bytes) % block_bytelen == 0
    assert len(bytes) >= block_bytelen * 2
    assert type(bytes[0]) == int
    decrypted = []
    curr_i = 0
    while curr_i + block_bytelen * 2 <= len(bytes):
        two_blocks = bytes[curr_i : curr_i+block_bytelen*2]
        decrypted.extend(decrypt_block_with_iv_using_padding_oracle(two_blocks))
        curr_i += block_bytelen
    return decrypted

def ints2s(ints):
    return ''.join([chr(x) for x in ints])

def s2ints(s):
    return [ord(c) for c in s]

def pkcs7pad(s):
    padding_length = block_bytelen - (len(s) % block_bytelen)
    padding = chr(padding_length) * padding_length
    return s + padding

def encrypt_message_using_padding_oracle(input, last_block_ciphertext=[0]*block_bytelen):
    cleartext = input
    if type(input) == str:
        cleartext = s2ints(pkcs7pad(input))
    ints = [0]*len(cleartext) + last_block_ciphertext
    curr = len(cleartext) - block_bytelen
    while curr >= 0:
        new_decrypt = decrypt_block_using_padding_oracle(ints[curr+block_bytelen:curr+block_bytelen*2])
        new_prev_block = xor_blocks(new_decrypt, cleartext[curr:curr+block_bytelen])
        ints[curr:curr+block_bytelen] = new_prev_block
        curr -= block_bytelen
    return ints

session = requests.session()
response = session.get(BASE_URL)
original_ints = [ord(x) for x in unhexlify(parse_qs(urlparse(response.url).query)['auth'][0])]
decrypted1 = decrypt_message_using_padding_oracle(original_ints)
print ints2s(decrypted1)
print "total requests:", total_requests
total_requests = 0

decrypted1[-3] = ord('1')
ints = encrypt_message_using_padding_oracle(decrypted1)
print get_content(ints)
print "total requests:", total_requests
total_requests = 0

