import hashlib

blksize = hashlib.sha1().digest_size
opadding = 0x5c
ipadding = 0x36

def Hmac(key, msg):
    hmackey = key
    hmacmessage = msg
    if len(str(hmackey)) > blksize:
        hmackey = hashlib.sha1(key)
    hmackey = hmackey + bytearray(blksize - len(str(hmackey)))
    o_key_pad = bytearray([hmackey[i] ^ opadding for i in range(blksize)])
    print('Opad = ', o_key_pad)
    i_key_pad = bytearray([hmackey[i] ^ ipadding for i in range(blksize)])
    print('ipad = ', i_key_pad)
    x = hashlib.sha1(i_key_pad + hmacmessage).hexdigest()
    return (hashlib.sha1(o_key_pad + x)).hexdigest()

def check_Hmac(key, msg):
    import hmac
    from hashlib import sha1
    return hmac.HMAC(key, msg, sha1).hexdigest()

if __name__ == '__main__':

    print Hmac('key', 'abc')
    print check_Hmac('key', 'abc')
