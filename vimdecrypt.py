#!/usr/bin/env python
"""
Tool for decrypting VIM encrypted files

Copyright (C) 2016 Willem Hengeveld <itsme@xs4all.nl>

"""
from __future__ import division, print_function
import sys
import struct
from binascii import b2a_hex, a2b_hex
from Crypto.Hash import SHA256

"""
VIM can encrypt text files transparently.
select the mode using 'set cryptmethod={zip, blowfish, blowfish2}'
and set the key using 'set key=<secret>'

Or from the commandline using: 'vim -x yourfile.txt'

"""


def wordswap(data):
    """ Swap byte order in each DWORD """
    fmt = '%dL' % ((len(data)+3)/4)
    pad = len(data)%4
    if pad:
        pad = 4-pad
        data += b"\x00" * pad
    return struct.pack('<'+fmt, *struct.unpack('>'+fmt, data))


def sha256(data, salt):
    """ Return sha256 digest of data + salt """
    h = SHA256.new()
    h.update(data)
    h.update(salt)
    return h.digest()


def hashpw(password, salt):
    """ Convert password to cipher key """
    key = sha256(password, salt)
    for _ in range(1000):
        key = sha256(b2a_hex(key), salt)
    return key


class BrokenCFB(object):
    """
    CFB wrapper used for bf1 mode.
    
    The problem here is that the first 64 bytes are all encrypted using the same IV.
    Effectively changing BF1 in a very weak fixed-key xor obfuscator.
    So when the first 64 bytes contain several 8 byte blocks with identical plain text,
    this will result in those blocks being encrypted into identical ciphertext.
    Which in turn will cause the same thing to happen for the next 64 bytes.

    You can see this when encrypting a file with a single line containing all
    the same characters. The encrypted file will look very repetitive.

    plain[i] = cipher[i] ^ encrypt(cipher[i-8])
    cipher[-8..-1] = iv
    """
    def __init__(self, cipher, iv):
        self.cipher = cipher
        self.iv = iv

    def decrypt(self, data):
        plain = bytearray()
        xor = self.cipher.encrypt(self.iv)
        for o in range(len(data)):
            if o>=64 and (o%8)==0:
                xor = self.cipher.encrypt(data[o-64:o-64+8])
            plain.append( xor[o%8] ^ data[o] )
        return plain


class GoodCFB(object):
    """
    CFB wrapper used for bf2.
    
    plain[i] = cipher[i] ^ encrypt(cipher[i-1])
    cipher[-1] = iv

    """
    def __init__(self, cipher, iv):
        self.cipher = cipher
        self.iv = iv

    def decrypt(self, data):
        plain = bytearray()
        xor = None
        for o in range(len(data)):
            if (o%8) == 0:
                xor = self.cipher.encrypt(self.iv)
                self.iv = data[o:o+8]
            plain.append( xor[o%8] ^ data[o] )
        return plain


def makeblowfish(args, key):
    """ Create blowfish cipher """
    if args.pycrypto:
        # either using pycrypto
        from Crypto.Cipher import Blowfish
        ecb = Blowfish.new(key, mode=Blowfish.MODE_ECB)
        # convert to little endian
        original_encrypt = ecb.encrypt
        ecb.encrypt = lambda data: bytearray(wordswap(original_encrypt(wordswap(data))))
    else:
        # or using pure python(3) blowfish module
        import blowfish
        ecb = blowfish.Cipher(key, byte_order="little")
        # make pyCrypto compatible
        ecb.encrypt = lambda data: bytearray(b''.join(ecb.encrypt_ecb(data)))
    return ecb


def makecfb(ver, ecb, iv):
    """ Creates CFB wrapper for bf1 or bf2 """
    if ver == "bf1":
        return BrokenCFB(ecb, iv)
    else:
        return GoodCFB(ecb, iv)


def bf_decrypt(ver, data, pw, args):
    """
    Handles blowfish and blowfish2 cryptmethods.

    There is a bug in the vim CFB implementation for the blowfish method,
    which causes the first 8 cipher blocks to be all encrypted with the same IV.
    """
    salt = data[0:8]
    iv = data[8:16]
    data = data[16:]

    if args.verbose:
        print("salt = ", b2a_hex(salt))
        print("seed = ", b2a_hex(iv))
        print("data = ", b2a_hex(data[:16]))

    key = hashpw(pw.encode("utf-8"), salt)
    if args.verbose:
        print("hashed key =", b2a_hex(key))

    cfb = makecfb(ver, makeblowfish(args, key), iv)
    return cfb.decrypt(bytearray(data))


def bf_test(args):
    """ This is the test which VIM runs prior to using it's encryption routines """
    pw = b"password"
    salt = b"salt"
    plain = b"plaintxt"
    littleendian = a2b_hex(b"ad3dfa7fe8ea40f6")
    bigendian = a2b_hex(b"72503b38106022a7")
    key = hashpw(pw, salt)
    print("test key =", b2a_hex(key))

    ecb = makeblowfish(args, key)
    crypted = ecb.encrypt(plain)

    if crypted == littleendian:
        print("ok - little endian bf")
    elif crypted == bigendian:
        print("ok - big endian bf")
    else:
        print("unknown crypt -> ", b2a_hex(crypted))


def zip_decrypt(data, pw):
    """
    The very weak 'zip' encryption

    This encryption can be cracked using tools like pkcrack.
    Pkcrack does a known plaintext attack, requiring 13 bytes of plaintext.
    """
    def make_crc_tab(poly):
        def calcentry(v, poly):
            for _ in range(8):
                v = (v>>1) ^ (poly if v&1 else 0)
            return v
        return [ calcentry(byte, poly) for byte in range(256) ]

    crctab = make_crc_tab(0xedb88320)

    def crc32(crc, byte):
        return crctab[(crc^byte)&0xff] ^ (crc>>8)

    def updatekeys(keys, byte):
        keys[0] = crc32(keys[0], byte)
        keys[1] = (keys[1] + (keys[0]&0xFF))&0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1)&0xFFFFFFFF
        keys[2] = crc32(keys[2], keys[1]>>24)

    keys = [ 305419896, 591751049, 878082192 ]
    for c in pw:
        updatekeys(keys, ord(c))

    plain = bytearray()
    for b in bytearray(data):
        xor = (keys[2] | 2)&0xFFFF
        xor = ((xor * (xor^1))>>8) & 0xFF
        b = b ^ xor
        plain.append(b)
        updatekeys(keys, b)
    return plain


def decryptfile(data, args):
    """ Determine cryptmethod, decrypt and print to stdout """
    if data[0:12] == b"VimCrypt~01!":
        plain = zip_decrypt(data[12:], args.password)
    elif data[0:12] == b"VimCrypt~02!":
        plain = bf_decrypt("bf1", data[12:], args.password, args)
    elif data[0:12] == b"VimCrypt~03!":
        plain = bf_decrypt("bf2", data[12:], args.password, args)
    else:
        print("unknown vim crypt type: ", b2a_hex(data[:12]))
        return
    print(plain.decode("utf-8"))


def main():
    import argparse
    parser = argparse.ArgumentParser(description='vimdecrypt')
    parser.add_argument('--test', action='store_true', help='run vim selftest')
    parser.add_argument('--pycrypto', action='store_true', help='Use PyCrypto library blowfish')
    parser.add_argument('--verbose', '-v', action='store_true', help='print details about keys etc.')
    parser.add_argument('--password', '-p', type=str, help='Decrypt using password')
    parser.add_argument('files', nargs='*', type=str)

    args = parser.parse_args()

    if not args.pycrypto and sys.version_info[0] == 2:
        print("pure python blowfish requires python3")
        return 1

    if args.test:
        bf_test(args)
        return

    for fn in args.files:
        if len(args.files) > 1:
            print("==>", fn, "<==")

        with open(fn, "rb") as fh:
            data = fh.read()
            decryptfile(data, args)
    return 0

if __name__ == '__main__':
    sys.exit(main())
