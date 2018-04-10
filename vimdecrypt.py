#!/usr/bin/env python
"""
Tool for decrypting VIM encrypted files

Copyright (C) 2016 Willem Hengeveld <itsme@xs4all.nl>

VIM can encrypt text files transparently.
select the mode using 'set cryptmethod={zip, blowfish, blowfish2}'
and set the key using 'set key=<secret>'

Or from the commandline using: 'vim -x yourfile.txt'

This tool can decrypt files saved by vim, without using vim.

"""
from __future__ import division, print_function
import sys
import struct
from binascii import b2a_hex, a2b_hex
from Crypto.Hash import SHA256
import zlib
import codecs
import time
import getpass

def SaveAsZip(zipname, filename, filedata):
    """ Create a PKZIP file containing the zip encrypted vim text,
        suitable for use with the known plaintext attack tool pkcrack
    """
    def LocalFileHeader(name, size):
        """ create the PKZIP local fileheader """
        utf8name = name.encode("utf-8")
        neededVersion = 10
        flags = 9        # bit0 = encrypted, bit4 = enhdefl(?)
        method = 0       # stored
        timestamp = 0
        crc32 = 0
        compressedSize = size
        originalSize = size-12
        nameLength = len(utf8name)
        extraLength = 0
        return b"PK\x03\x04" + struct.pack("<3H4LHH", neededVersion, flags, method, timestamp, crc32, compressedSize, originalSize, nameLength, extraLength) + utf8name
    
    def DirEntry(name, size):
        """ create the PKZIP directory entry """
        utf8name = name.encode("utf-8")
        createVersion = 798
        neededVersion = 10
        flags = 9
        method = 0
        timestamp = 0
        crc32 = 0
        compressedSize = size
        originalSize = size-12
        nameLength = len(utf8name)
        extraLength = 0
        commentLength = 0
        diskNrStart = 0
        zipAttrs = 0
        osAttrs = 0
        dataOfs = 0
        return b"PK\x01\x02" + struct.pack("<4H4L5HLL", createVersion, neededVersion, flags, method, timestamp, crc32, compressedSize, originalSize, nameLength, extraLength, commentLength, diskNrStart, zipAttrs, osAttrs, dataOfs) + utf8name
    def EndofZip(dirSize, dirOfs):
        """ create the PKZIP end of file marker """
        thisDiskNr = 0
        startDiskNr = 0
        thisEntries = 1
        totalEntries = 1
        commentLength = 0
        return b"PK\x05\x06" + struct.pack("<4HLLH", thisDiskNr, startDiskNr, thisEntries, totalEntries, dirSize, dirOfs, commentLength)

    with open(zipname, "wb") as fh:
        lfh = LocalFileHeader(filename, len(filedata)+12)
        dent = DirEntry(filename, len(filedata)+12)
        eoz = EndofZip(len(dent), len(lfh)+len(filedata)+12)

        fh.write(lfh)
        fh.write(b'\x00' * 12)
        fh.write(filedata)
        fh.write(dent)
        fh.write(eoz)


def wordswap(data):
    """ Swap byte order in each DWORD """
    fmt = '%dL' % ((len(data)+3)/4)
    pad = len(data) % 4
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
    from Crypto.Cipher import Blowfish
    ecb = Blowfish.new(key, mode=Blowfish.MODE_ECB)
    # convert to little endian
    original_encrypt = ecb.encrypt
    ecb.encrypt = lambda data: bytearray(wordswap(original_encrypt(wordswap(data))))

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


def zip_decrypt(data, pw, args):
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
        keys[1] = ((keys[1] + (keys[0]&0xFF)) * 134775813 + 1)&0xFFFFFFFF
        keys[2] = crc32(keys[2], keys[1]>>24)

    keys = [ 0x12345678, 0x23456789, 0x34567890 ]
    for c in pw:
        updatekeys(keys, ord(c))

    if args.verbose:
        print("keys: %08x %08x %08x" % tuple(keys))

    plain = bytearray()
    for b in bytearray(data):
        xor = (keys[2] | 2)&0xFFFF
        xor = ((xor * (xor^1))>>8) & 0xFF
        b = b ^ xor
        plain.append(b)
        updatekeys(keys, b)
    return plain


def decryptfile(data, password, args):
    """ Determine cryptmethod, decrypt and print to stdout """
    if data[0:12] == b"VimCrypt~01!":
        return zip_decrypt(data[12:], password, args)
    elif data[0:12] == b"VimCrypt~02!":
        return bf_decrypt("bf1", data[12:], password, args)
    elif data[0:12] == b"VimCrypt~03!":
        return bf_decrypt("bf2", data[12:], password, args)
    elif data[0:9] == b"VimCrypt~":
        raise Exception("Unsupported VimCrypt method %s" % data[0:12])
    else:
        raise Exception("Not a VimCrypt file")


def dictionary_words(dictfile, args):
    """ read words, one per line from the given file, or STDIN """
    for password in sys.stdin if dictfile=="-" else open(dictfile, "r"):
        yield password.rstrip("\r\n")


def bruteforce_generator(args):
    """ Generate all 1, 2, 3, .. 10 letter words """

    def incpw(pw):
        i = 0
        while i<len(pw) and pw[i]=='z':
            pw[i] = 'a'
            i += 1
        if i==len(pw):
            return False
        pw[i] = chr(ord(pw[i])+1)
        return True

    for l in range(1,10):
        pw = [ 'a' for _ in range(l) ]
        while True:
            yield "".join(pw)
            if not incpw(pw):
                break


def looks_like_text(data):
    """
    Heuristic for determining if we have plaintest:
    if the compression ration if larger than 1.1 we assume text
    """
    if sys.version_info[0] == 2:
        data = str(data)
    comp = zlib.compress(data, 1)

    return len(data) >= len(comp)-6


def password_cracker(data, args):
    """ run bruteforce or dictionary attack """
    data = data[:1024]
    pwgen = dictionary_words(args.dictionary, args) if args.dictionary else bruteforce_generator(args)

    t0 = time.clock()
    count = 0
    for password in pwgen:
        result = decryptfile(data, password, args)
        if looks_like_text(result):
            lines = result.split(b"\n", 5)
            print("probable password: %s" % password)
            print("---------")
            print(b"\n".join(lines[:4]).decode("utf-8", errors='ignore'))
            print("---------")
        count += 1
        if (count%1000)==0:
            print("%8d passwords tried, %d passwords per second" % (count, count/(time.clock()-t0)))


def main():
    import argparse
    parser = argparse.ArgumentParser(description='vimdecrypt')
    parser.add_argument('--test', action='store_true', help='run vim selftest')
    parser.add_argument('--verbose', '-v', action='store_true', help='print details about keys etc.')
    parser.add_argument('--debug', action='store_true', help='abort on exceptions.')
    parser.add_argument('--password', '-p', type=str, help='Decrypt using password')
    parser.add_argument('--encoding', '-e', type=str, help='Specify alternate text encoding', default='utf-8')
    parser.add_argument('--writezip', '-w', action='store_true', help='Save zip encrypted data to a .zip file for cracking')
    parser.add_argument('--dictionary', '-d', type=str, help='Dictionary attack, pass filename or - for STDIN')
    parser.add_argument('--bruteforce', '-b', action='store_true', help='Bruteforce attack')
    parser.add_argument('files', nargs='*', type=str)

    args = parser.parse_args()

    if args.test:
        bf_test(args)
        return

    count = 0
    for fn in args.files:
        try:
            if len(args.files) > 1:
                print("==>", fn, "<==")

            if args.password is None and not args.dictionary and not args.bruteforce:
                args.password = getpass.getpass()

            with open(fn, "rb") as fh:
                data = fh.read()
                if args.writezip:
                    if data[0:12] == b"VimCrypt~01!":
                        SaveAsZip("for_pkcrack-%d.zip" % count, fn, data[12:])
                if args.dictionary or args.bruteforce:
                    password_cracker(data, args)
                elif args.password is None:
                    print("must specify a password")
                else:
                    plain = decryptfile(data, args.password, args)
                    if plain:
                        if args.encoding == "hex":
                            print(b2a_hex(plain))
                        else:
                            print(plain.decode(args.encoding))
            count += 1
        except Exception as e:
            print("EXCEPTION %s" % e)
            if args.debug:
                raise
    return 0


if __name__ == '__main__':
    sys.exit(main())
