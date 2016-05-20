VimDecrypt
==========

Tool for decrypting VIM encrypted files.

Dependencies:
 * either [pycrypto](https://pypi.python.org/pypi/pycrypto)
 * or [blowfish](https://pypi.python.org/pypi/blowfish/) -- a pure python 3.x implementation of blowfish.

vimdecrypt should work with both python2 and python3.


Usage:

   python vimdecrypt.py -p PASSWORD [--pycrypto] yourfile.txt


VIM
===

VIM can encrypt text files transparently.
select the mode using 'set cryptmethod={zip, blowfish, blowfish2}'
and set the key using 'set key=<secret>'


The encryption methods
======================

    command: set cryptmethod=zip
    header: VimCrypt~01!

Uses the same algorithm as the old PKZIP program.
There is a tool called pkcrack which does a known plaintext attack
on zip files encrypted using this algorithm.

I think that to be able to use pkcrack on vim files, you would need
to manually construct a zip file around the vim encrypted bytes.
I have not tried, but i think it would work.


    command: set cryptmethod=blowfish
    header: VimCrypt~02!

Uses blowfish in little-endian mode, using Cipher Feedback Mode, but with a bug because of which the first 8 blocks all use the same IV.


    command: set cryptmethod=blowfish2
    header: VimCrypt~03!

Uses blowfish in little-endian mode, this time with a correct Cipher Feedback Mode implementation.


Both blowfish methods use 1000 iterations of a salted sha256 of the password.
The undo and swap are also encrypted when editing an encrypted file.


TODO
====

Add decryptor for encrypted .swp files


AUTHOR
======

Willem Hengeveld <itsme@xs4all.nl>

