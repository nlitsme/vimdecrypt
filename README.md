VimDecrypt
==========

Tool for decrypting VIM encrypted files.

Dependencies:
 * [pycrypto](https://pypi.python.org/pypi/pycrypto)

vimdecrypt should work with both python2 and python3.


Usage:

    python vimdecrypt.py -p PASSWORD yourfile.txt

Or with dictionary:

    python vimdecrypt.py --dictionary /usr/share/wordlists/rockyou.txt yourfile.txt


| option             | description
|:------------------ |:-------------------------
| --test             | run vim selftest
| --verbose          | print details about keys etc.
| --password PASSWD  | use PASSWD to decrypt the specified files
| --encoding ENC     | use an alternate encoding ( default = utf-8, example: latin-1, hex )
| --writezip         | create PKCRACKable .zip file from VimCrypt file
| --dictionary DICT  | try all words from DICT as password
| --bruteforce       | try all lowercase passwords


A second tool will decrypt the swap file:

    python vimswap.py -p PASSWORD .yourfile.txt.swp


VIM
===

VIM can encrypt text files transparently.
Select the mode using 'set cryptmethod={zip, blowfish, blowfish2}'
and set the key using 'set key=<secret>'

Beware when entering the wrong password, VIM wil happily open the file for you.
And display nonsense content.
When you now save this again, it will be quite difficult to recover the original file.

You can retry the password by either quitting and reloading vim, or by typing:

    :bdel | edit #

in VIM. ([from](http://stackoverflow.com/questions/22353221/not-able-to-recover-vim-encrypted-file-after-set-key))


The encryption methods
======================

    command: set cryptmethod=zip
    header: VimCrypt~01!

Uses the same algorithm as the old PKZIP program.
There is a tool called pkcrack which does a known plaintext attack
on zip files encrypted using this algorithm.

By wrapping the VimCrypt file in a .zip file you can crack this
using [PKCRACK](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html).
The `-w` option of `vimdecrypt.py` creates a PKCRACKable .zip archive from a given VimCrypt file.

Note: there exists a tool [vimzipper.c](http://pastebin.com/7gKp6P3J) by Richard Jones, which
can also do this.


    command: set cryptmethod=blowfish
    header: VimCrypt~02!

Uses blowfish in little-endian mode, using Cipher Feedback Mode, but with a bug because of which the first 8 blocks all use the same IV.


    command: set cryptmethod=blowfish2
    header: VimCrypt~03!

Uses blowfish in little-endian mode, this time with a correct Cipher Feedback Mode implementation.


Both blowfish methods use 1000 iterations of a salted sha256 of the password.
The undo and swap are also encrypted when editing an encrypted file.


Security problems
=================

ZIP
---

The `zip` method is very weak, you need 13 bytes of plaintext to find the key.

Blowfish / bf1
--------------

The `bf1` method is problematic for short files. 
The problem is that the first 8 blocks all use the same `IV`, so:

    enc(block1) XOR enc(block2) == block1 XOR block2

This leaks lots of information which can be used to guess the contents
of the first 64 bytes.

Blowfish2 / bf2
---------------

The `bf2` method does not have the broken CFB problem, but 
since it is using `CFB` without any checksum, an attacker can modify
the last block of the encrypted text without the user noticing.

Blowfish though not really insecure, is quite old. Better ciphers, like AES,
or Twofish have been designed since 1993.

password hashing
----------------

The `ZIP` cipher uses it's own weak hashing algorithm.
With the `bf1` and `bf2` methods, the user password is hashed 1000 times using sha256.
This does make bruteforcing a bit more difficult, but still, this method is easily accelerated
using FPGA or GPU crackers.
Better would be to use a hashing algorithm which is difficult in both time and space, like
`PBKDF2`, or `scrypt`.

Password cracking
=================

`vimdecrypt.py` can do some simple password cracking, either by dictionary, or bruteforce.
Note that this all done in python, and not very fast:

| algorithm | speed  |  notes
|:---- | -----------:|:----
|  zip | 650 pw/sec  |
|  bf2 | 300 pw/sec  | python2, pycrypto
|  bf2 | 180 pw/sec  | python3, pycrypto

Example:

    python3 vimdecrypt.py -d words.txt  encrypted.txt

or 

    python3 vimdecrypt.py -b encrypted.txt


You can also use a word generator like [John the Ripper](http://www.openwall.com/john/), and pipe the wordlist
to stdin of `vimdecrypt.py`, and specify `-` for the wordlist.

Like this:

    john --wordlist=words.txt --rules --stdout | python3 vimdecrypt.py -d - encrypted.txt


For bruteforce cracking you need some kind of heuristic to tell if the decryption was successful.
Since encrypted data will generally compress really badly, while text compresses very well,
this is what i test against in `vimdecrypt`.

Note that unlike .zip files, VIM does not store the CRC of the original file, so you can't use that to
validate the success of the decryption.


swapfile
========

When you first type/insert text in an empty file, and then set the encryption key, the swapfile will
be unencrypted until you actually save the file.

If you first set the encryption key, then the swapfile will be encrypted immediately.


TODO
====

 * Add decryptor for encrypted .swp files
 * bug: wordlist from STDIN works only with one file.


SIMILAR PROJECTS
================

 * [vimdecrypt](https://github.com/gertjanvanzwieten/vimdecrypt) by gertjanvanzwieten - only handles blowfish2 method
 * [node-vim-blowfish](https://github.com/stelcheck/node-vim-blowfish) by stelcheck - in perl, but not working according to it's readme.
 * [emacs-vimcryot](https://github.com/wert310/emacs-vimcrypt) by wert310 - an emacs plugin
 * [crackvim](https://github.com/wjlandryiii/crackvim) by wjlandryiii - a bruteforce cracker
 * [vimdecrypt](https://github.com/EaterOA/vimdecrypt) - by EaterOA - unfinished code
 * [vim72bf](https://github.com/xenocons/vim72bf) - by xenocons
 * [vim-blowfish](https://github.com/nowox/vim-blowfish) - by nowox
 * [vcm](https://github.com/AlexAtNet/vcm) - by AlexAtNet, in go
 * [vimcrypt.py](https://gist.github.com/amtal/d482a2f8913bc6e2c2e0) - gist


AUTHOR
======

Willem Hengeveld <itsme@xs4all.nl>

