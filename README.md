VimDecrypt
==========

Tool for decrypting VIM encrypted files.

Dependencies:
 * [pycrypto](https://pypi.python.org/pypi/pycrypto)

vimdecrypt should work with both python2 and python3.


Usage:

   python vimdecrypt.py -p PASSWORD yourfile.txt

| option             | description
|:------------------ |:-------------------------
| --test             | run vim selftest
| --verbose          | print details about keys etc.
| --password PASSWD  | use PASSWD to decrypt the specified files
| --encoding ENC     | use an alternate encoding ( default = utf-8, example: latin-1, hex )
| --writezip         | create PKCRACKable .zip file from VimCrypt file
| --dictionary DICT  | try all words from DICT as password
| --bruteforce       | try all lowercase passwords


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


Password cracking
=================

`vimdecrypt.py` can do some simple password cracking, either by dictionary, or bruteforce.
Note that this all done in python, and not very fast:

| algorithm | speed  |  notes
|:---- | -----------:|:----
|  zip | 650 pw/sec  |
|  bf2 | 300 pw/sec  | python2, pycrypto
|  bf2 | 180 pw/sec  | python3, pycrypto


You can also use a word generator like [John the Ripper](http://www.openwall.com/john/), and pipe the wordlist
to stdin of `vimdecrypt.py`, and specify `-` for the wordlist.


TODO
====

 * Add decryptor for encrypted .swp files
 * bug: wordlist from STDIN works only with one file.


AUTHOR
======

Willem Hengeveld <itsme@xs4all.nl>

