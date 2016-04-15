VimDecrypt
==========

Tool for decrypting VIM encrypted files.

Dependencies:
 * either [pycrypto](https://pypi.python.org/pypi/pycrypto)
 * or [blowfish](https://pypi.python.org/pypi/blowfish/) -- a pure python implementation of blowfish.

vimdecrypt should work with both python2 and python3.


Usage:

   python vimdecrypt.py -p PASSWORD [--pycrypto] yourfile.txt


Willem Hengeveld <itsme@xs4all.nl>

