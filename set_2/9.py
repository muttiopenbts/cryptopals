'''
Typical use:
Pad plaintext message using pkcs#7
python 9.py -m'ABC' -s 16
'ABC\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d'
'''
from __future__ import print_function
from pwn import *
# Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *
import binascii
import enchant
import sys
from optparse import OptionParser
import string
import itertools
import operator
script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_path, '..','libs'))
import common
from Crypto.Cipher import AES
from collections import Counter


def set_padding(plaintext, key_size):
    key_size = int(key_size)
    padded_message = '' # padded message to return

    if key_size > 256:
        raise Exception('PKCS#7 restricts padding to no greater than 256')
    elif key_size > len(plaintext):
        size_diff = key_size - len(plaintext)
        padded_message = '{}{}'.format(plaintext, chr(size_diff) * size_diff)
    elif key_size == len(plaintext):
        padded_message = plaintext
    else:
        raise Exception('Plaintext larger than keysize')
    return padded_message

def main(options,args):
    # Read command line parameters
    plaintext = options.plaintext
    key_size = options.key_size
    print ('Plaintext: {}'.format(plaintext))
    print ('Key size: {}'.format(key_size))
    padded_message = set_padding(plaintext, key_size)
    hexdump(padded_message)

if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-m",
        dest="plaintext",
        help="Plaintext message to pad")
    parser.add_option(
        "-s",
        dest="key_size",
        help="Key size, where by message will have pkcs#7 bytes padded upto")

    (options, args) = parser.parse_args()

    main(options,args)
