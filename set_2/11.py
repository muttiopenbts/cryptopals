'''
sh-3.2$ echo "YELLOW SUBMARINE" |xxd
00000000: 5945 4c4c 4f57 2053 5542 4d41 5249 4e45  YELLOW SUBMARINE

Typical use:
$ python 10.py -m d -k '59454c4c4f57205355424d4152494e45' -i '00000000000000000000000000000000' -f 10.txt
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
from collections import Counter
import common_crypt
import random
from Crypto.Cipher import AES


def main(options,args):
    # Going to prepend and append 5-10 random bytes before and after plaintext
    rand_prepend = common_crypt.get_random_byte_string(random.randrange(5,11))
    rand_append = common_crypt.get_random_byte_string(random.randrange(5,11))
    plaintext = rand_prepend + options.plaintext + rand_append
    mode = options.mode
    key = common_crypt.get_random_byte_string(16)
    key_size = len(key)
    message_size = len(plaintext)

    if mode == 'e': # Encrypt
        hexdump(plaintext)
        print ('Plaintext size: {}'.format(len(options.plaintext)))
        print ('Key size: {}'.format(key_size))
        print ('Message size: {}'.format(message_size))
        print ('Key: {}'.format(key.encode('hex')))
        if random.randrange(1,3) == 1: # Do ecb mode
            print ('Using ECB mode')
            # AES object. Will be used multiple times
            encobj = AES.new(key, AES.MODE_ECB)
            plaintext = common_crypt.set_padding(plaintext,key_size)
            print ('Plaintext with padding')
            hexdump(plaintext)
            cipher_text = encobj.encrypt(plaintext)
            print ('Cipher text size: {}'.format(len(cipher_text)))
        else: # do cbc mode
            iv = common_crypt.get_random_byte_string(16)
            print ('IV: {}'.format(iv.encode('hex')))
            print ('Using CBC mode')
            plaintext = common_crypt.set_padding(plaintext,key_size)
            print ('Plaintext with padding')
            hexdump(plaintext)
            cipher_text = common_crypt.aes_cbc_encrypt(plaintext, key, iv)
            print ('Cipher text size: {}'.format(len(cipher_text)))

        hexdump(cipher_text)
        # Did we detect ecb mode?
        ecb_detected = common_crypt.is_ecb_mode(cipher_text,key_size)
        if ecb_detected:
            print ('We may have detected ecb mode here: {}'.format(ecb_detected))

    else: # decrypt mode
        # Read command line parameters
        filename = options.challenge_filename

        # Actual challenge
        # Read entire file and base64 decode
        with open(filename, 'r') as challenge_file:
            challenge_file_contents = challenge_file.read()
        # We should now have a copy of the raw cipher text
        decoded_b64_challenge = b64d(challenge_file_contents)


        print ('File name: {}'.format(filename))
        print ('Key size: {}'.format(key_size))
        print ('Key: {}'.format(key.encode('hex')))
        print ('IV: {}'.format(iv.encode('hex')))
        print ('Mode: {}'.format(mode))
        plaintext = aes_cbc_decrypt(decoded_b64_challenge, key, iv)
        print(plaintext)


if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-f",
        "--file",
        dest="challenge_filename",
        help="file to decrypt. Expected file format is base64")
    parser.add_option(
        "-p",
        dest="plaintext",
        help="Plaintext message to encrypt")
    parser.add_option(
        "-m",
        dest="mode",
        help="Mode [e|d] encrypt or decrypt")

    (options, args) = parser.parse_args()

    main(options,args)
