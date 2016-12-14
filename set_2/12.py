'''
Typical use:
python 12.py
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
import subprocess


'''
'''
def do_ecb_byte_decryption(plaintext,key):
    guessed_block_size = do_guess_ecb_block_size(plaintext,key)
    plaintext_size = len(plaintext)
    ''' 
    custome_block size = 8
    unknown_message size = 8
    Custom block-1 + unknown_message
    'AAAAAAAA'
    '12345678'
    test_case = 'AAAAAAA'+'1'+'2345678'+'01'           
    '''
    guessed_unknown_message_hexstring = ''

    while len(plaintext) / float(guessed_block_size) > 0:
        guessed_unknown_message_hexstring_block = ''
        for block_size in reversed(range(0,guessed_block_size)): # Create list [15,14...0]
            custom_base_block = 'A' * block_size # This block will decrease in size with each correct match
            custom_block = custom_base_block + unhex(guessed_unknown_message_hexstring_block)
            guessed_blocks = [custom_block+str(chr(guessed_byte)) for guessed_byte in range(0,256)]
            for guessed_block in guessed_blocks:
                # If we have hit the correct guessed block then we should detect ecb mode because duplicate blocks
                #hexdump(guessed_block + custom_base_block + plaintext)
                bruteforce_guess = common_crypt.aes_128_ecb(guessed_block + custom_base_block + plaintext, key)
                if common_crypt.is_ecb_mode(bruteforce_guess):
                    guessed_unknown_message_hexstring_block += chr(guessed_blocks.index(guessed_block)).encode('hex')
                    #print(guessed_unknown_message_hexstring_block)
                    break
        guessed_unknown_message_hexstring += guessed_unknown_message_hexstring_block
        plaintext = plaintext[guessed_block_size:]
    return unhex(guessed_unknown_message_hexstring)


'''
This is an exercise to detect the block size used in aes ecb encryption.
'''
def do_guess_ecb_block_size(plaintext,key):
    BYTE = 8
    MULTIPLES = 32 / BYTE # bits
    MIN_KEY_SIZE =  128 / BYTE  # bits. aes spec
    MAX_KEY_SIZE = 256 / BYTE  # bits. aes spec
    MIN_BLOCK_SIZE  = 128 / BYTE
    MAX_BLOCK_SIZE  = 256 / BYTE # Not sure this is allowed in aes spec

    for guessed_block_size in range(MIN_BLOCK_SIZE, (MAX_BLOCK_SIZE + 1)*2):
        guessed_block = 'A'*guessed_block_size
        message = guessed_block + plaintext
        cipher_text = common_crypt.aes_128_ecb(message, key)

        if common_crypt.is_ecb_mode(cipher_text):
            guessed_block_size = guessed_block_size / 2
            print ('AES ECB mode detected and block size is {}'.format(guessed_block_size))
            return guessed_block_size


def main(options,args):
    BYTE = 8
    KEY_SIZE = 128 / BYTE # bits
    ''' unknown_string to be append to plaintext and we need to figure out its contents'''
    unknown_string = b64d('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    plaintext = unknown_string
#    if not options.plaintext: # Did user specify plaintext?
#        plaintext = common.get_random_sentences(48)
#    else:
#        plaintext = options.plaintext


    key = common_crypt.get_random_byte_string(KEY_SIZE)
    key_size = len(key)
    message_size = len(plaintext)

    print ('Sending uknown message to ecb byte decryptor')
    #hexdump(plaintext)
    print ('Plaintext size: {}'.format(len(plaintext)))
    print ('Key size: {}'.format(key_size))
    print ('Message size: {}'.format(message_size))
    print ('Key: {}'.format(key.encode('hex')))

    guessed_unknown = do_ecb_byte_decryption(plaintext,key)

    if guessed_unknown:
        print ('Decipher uknown message is:')
        hexdump(guessed_unknown)


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

    (options, args) = parser.parse_args()

    main(options,args)
