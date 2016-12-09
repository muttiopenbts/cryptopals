'''
Typical use:
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


'''
Simple xor wrapper.
param message and iv must match size.
Expect message and iv to be byte stream. e.g. ('ABC','\x04\x05\x06')
'''
def get_iv_xor(message, iv):
    if len(message) != len(iv):
        raise Exception('Message and IV mismatch length {} {}'.format(len(message),len(iv)))
    else:
        return xor(message,iv)


'''
Encrypt message using AES in cbc mode.
Params message, key, and iv expect to be byte stream format. e.g. ('AA','ZW','\x03\x22')
Returns cipher text.
'''
def aes_cbc_encrypt(message, key, iv):
    ciphertext = ''
    key_size = len(key)

    for block in common.grouper(message,key_size,fillvalue='\x00'):
        block = ''.join(block) # Convert grouper array into byte string
        ciphertext_cbc = do_aes_cbc_encrypt_chain(block, key, iv)
        iv = ciphertext_cbc
        ciphertext += ciphertext_cbc

    return ciphertext


'''
Decrypt message using AES in cbc mode.
Params cipher text, key, and iv expect to be byte stream format. e.g. ('AA','ZW','\x03\x22')
Returns plain text.
'''
def aes_cbc_decrypt(message, key, iv):
    key_size = len(key)
    round = 0
    previous_cipher_block = ''
    plaintext = ''

    for cipher_block in common.grouper(message,key_size,fillvalue='\x00'):
        cipher_block = ''.join(cipher_block) # Convert grouper array into byte string

        # First round of chain uses the specified iv instead of previous decrypted block
        if round == 0:
            plaintext_block = do_aes_cbc_decrypt_chain(cipher_block, key, iv)
        else:
            iv = previous_cipher_block
            plaintext_block = do_aes_cbc_decrypt_chain(cipher_block, key, iv)

        previous_cipher_block = cipher_block # This is needed for next round iv
        plaintext += plaintext_block
        round += 1

    return plaintext


'''
Perform a single chain round for aes_cbc_encrypt mode.
A single aes cbc round consists of, aes_ecb(xor(pt,iv), key)
'''
def do_aes_cbc_encrypt_chain(message, key, iv):
    # AES object. Will be used multiple times
    encobj = AES.new(key, AES.MODE_ECB)

    message = get_iv_xor(message,iv)
    message = encobj.encrypt(message)
    return message


'''
Perform a single chain round for aes_cbc_decrypt mode.
A single aes cbc round consists of, xor(aes_ecb(cipher, key),iv)
'''
def do_aes_cbc_decrypt_chain(message, key, iv):
    # AES object. Will be used multiple times
    encobj = AES.new(key, AES.MODE_ECB)

    message = encobj.decrypt(message)
    message = get_iv_xor(message,iv)
    return message


def main(options,args):
    # Read command line parameters
    filename = options.challenge_filename
    plaintext = options.plaintext
    mode = options.mode
    iv = unhex(options.iv)
    key = unhex(options.key)
    key_size = len(key)

    if mode == 'e':
        print ('Plaintext: {}'.format(plaintext))
        print ('Key size: {}'.format(key_size))
        print ('Key: {}'.format(key.encode('hex')))
        print ('IV: {}'.format(iv.encode('hex')))
        cipher_text = aes_cbc_encrypt(plaintext, key, iv)
        hexdump(cipher_text)
    else: # decrypt mode
        # Read command line parameter specifying challenge file
        challenge_filename = options.challenge_filename

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
        "-k",
        dest="key",
        help="CBC Key in hexstring format")
    parser.add_option(
        "-i",
        dest="iv",
        help="IV in hexstring format")
    parser.add_option(
        "-m",
        dest="mode",
        help="Mode [e|d] encrypt or decrypt")

    (options, args) = parser.parse_args()

    main(options,args)
