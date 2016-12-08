'''
Typical use:
python 8.py -f 8.txt
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


def main(options,args):
    # Read command line parameter specifying challenge file
    challenge_filename = options.challenge_filename
    key_size = 16
    print ('Key size: {}'.format(key_size))
    ecb_match = {'score':0,'ciphertext':''}

    # Read file line by line
    with open(challenge_filename, 'r') as challenge_file:
        file_line_number = 1
        # Iterate over lines of file representing new ciphertext
        for ciphertext in challenge_file:
            # Total for all matched bytes in entire cipher text
            ct_total_matched_bytes = 0
            print('Checking cipher {}'.format(file_line_number))
            file_line_number += 1
            print (ciphertext)
            ciphertext = unhex(ciphertext.rstrip())
            # Bunch up bytes encrypted with same byte key into groups
            blocks_of_cipher = common.convert_bytes_to_key_blocks(ciphertext, key_size)

            block_position = 1
            matched_bytes_list = []
            # Get count of bytes that match. We are looking for bytes that have been enc using same key
            for single_byte_xor_block in blocks_of_cipher:
                separated_bytes = list(single_byte_xor_block)
                # Get count of all similar bytes
                matched_bytes = [{byte:count} for byte,count in Counter(separated_bytes).items() if count>1]
                if matched_bytes:
#                    print (matched_bytes)
                    matched_bytes_list.append(matched_bytes)

                # Total up all match bytes for single byte key
                total_bytes_match = sum([count for byte in matched_bytes for count in byte.values()])
                ct_total_matched_bytes += total_bytes_match
                print ('Comparing single byte key block {} for dups. Total: {}'.format(block_position, total_bytes_match))
                block_position += 1

            print ('Number of cipher blocks with match were {}, and total matched bytes {}'.format(len(matched_bytes_list),ct_total_matched_bytes))

            if ct_total_matched_bytes > ecb_match['score']:
                ecb_match['score'] = ct_total_matched_bytes
                ecb_match['ciphertext'] = file_line_number
        print ('Best score {}'.format(ecb_match))

if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-f",
        "--file",
        dest="challenge_filename",
        help="File with cipher text to guess ecb mode. Expected file format is hexstrings representing bytes")

    (options, args) = parser.parse_args()

    main(options,args)
