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
import common_crypt


def main(options,args):
    # Read command line parameter specifying challenge file
    challenge_filename = options.challenge_filename
    key_size = 16
    print ('Key size: {}'.format(key_size))
    ecb_match = {'score':0,'ciphertext':'','line':0}

    # Read file line by line
    with open(challenge_filename, 'r') as challenge_file:
        file_line_number = 1
        # Iterate over lines of file representing new ciphertext
        for ciphertext in challenge_file:
            # Total for all matched bytes in entire cipher text
            ct_total_matched_bytes = 0
            print('Checking cipher {}'.format(file_line_number))
            print (ciphertext)
            ciphertext = unhex(ciphertext.rstrip())
            ecb =  common_crypt.is_ecb_mode(ciphertext,key_size)
            if ecb:
                ecb_match = {'score':1, 'ciphertext':ecb,'line':file_line_number}
            file_line_number += 1
        print (ecb_match)


if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-f",
        "--file",
        dest="challenge_filename",
        help="File with cipher text to guess ecb mode. Expected file format is hexstrings representing bytes")

    (options, args) = parser.parse_args()

    main(options,args)
