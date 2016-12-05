'''
Typical use:
$ echo -e 'YELLOW SUBMARINE'|xxd -
00000000: 5945 4c4c 4f57 2053 5542 4d41 5249 4e45  YELLOW SUBMARINE
00000010: 0a
$ openssl enc -d -aes-128-ecb -in ~/Dropbox/Dev/crypto/cryptopals/set_1/7.txt -a -nosalt -K '59454c4c4f57205355424d4152494e45'

Simple example of python aes decryption usage
'''
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
sys.path.append(os.path.join(script_path, '../libs'))
from Crypto.Cipher import AES


def main(options,args):
    # Read command line parameter specifying challenge file
    challenge_filename = options.challenge_filename

    # Read entire file and base64 decode
    challenge_file_contents = open(challenge_filename, 'r').read()

    # We should now have a copy of the raw cipher text
    decoded_b64_challenge = b64d(challenge_file_contents)

    key = 'YELLOW SUBMARINE'
    ciphertext = decoded_b64_challenge

    decobj = AES.new(key, AES.MODE_ECB)
    plaintext = decobj.decrypt(ciphertext)

    print 'Decryption key: {}'.format(key)
    # Resulting plaintext
    print plaintext

if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-f",
        "--file",
        dest="challenge_filename",
        help="file to decrypt. Expected file format is base64")

    (options, args) = parser.parse_args()

    main(options,args)
