'''
Typical use:
bash-3.2$ python2.7 set_2/14.py
Sending uknown message to ecb byte decryptor
Plaintext size: 138
Key size: 16
Message size: 138
Key: a3f5ba073528200b2ca6dba8113774d4
Decipher uknown message is:
00000000: A0 33 D6 4D A0 E9 13 9C  74 F7 5F 59 45 BC 85 8E  .3.M....t._YE...
00000010: 74 6C BB 92 41 05 47 8D  41 23 9F 42 2B CF F2 CC  tl..A.G.A#.B+...
00000020: 4E E5 8B 7A 3A 28 68 E5  D0 E1 8E F3 C5 51 E9 33  N..z:(h......Q.3
00000030: 67 59 83 7D 1F E5 B8 1E  13 14 DF 6D 6B D7 7C 06  gY.}.......mk.|.
00000040: 29 24 08 B9 6C 9C 36 67  D8 AA 83 52 6F 6C 6C 69  )$..l.6g...Rolli
00000050: 6E 27 20 69 6E 20 6D 79  20 35 2E 30 0A 57 69 74  n' in my 5.0.Wit
00000060: 68 20 6D 79 20 72 61 67  2D 74 6F 70 20 64 6F 77  h my rag-top dow
00000070: 6E 20 73 6F 20 6D 79 20  68 61 69 72 20 63 61 6E  n so my hair can
00000080: 20 62 6C 6F 77 0A 54 68  65 20 67 69 72 6C 69 65   blow.The girlie
00000090: 73 20 6F 6E 20 73 74 61  6E 64 62 79 20 77 61 76  s on standby wav
000000A0: 69 6E 67 20 6A 75 73 74  20 74 6F 20 73 61 79 20  ing just to say
000000B0: 68 69 0A 44 69 64 20 79  6F 75 20 73 74 6F 70 3F  hi.Did you stop?
000000C0: 20 4E 6F 2C 20 49 20 6A  75 73 74 20 64 72 6F 76   No, I just drov
000000D0: 65 20 62 79 0A 01                                 e by..

Haven't really changed anything from challenge 12. Not sure if misunderstood instructions.
'''
from __future__ import print_function
# Use this hexdump lib because pwntools hexdump is too slow
import sys
from optparse import OptionParser
import os
script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_path, '..','libs'))
import json
import common_crypt
import common
import hexdump
import collections
import re
import urlparse
import pwn


def main(options,args):
    BYTE = 8
    KEY_SIZE = 128 / BYTE # bits
    ''' unknown_string to be append to plaintext and we need to figure out its contents'''
    unknown_string = pwn.b64d('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    plaintext = unknown_string

    key = common_crypt.get_random_byte_string(KEY_SIZE)
    key_size = len(key)
    message_size = len(plaintext)
    random_prefix = common_crypt.get_random_byte_string(ord(os.urandom(1)))

    print ('Sending uknown message to ecb byte decryptor')
    #hexdump(plaintext)
    print ('Plaintext size: {}'.format(len(plaintext)))
    print ('Key size: {}'.format(key_size))
    print ('Message size: {}'.format(message_size))
    print ('Key: {}'.format(key.encode('hex')))

    guessed_unknown = common_crypt.ecb_byte_decryption(prefix_plaintext=random_prefix,plaintext=plaintext,key=key)
#    guessed_unknown = common_crypt.ecb_byte_decryption(plaintext=plaintext,key=key)

    if guessed_unknown:
        print ('Decipher uknown message is:')
        hexdump.hexdump(guessed_unknown)


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
