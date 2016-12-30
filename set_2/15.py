'''
Typical use:
$ python2 15.py
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
    plaintext = options.plaintext
    common_crypt.remove_pkcs7(plaintext)


if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-p",
        dest="plaintext",
        help="Plaintext message to remove pkcs7 padding from")

    (options, args) = parser.parse_args()

    main(options,args)
