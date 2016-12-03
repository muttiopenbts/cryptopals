'''
Typical use
$ python 5.py -f '5.txt' --key='ICE'
Opening challenge file 5.txt
XOR'ing with key ICE
Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal
00000000: 0B 36 37 27 2A 2B 2E 63  62 2C 2E 69 69 2A 23 69  .67'*+.cb,.ii*#i
00000010: 3A 2A 3C 63 24 20 2D 62  3D 63 34 3C 2A 26 22 63  :*<c$ -b=c4<*&"c
00000020: 24 27 27 65 27 2A 28 2B  2F 20 69 0A 65 2E 2C 65  $''e'*(+/ i.e.,e
00000030: 2A 31 24 33 3A 65 3E 2B  20 27 63 0C 69 2B 20 28  *1$3:e>+ 'c.i+ (
00000040: 31 65 28 63 26 30 2E 27  28 2F                    1e(c&0.'(/

Beware, key command line parameter couldn't be set with capital letters unless --key= format was used.
'''
from pwn import *
# Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *
import binascii
import enchant
import sys
from optparse import OptionParser

'''
Attempt to crack message with single byte xor key.
Will score each derived message by tokenizing message into words (spaces)
and comparing if word is in english dictionary.
Somewhat reliable.
Returns a dictionary containing score, message, key
'''
def crack_xor_message_dictionary(message):
    cracked_message = {'score':0, 'message':'', 'key':''}
    best_score = 0
    dictionary_eng = enchant.Dict("en_US")
    print message

    # Bruteforce entire message trying every possible byte option
    for key in range(0x00, 0xff):
        result = xor(unhex(message),unhex(str(key)),cut='max')
        score = 0
        #Tokenize message
        for extracted_word in result.split():
            # Skip enchant errors when words are garbage
            try:
                # Check word is alph numeric to prevent enchant errors.
                if extracted_word.isalnum() and dictionary_eng.check(extracted_word):
                    # Start counting english words
                    score+=1
            except:
                None
        # Replace top score if current score is higher
        if score > best_score:
            cracked_message = {'score':score, 'message':result, 'key':key}
            best_score = score

    return cracked_message

'''
Attempt to crack message with single byte xor key.
Will score each derived message by counting number of alpha numeric characters.
Not very reliable.
'''
def crack_xor_message(message):
    cracked_message = {}
    best_score = 0
    for key in range(0x00, 0xff):
        result = xor(unhex(message),unhex(str(key)),cut='max')
        score = 0
        for character in result:
            if is_ascii(character):
                score+=1
        if score > best_score:
            cracked_message = {'score':score, 'message':result, 'key':key}
            best_score = score
    return cracked_message

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="challenge_filename",
                      help="file to encrypt")
    parser.add_option("-k", "--key",
                      help="xor key to use")
    (options, args) = parser.parse_args()

    # Read command line parameter specifying challenge file
    challenge_filename = options.challenge_filename
    xor_key = options.key

    print "Opening challenge file {}".format(challenge_filename)
    print "XOR'ing with key {}".format(xor_key)
    # Open challenge file which should contain bunch of hex encoded lines
    with open(challenge_filename, 'r') as challenge:
        challenge_message = challenge.read().rstrip()
        print "{}".format(challenge_message)
        encrypted_message = xor(challenge_message, xor_key, cut='max')
        print "{}".format(hexdump(encrypted_message))
