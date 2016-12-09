from pwn import *
# Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *
import binascii
import enchant
import sys
from optparse import OptionParser
import editdistance
import string
import itertools
import operator
script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_path, '.'))
import freqAnalysis
import difflib
import copy
import numpy
import re
import progressbar
import common

'''
PKCS#7 padding function.
Pass param message which will have padding appended to and keysize.
'''
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
            if character.isalnum():
                score+=1
        if score > best_score:
            cracked_message = {'score':score, 'message':result, 'key':key}
            best_score = score
    return cracked_message


'''
Attempt to crack message with single byte xor key.
Will score each derived message by frequency analysis of most common letters in english text.
Somewhat reliable.
Param message can either be raw bytes '\x41\xaf' or hex string '41af'.
function will try to automatically convert message to hex string when xor()
'''
def crack_xor_message_frequency(message):
    # Guess format of message
    # Is message a hex string like 'a41332ef', hex pairs represent bytes.
    if not is_hex_string(message):
        message = message.encode('hex')

    cracked_message = {'score':None,'message':'','key':''}
    best_score = 0

    bar = progressbar.ProgressBar(max_value=0xff, redirect_stdout=True)

    for key in range(0x00, 0xff):
        bar.update(key)

        # Xor params should be hex bytes. e.g. xor('\xaf', '\x0a')
        guessed_plaintext = xor(unhex(message),unhex("{:02x}".format(key)),cut='max')
        score = 0
        letter_frequency_order = freqAnalysis.getFrequencyOrder(guessed_plaintext, True)
        score = freqAnalysis.englishFreqMatchScore(guessed_plaintext)

        # Matches all non printable ascii characters
        # and lower score
        regex_non_ascii = r'[^ -~\x0D\x0A]'
        matches = re.findall( regex_non_ascii, guessed_plaintext)
        if matches:
            score -= len(matches)

        # Matches all non alpha ascii characters
        # and lower score.
        # Improved accuracy.
        regex_non_alpha_ascii = r'[^a-zA-Z]'
        matches = re.findall( regex_non_alpha_ascii, guessed_plaintext)
        if matches:
            score -= len(matches) / float(2) # each find reduces score by 0.5 per find

        # Matches all non lowercase alpha ascii characters
        # and lower score
#        regex_non_lcalpha_ascii = r'[^a-z]'
#        matches = re.findall( regex_non_lcalpha_ascii, guessed_plaintext)
#        if matches:
#            score -= len(matches) / float(2) # each find reduces score by 0.5 per find

        if score > cracked_message['score']:
            cracked_message = {'score':score,'message':guessed_plaintext, 'key':key}
    bar.finish()

    return cracked_message


def get_guessed_keysize(decoded_b64_challenge):
    min_keysize = 2
    max_keysize = 41
    # Keep a list of key sizes and their calculated edit distance
    edit_distance_list = {}
    guessed_keysize = 0
    bar = progressbar.ProgressBar(max_value=max_keysize)

    for keysize in range(min_keysize, max_keysize):
        bar.update(keysize)

        # make sure we are within bounds of string
        num_of_blocks = len(decoded_b64_challenge) / keysize

        # Extract consecutive blocks from cipher text for comparison
        # e.g. ['ab','cd','ef', ...num_of_blocks]= 'abcdefghij'
        list_of_cipher_text_blocks = [decoded_b64_challenge[x*keysize:(x+1)*keysize] for x in range(0, num_of_blocks)]
        # convert bytes to hex strings
        list_of_cipher_hex_blocks = [block.encode('hex') for block in list_of_cipher_text_blocks]
        # convert hexstrings to binary format
        list_of_cipher_binary_blocks = [get_binary_from_hexstring(block) for block in list_of_cipher_hex_blocks]
        # create list of every combination of pairs of blocks and get hamming distance
        list_of_edit_distances = [ hammingDistance(block1,block2) / float(keysize) for block1, block2 in itertools.combinations(list_of_cipher_binary_blocks, 2)]
        # create list of every combination of pairs of blocks and get hamming distance
        normalized_edit_distance = sum(list_of_edit_distances) / float(len(list_of_edit_distances))

#        print 'Guessed key size {}, normalized {}'.format(keysize, normalized_edit_distance)
        edit_distance_list[keysize] = normalized_edit_distance

    # Find smallest edit distance in list
    guessed_keysize = min(edit_distance_list.iteritems(), key=operator.itemgetter(1))[0]

    bar.finish()

    return guessed_keysize
