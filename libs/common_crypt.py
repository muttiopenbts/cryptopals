'''
pytest used for unit testing.
Use this hexdump lib because pwntools hexdump is too slow
'''
from hexdump import *
import binascii
import enchant
import sys
from optparse import OptionParser
import editdistance
import string
import itertools
import operator
import os
script_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_path, '.'))
import freqAnalysis
import difflib
import copy
import numpy
import re
import progressbar
import common
from Crypto.Cipher import AES
from collections import Counter


'''
Python recommended way to obtain random bytes.
Specify parameter size in bytes.
'''
def get_random_byte_string(size):
    return os.urandom(size)


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

    # Break byte string up into even sized blocks
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

'''
Perform aes in ecb mode with 128 bit key.
Does padding.
Block size hardcoded to 16 bytes.
'''
def do_aes_128_ecb(plaintext, key):
    block_size = 16 # bytes
    key_size = len(key)

    encobj = AES.new(key, AES.MODE_ECB)
    # Pad plaintext
    plaintext = set_padding(plaintext,block_size)
    #hexdump(plaintext)
    cipher_text = encobj.encrypt(plaintext)
    return cipher_text


'''
Perform aes decryption in ecb mode.
Returns plaintext.
'''
def do_aes_128_ecb_decryption(ciphertext, key):
    key_size = len(key)

    decobj = AES.new(key, AES.MODE_ECB)
    plaintext = decobj.decrypt(ciphertext)
    return plaintext


'''
Perform aes in ecb mode with 128 bit key.
Does padding.
Block size hardcoded to 16 bytes.
'''
def aes_128_ecb(plaintext, key):
    return do_aes_128_ecb(plaintext, key)


'''
PKCS#7 padding function.
Pass param message which will have padding appended to as block size.
# Block size is usually 8 or 16 bytes, I believe.
'''
def set_padding(plaintext, block_size=8):
    padded_message = '' # padded message to return
    #print('Block size: '+str(block_size))
    #print('Text size: '+str(len(plaintext)))

    if block_size < len(plaintext):
        if block_size == len(plaintext): # Do nothing
            padded_message = plaintext
        else:
            # Pad plaintext to multiple of key size
            remaining_padding_size = len(plaintext) % block_size
            if remaining_padding_size == block_size or remaining_padding_size == 0: # Do nothing because it fits
                padded_message = plaintext
            else:
                #print ('Remaining size: '+str(remaining_padding_size))
                padding_size = block_size - remaining_padding_size
                #print ('Padding size: '+str(padding_size))
                if padding_size > 256:
                    raise Exception('Padding size cannot be greater than 256 as per PKCS#7 standard')
                padded_message = '{}{}'.format(plaintext, chr(padding_size) * padding_size)

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

'''
Attept to detect if cipher text block was encrypted in ecb mode.
Param ciphertext expected to be byte string.
Returns dictionary of cipher blocks with count as array.
e.g. [[{'\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83': 4}]]
'''
def is_ecb_mode(ciphertext, key_size=16):
    #print ('Key size: {}'.format(key_size))

    # Break cipher into key sized blocks and store each block as array elem
    cipher_blocks = [b for cipher_block in common.grouper(ciphertext,key_size) for b in [''.join(cipher_block)]]

    # Get count of all similar cipher blocks
    matched_blocks = [{byte:count} for byte,count in Counter(cipher_blocks).items() if count>1]

    # Total up all matched cipher blocks
    total_blocks_match = sum([count for byte in matched_blocks for count in byte.values()])

    #print ('Number of cipher blocks with match were {}, and total matched blocks {}'.format(len(matched_blocks),total_blocks_match))
    return matched_blocks


'''
This is an exercise to detect the block size used in aes ecb encryption.
'''
def test_guess_ecb_block_size():
    aes_key = get_random_byte_string(128/8)
    assert guess_ecb_block_size(do_aes_128_ecb, aes_key, 'my plaintext') == 16, 'Something wrong with ecb block size'

def guess_ecb_block_size(encryption_func, key, plaintext):
    BYTE = 8
    MULTIPLES = 32 / BYTE # bits
    MIN_KEY_SIZE =  128 / BYTE  # bits. aes spec
    MAX_KEY_SIZE = 256 / BYTE  # bits. aes spec
    MIN_BLOCK_SIZE  = 128 / BYTE
    MAX_BLOCK_SIZE  = 256 / BYTE # Not sure this is allowed in aes spec

    for guessed_block_size in range(MIN_BLOCK_SIZE, (MAX_BLOCK_SIZE + 1)*2):
        guessed_block = 'A'*guessed_block_size
        message = guessed_block + plaintext
        cipher_text = encryption_func(message, key)

        if is_ecb_mode(cipher_text):
            guessed_block_size = guessed_block_size / 2
            #print ('AES ECB mode detected and block size is {}'.format(guessed_block_size))
            return guessed_block_size


'''
From set 2 challenge 12
'''
def ecb_byte_decryption(plaintext,key):
    guessed_block_size = guess_ecb_block_size(plaintext,key)
    plaintext_size = len(plaintext)
    '''
    custom_block size = 8
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
