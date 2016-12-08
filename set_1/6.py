'''
Typical use:
input 1: 'this is a test'
input 2: 'wokka wokka!!!'

Calculated distance should equal 37

Distance is based on binary representation.

<script name>.py 'this is a test' 'wokka wokka!!!'
Hamming distance between this is a test and wokka wokka!!! is 37
Edit distance between this is a test and wokka wokka!!! is 37
levenshtein distance between this is a test and wokka wokka!!! is 37
'''
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
sys.path.append(os.path.join(script_path, '..','libs'))
import freqAnalysis
import difflib
import copy
import numpy
import re
import progressbar

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
Test if passed param is hex represented string.
e.g. 'a0afa19d'
'''
def is_hex_string(stream):
    stream = "".join(stream.split())
    # Is message a hex string like 'a41332ef', hex pairs represent bytes.
    regex = r'[^a-f0-9]+'
    # If any non hex chars are found then can't be hex string
    matches = re.search(regex, stream, re.I)
    if matches:
        return False
    else:
        return True


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


def is_ascii(s):
    return all(ord(c) < 128 for c in s)

# s1, s2 should be binary sequences
def hammingDistance(s1, s2):
    """Return the Hamming distance between equal-length sequences"""
    if len(s1) != len(s2):
        raise ValueError("Undefined for sequences of unequal length {}:{}, {}:{}".format(len(s1),s1,len(s2),s2))
    return sum(el1 != el2 for el1, el2 in zip(s1, s2))

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def demo():
    s1 = 'this is a test'
    s2 = 'wokka wokka!!!'

    s1_binary = get_binary_from_string(s1)
    s2_binary = get_binary_from_string(s2)
    # This is just a demo.
    print "Hamming distance between {} and {} is {}".format(s1, s2, hammingDistance(s1_binary, s2_binary))
    print "Edit distance between {} and {} is {}".format(s1, s2, editdistance.eval(s1_binary, s2_binary))
    print "levenshtein distance between {} and {} is {}".format(s1, s2, levenshtein(s1_binary, s2_binary))


def get_binary_from_string(string):
    # convert some text to hex representation
    # 'abc' = '6163'
    s1_string_to_hexString = string.encode("hex")
    return get_binary_from_hexstring(s1_string_to_hexString)


#Keep leading zeros
def get_binary_from_hexstring(hexstring):
    # Convert hex to integer
    # '6163' = 24931
    s1_hex_to_int = int(hexstring, 16)
    # Convert integer to binary
    # 24931 = 110000101100011
    byte_size = 8
    s1_binary = format(s1_hex_to_int,'0' + str(len(hexstring)/2*byte_size) + 'b')
    return s1_binary

def _get_key(min_length, max_length, min, max):
    for key in range(min, max):
        yield key

def get_key(items, max):
    for c in itertools.product(items, repeat=max):
        yield c

def convert_bytes_to_key_blocks(param_bytes, keysize):
    single_key_byte_blocks = []
    for key_count in range(keysize):
        single_key_byte_blocks.append(param_bytes[key_count::keysize])
    return single_key_byte_blocks

def get_hex_string(stream):
    # breack hexstring into hex pairs. '1234567890' into ['12','34',...]
    hex_pairs = [hexstring[i:i+2] for i in range(0, len(stream), 2)]


def convert_hexstring_to_key_blocks(hexstring, keysize):
    single_key_byte_blocks = []
    # breack hexstring into hex pairs. '1234567890' into ['12','34',...]
    hex_pairs = [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]
    for key_count in range(keysize):
        # Combine hex pairs from every nth (key_count) into a single hex string
        # e.g. ['1245', '2367'] if keysize were two.
        byte_block_string = ''.join( hex_pairs[key_count::keysize] )
        single_key_byte_blocks.append(byte_block_string)
    return single_key_byte_blocks


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
Generate a list of lists for every combination.
e.g. bruteforce list of passwords of given length
'''
def generate_patterns():
    list_of_key_items = string.lowercase[:]
    #list_of_key_items = ['0','1']
    for keysize in range(min_keysize, max_keysize):
        for key in get_key(list_of_key_items, keysize):
            print ''.join(key)

    for keysize in range(2,41):
        # Position file read pointer
        cipher_text = decoded_b64_challenge[:keysize]
        print keysize
        hexdump(cipher_text)
        cipher_text_hexstring = binascii.hexlify(cipher_text)
        print cipher_text_hexstring
        cipher_text_binary = get_binary_from_hexstring(cipher_text_hexstring)
        print cipher_text_binary


def main(options,args):
    # Read command line parameter specifying challenge file
    challenge_filename = options.challenge_filename

    # Actual challenge
    # Read entire file and base64 decode
    with open(challenge_filename, 'r') as challenge_file:
        challenge_file_contents = challenge_file.read()

    # We should now have a copy of the raw cipher text
    decoded_b64_challenge = b64d(challenge_file_contents)

    guessed_keysize = get_guessed_keysize(decoded_b64_challenge)

    total_blocks = len(decoded_b64_challenge) / guessed_keysize
    print 'Total cipher length {}, key size {}, broken up into blocks of {}'.format(len(decoded_b64_challenge), guessed_keysize, total_blocks)

    '''
    Transpose cipher text blocks which represent blocks enrypted with a key
    into blocks that represent a single byte of the key.
    key size 3. Cipher text = abc def ghi jkl.
    New transposed blocks would be adgj behk cfil.
    So transposed block 0 (adgj) would have been encrypted with key byte 0
    '''
    single_key_byte_blocks = []

    # Need to split cipher into blocks. If cipher message is hex string format
    # then they need to be split in pairs like 'ab' 'af' '41'
    if is_hex_string(decoded_b64_challenge):
        single_key_byte_blocks = convert_hexstring_to_key_blocks(decoded_b64_challenge, guessed_keysize)
    else:
        single_key_byte_blocks = convert_bytes_to_key_blocks(decoded_b64_challenge, guessed_keysize)

    decrypted_key_byte_blocks = []

    key = ''
    for key_block in single_key_byte_blocks:
        b = crack_xor_message_frequency(key_block)
        decrypted_key_byte_blocks.append(b['message'])
        # print 'Key hex {} ascii {}'.format(hex(b['key']), chr(b['key']))
        key += chr(b['key'])
    print 'Key {}'.format(str(key))

    hexdump( ''.join(numpy.array(list(itertools.izip(*decrypted_key_byte_blocks))).flatten()) )
    decrypted_message =''.join(numpy.array(list(itertools.izip(*decrypted_key_byte_blocks))).flatten())
    print decrypted_message


if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-f",
        "--file",
        dest="challenge_filename",
        help="file to decrypt. Expected file format is base64")

    parser.add_option(
        "--demo",
        dest="mode",
        help="Demo mode. Set any value, e.g. --demo=1")
    (options, args) = parser.parse_args()

    if options.mode:
        demo()
    else:
        main(options,args)
