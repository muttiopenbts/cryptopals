from pwn import *
# Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *
import binascii
import enchant
import sys

def get_xor_message(message, xor_key):
    """ Retrieve an xor key from two messages.
        Tried using pwntools xor utility but found it had size limit of 255 :(
    """
    # Get key to match size of message
    adjusted_xor_key = ''
    while len(adjusted_xor_key) < len(message):
        adjusted_xor_key += xor_key
    # This should truncate size of adjusted xor key to match size of message
    adjusted_xor_key = adjusted_xor_key[:len(message)]
    xor_message = "".join(chr(ord(x) ^ ord(y)) for x, y in zip(message, adjusted_xor_key))
    return xor_message

def is_ascii(s):
    return s.isalnum()
#    return all(ord(c) < 128 for c in s)

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
    best_score = {'score':0, 'message':'', 'key':''} # Keep score of most likely encrypted message line
    # Read command line parameter specifying challenge file
    challenge_filename = sys.argv[1]
    print "Opening challenge file {}".format(challenge_filename)
    # Open challenge file which should contain bunch of hex encoded lines
    with open(challenge_filename, 'r') as challenge:
        for line in  challenge:
            #Bruteforce crack the encoded line
            cracked_message = crack_xor_message_dictionary(line.rstrip())
            # What score (frequency) of english words contained
            if cracked_message['score'] > best_score['score']:
                # Keep record of best score
                best_score = cracked_message
    print best_score
