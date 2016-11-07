from pwn import *
# Use this hexdump lib because pwntools hexdump is too slow
from hexdump import *

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


challenge = "1c0111001f010100061a024b53535009181c"
key = "686974207468652062756c6c277320657965"

result = get_xor_message(unhex(challenge),unhex(key))
print hexdump(result)
