from pwn import *

challenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

unhexed = pwnlib.util.fiddling.unhex(challenge)
print pwnlib.util.fiddling.b64e(unhexed)
