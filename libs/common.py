import itertools

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

def is_ascii(s):
    return all(ord(c) < 128 for c in s)


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


def convert_bytes_to_key_blocks(param_bytes, keysize):
    single_key_byte_blocks = []
    for key_count in range(keysize):
        single_key_byte_blocks.append(param_bytes[key_count::keysize])
    return single_key_byte_blocks


def get_hex_string(stream):
    # breack hexstring into hex pairs. '1234567890' into ['12','34',...]
    hex_pairs = [hexstring[i:i+2] for i in range(0, len(stream), 2)]

# Param should be hex string. e.g. 'afee3af5'
# Returns array with of hexstrings broken into chunks sizes of keysize.
# Note: key represents single byte.
# e.g. ['af3a', 'eef5'] if keysize were two
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


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args, fillvalue=fillvalue)
