'''
Purpose of this exercise is to modify the integrity of the cipher text
without knowning the cipher key.
Attacker can create valid cipher blocks and manipulate the order, or contents of
valid cipher blocks to fit their purpose.
Typical use:
$ python2.7 set_2/13.py -e 'f@bar.com' -k c2950388e90e586c9c8c60815f91dddd

00000000: 99 7C 04 6D 31 DF DC D3  C3 E9 63 40 B0 EC 1E 51  .|.m1.....c@...Q
email=f@bar.com&

$ python2.7 13.py -e 'fBBBBBBBBBBBBBBBBBBBB@bar.com' -k c2950388e90e586c9c8c60815f91dddd

00000000: FC 94 A6 E9 A3 1C CB 35  60 B8 14 0C CA 5D AA 4F  .......5`....].O
com&uid=10&role=

$ python2.7 13.py -e 'fBBBBBBBBBBBBBBBBBBBB@bar.admin' -k c2950388e90e586c9c8c60815f91dddd

00000000: CA A3 A1 D5 25 30 32 3A  C8 01 F9 25 99 C7 5E 3B  ....%02:...%..^;
admin&uid=10&rol

and

bash-3.2$ python2.7 13.py -e 'fBBBBBBBBBBBBBBBBBBBB@bar.admin' -k c2950388e90e586c9c8c60815f91dddd -c '997C046D31DFDCD3C3E96340B0EC1E51FC94A6E9A31CCB3560B8140CCA5DAA4FCAA3A1D52530323AC801F92599C75E3B'
aes key:c2950388e90e586c9c8c60815f91dddd
Decrypted data of profile: email=f@bar.com&com&uid=10&role=admin&uid=10&rol
And after parsing: {
    "role": "admin", 
    "email": "f@bar.com", 
    "uid": "10"
}
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


def    remove_ascii_non_printable(str):
      """Removes Non-printable chars from ASCII String"""
      return ''.join([ch for ch in str if ord(ch) > 31 and ord(ch) < 126 or ord(ch) == 9])


'''
Pass foo=bar&baz=qux&zap=zazzle.
Return json string
e.g.
{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
'''
def parse_key_values(key_values):
    kv_dic = urlparse.parse_qs(key_values)

    flattened_kv = {}
    # Only extract first value per key
    for key in kv_dic:
        flattened_kv[key] = remove_ascii_non_printable(kv_dic[key][0])
    return json.dumps(flattened_kv,indent=4,ensure_ascii=True, )


'''
Pass email as parameter.
Returns key value pairs of profile.
e.g. email=foo@bar.com&uid=10&role=user
'''
def profile_for(email):
    email = re.sub(r"[=&]", '', email)
    profile = collections.OrderedDict()

    profile['email'] = email
    profile['uid'] = 10
    profile['role'] = "user"

    return "&".join(["=".join([key, str(val)]) for key, val in profile.items()])


'''
Purpose of this function is to allow attacker to send an email address param
and generate valid cipher blocks such that the role value can be manipulated
by the attacker to equal role=admin, even though the role is hard coded to user.

'''
def tamper_role(email,aes_key):
    profile_key_values = profile_for(email)
    cipher_text = common_crypt.do_aes_128_ecb(profile_key_values, aes_key)
    return cipher_text

def main(options,args):
    if not options.email:
        raise Exception('Must specify -e for profile email id')
    email = options.email

    if options.aes_key and (len(options.aes_key) == 32):
        aes_key = options.aes_key.decode('hex')
    else:
        # aes 128 bits
        aes_key = common_crypt.get_random_byte_string(128/8)
    print('aes key:{}'.format(aes_key.encode('hex')))

    # Test decryption mode. cipher text and key must be specified
    if options.cipher_text and options.aes_key:
        cipher_text = options.cipher_text.decode('hex')
        plaintext_profile = common_crypt.do_aes_128_ecb_decryption(cipher_text,aes_key)
        print ('Decrypted data of profile: {}'.format(plaintext_profile))
        plaintext_profile =  parse_key_values(plaintext_profile)
        print('And after parsing: {}'.format(plaintext_profile))
    else:
        # Guess aes block size
        block_size = common_crypt.guess_ecb_block_size(common_crypt.do_aes_128_ecb, aes_key, email)
        print ('Block size is: {}'.format(block_size))
        cipher_text_profile = tamper_role(email,aes_key)
        hexdump.hexdump(cipher_text_profile)

        plaintext_profile = common_crypt.do_aes_128_ecb_decryption(cipher_text_profile,aes_key)
        print('Decrypted cipher text from attack is: {}'.format(plaintext_profile))

        plaintext_profile =  parse_key_values(plaintext_profile)
        print('And after parsing: {}'.format(plaintext_profile))

        # break up cipher text into block size
        for cipher_text_block in common.grouper(cipher_text_profile, block_size):
            cipher_text_block = ''.join(cipher_text_block)
            hexdump.hexdump(cipher_text_block)
            print (common_crypt.do_aes_128_ecb_decryption(cipher_text_block,aes_key) )


if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option(
        "-m",
        dest="key_values",
        help="Specify key values. e.g. \"foo=bar&baz=qux&zap=zazzle\"")

    parser.add_option(
        "-e",
        dest="email",
        help="Specify profile email. e.g. \"user@domain.com\"")

    parser.add_option(
        "-k",
        dest="aes_key",
        help="Specify aes key as hex string. e.g. \"AE1242FF...\"")

    parser.add_option(
        "-c",
        dest="cipher_text",
        help="Specify cipher text as hex string for testing profile decryption. e.g. \"AE1242FF...\"")

    (options, args) = parser.parse_args()

    main(options,args)
