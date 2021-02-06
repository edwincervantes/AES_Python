#!/usr/bin/python
#EJ Cervantes
import sys
import os
import traceback
from textwrap import wrap
import numpy as np      #MUST BE INSTALLED python -m pip install --user numpy scipy matplotlib ipython jupyter pandas sympy nose

PATH = os.getcwd()
PLAINTEXT_PATH_WINDOWS = os.path.dirname(PATH) + '\data\plaintext.txt'
PLAINTEXT_PATH_LINUX = os.path.dirname(PATH) + '/data/plaintext.txt'
SUBKEY_PATH_WINDOWS = os.path.dirname(PATH) + '\data\subkey_example.txt'
SUBKEY_PATH_LINUX = os.path.dirname(PATH) + '/data/subkey_example.txt'
SCALE = 16 #equal to hex
NUM_BITS = 8
'''
:param: aes_Obj
:return: None 
'''


class aes_Obj(object):

    def  __init__(self):
        self.platform = sys.platform
        self.message_ascii = None
        self.message_bit = None
        self.message_hex = None
        self.initial_state = np.array([[], [], [], []])
        self.plaintext_path = None
        self.subkey_path = None
        self.subkey0 = None
        self.subkey1 = None



def to_ascii(string):
    '''
    Convert a string value to ASCII value
    :param: string value
    :return: ASCII value
    '''
    char_list = list(string)
    asc_arr = []
    for char in char_list:
        ascii_val = ''.join(str(ord(c)) for c in char)
        asc_arr.append(ascii_val)
    return asc_arr


def format_ascii_to_bit(text):
    '''
    Convert an ascii value to hex value
    :param: ascii value
    :return: bit value
    '''
    char_list = list(text)
    bit_arr = []
    for char in char_list:
        binary = format(int(char), 'b').zfill(8)
        bit_arr.append(binary)
    str = ''
    joins = str.join(bit_arr)
    return joins


def format_to_hex(bit):
    '''
    Convert a bit value to a hexadecimal value
    :param: bit value
    :return: hexadecimal value
    '''
    hex_val = hex(int(bit, 2))[2:]
    return hex_val


def format_to_bit(hex):
    '''
    Convert a hexadecimal value to a bit value
    :param: hexadecimal value
    :return: bit value
    '''
    bit_val = bin(int(hex, SCALE))[2:].zfill(NUM_BITS)

    return bit_val


def sub_bytes():
    '''
    Substitute each byte in the State
    :param: aes_Obj
    :return: None
    '''
    return


def shift_rows():
    '''
    Shift bytes in the State
    :param: aes_Obj
    :return: None
    '''
    return


def mix_columns():
    '''
    Invertible transformation on each column, this step will be skipped in the final round
    :param: aes_Obj
    :return: None
    '''

    return


def add_key():
    '''
    This where we XOR our 128-bit subkey with the state.
    :param: aes_Obj
    :return: None
    '''

    return

def do_round(aes):
    '''
    These are the operations that will be performed in each round of AES
    :param: aes_Obj
    :return: None
    '''
    sub_bytes()
    shift_rows()
    mix_columns()
    add_key()

    return


def calculate_add_key(aes):
    '''
    A 128-bit subkey XOR with the State
    :param: aes_Obj
    :return: None
    '''
    return


def get_initial_state(aes):
    bytes = wrap(aes.message_hex, 2)
    #for byte in bytes:
    np.insert(aes.initial_state, 0, bytes)
    print(aes.initial_state)


def get_subkeys(aes):
    '''
    Assigns the subkeys to our AES object in bit form(128-bits) while getting the hexadecimal from our file
    Sometimes our bit converter drops the leading 0 so we need to add it to ensure it is 128-bits
    :param: aes_Obj
    :return: None
    '''
    with open(aes.subkey_path, 'r') as f:
        lines = f.readlines()
        key0 = lines[0]
        key1 = lines[1]
    aes.subkey0 = format_to_bit(key0)
    aes.subkey1 = format_to_bit(key1)
    if aes.subkey0 is None or aes.subkey1 is None:
        raise Exception("The Subkeys were not able to be generated. Please read the file report.pdf")
    if len(aes.subkey0) < 128:
        aes.subkey0 = '0' + aes.subkey0
    if len(aes.subkey1) < 128:
        aes.subkey1 = '0' + aes.subkey1


def create_matrix(aes):
    '''
    The matrix is a 4x4 array of bytes that is generated from the bits of the key or message.
    :param: aes_Obj
    :return: None
    '''


def get_message(aes):
    '''
    Assigns the plaintext message to our aes object from the file in ASCII format then to binary
    TODO: The # of bits does not match up to what it's supposed to be. May need to debug later
    :param: aes_Obj
    :return: None
    '''
    with open(aes.plaintext_path, 'r') as f:
        message_plaintext = f.read().strip()
        print('Message: ' + message_plaintext)
    aes.message_ascii = to_ascii(message_plaintext)
    print('Message in ASCII: ' + str(aes.message_ascii))
    aes.message_bit = format_ascii_to_bit(aes.message_ascii)
    print('The message in bit form: ' + aes.message_bit)
    print('Number of bits in message: ' + str(len(aes.message_bit)))
    aes.message_hex = format_to_hex(aes.message_bit)
    print('Message in hex-form: ' + aes.message_hex)
    if aes.message_bit is None:
        raise Exception('Not able to obtain the plaintext message. Please read the file report.pdf')


def check_OS_and_files(aes):
    '''
    Used to determine what the OS is that is being run to determine correct directory structure.
    Also checks to verify that the message and subkey are located in the designated .txt
    :param: aes_Obj
    :return: None
    '''
    if aes.platform == "linux" or aes.platform == "linux2" or aes.platform == "darwin":
        if not os.path.exists(PLAINTEXT_PATH_LINUX):
            raise Exception('The message to encrypt must be stored in .../data/plaintext.txt')
        aes.plaintext_path = PLAINTEXT_PATH_LINUX
        if not os.path.exists(SUBKEY_PATH_LINUX):
            raise Exception('The message to encrypt must be stored in .../data/subkey_example.txt')
        aes.subkey_path = SUBKEY_PATH_LINUX

    elif aes.platform == "win32" or aes.platform == "win64":
        if not os.path.exists(PLAINTEXT_PATH_WINDOWS):
            raise Exception('The message to encrypt must be stored in ...\data\plaintext.txt')
        aes.plaintext_path = PLAINTEXT_PATH_WINDOWS
        if not os.path.exists(SUBKEY_PATH_WINDOWS):
            raise Exception('The message to encrypt must be stored in ...\data\subkey_example.txt')
        aes.subkey_path = SUBKEY_PATH_WINDOWS


def script_execute(aes):
    '''
    Executes our AES algorithm
    :param: None
    :return: None if successful
    '''
    check_OS_and_files(aes)
    get_message(aes)
    get_subkeys(aes)
    create_matrix(aes)
    calculate_add_key(aes)
    do_round(aes)
    get_initial_state(aes)


if __name__ == '__main__':
    try:
        aes = aes_Obj()
        script_execute(aes)
    except:
        print(traceback.format_exc())
        sys.stdout.flush()
        sys.exit(1)
