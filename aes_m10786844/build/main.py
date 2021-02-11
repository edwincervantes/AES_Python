#!/usr/bin/python
# EJ Cervantes
import sys
import os
import itertools
import traceback
from textwrap import wrap
import numpy as np  # MUST BE INSTALLED python -m pip install --user numpy scipy matplotlib ipython jupyter pandas sympy nose

PATH = os.getcwd()
PLAINTEXT_PATH_WINDOWS = os.path.dirname(PATH) + '\data\plaintext.txt'
PLAINTEXT_PATH_LINUX = os.path.dirname(PATH) + '/data/plaintext.txt'
SUBKEY_PATH_WINDOWS = os.path.dirname(PATH) + '\data\subkey_example.txt'
SUBKEY_PATH_LINUX = os.path.dirname(PATH) + '/data/subkey_example.txt'
SCALE = 16  # equal to hex
NUM_BITS = 8
AES_S_BOX = np.array([
    [63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
])  # To use the hex values do hex(AES_S_BOX[x,n]) or else it will translate it to binary

MIX_COLUMNS = np.array([
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
])

'''
:param: aes_Obj
:return: None 
'''


class aes_Obj(object):

    def __init__(self):
        self.platform = sys.platform
        self.message_ascii = None
        self.message_bit = None
        self.message_hex = None
        self.initial_state = None
        self.plaintext_path = None
        self.subkey_path = None
        self.subkey0_bin = None
        self.subkey0_hex = None
        self.subkey1_bin = None
        self.subkey1_hex = None
        self.subkey_matrix = None


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


def sub_bytes(aes):
    '''
    Substitute each byte in the State with the AES_S_BOX value
    :param: aes_Obj
    :return: None
    '''
    for x in aes.initial_state:
        first = x[0]
        second = x[1]
        third = x[2]
        fourth = x[3]

        new1 = hex(AES_S_BOX[int(first[0], 16), int(first[1], 16)])
        new2 = hex(AES_S_BOX[int(second[0], 16), int(second[1], 16)])
        new3 = hex(AES_S_BOX[int(third[0], 16), int(third[1], 16)])
        new4 = hex(AES_S_BOX[int(fourth[0], 16), int(fourth[1], 16)])

        aes.initial_state = (np.where(aes.initial_state == first, new1, aes.initial_state))

        aes.initial_state = (np.where(aes.initial_state == second, new2, aes.initial_state))

        aes.initial_state = (np.where(aes.initial_state == third, new3, aes.initial_state))

        aes.initial_state = (np.where(aes.initial_state == fourth, new4, aes.initial_state))

    return


def shift_rows(aes):
    '''
    Shift bytes in the State according to AES shifting standard
    :param: aes_Obj
    :return: None
    '''
    aes.initial_state[1] = np.roll(aes.initial_state[1], -1)
    aes.initial_state[2] = np.roll(aes.initial_state[2], -2)
    aes.initial_state[3] = np.roll(aes.initial_state[3], -3)

    return


def mix_columns(aes):
    '''
    Invertible transformation on each column, this step will be skipped in the final round
    Look at lecture10 p. 29 for an example. Take the row of the static matrix and then the column of
    our current state, this will give you 1 value for the next part
    :param: aes_Obj
    :return: None
    '''
    list = []
    print("Mix Columns: ")
    mix_col_list = (MIX_COLUMNS[0].tolist())
    i_state_list = (aes.initial_state.T[0].tolist())
    print(mix_col_list)
    print(i_state_list)
    print(type(mix_col_list))
    print(type(i_state_list))


    for i in range(0, len(mix_col_list)):
        list.append(i_state_list[i] * mix_col_list[i])

    print(list)

    return


def add_key(aes):
    '''
    This is where we XOR our initial state matrix with our subkey. The output of this will be used as the next rounds initial state
    :param: aes_Obj
    :return: None
    '''
    print('SubkeyMatrix:')
    print(aes.subkey_matrix)
    xor_list = []
    for x, y in zip(aes.initial_state, aes.subkey_matrix):
        for elem1, elem2 in zip(x, y):
            elem1 = int(elem1, 16)
            new_elem1 = elem1 + 0x200
            elem2 = int(elem2, 16)
            new_elem2 = elem2 + 0x200
            xor1 = new_elem1 ^ new_elem2
            xor_list.append(xor1)
    chunks = [xor_list[x:x + 4] for x in range(0, len(xor_list), 4)]
    aes.initial_state[0] = chunks[0]
    aes.initial_state[1] = chunks[1]
    aes.initial_state[2] = chunks[2]
    aes.initial_state[3] = chunks[3]

    return


def do_round(aes):
    '''
    These are the operations that will be performed in each round of AES
    :param: aes_Obj
    :return: None
    '''
    sub_bytes(aes)
    print('sub_byte function: ')
    print(aes.initial_state)
    shift_rows(aes)
    print('Shift_rows function')
    print(aes.initial_state)
    mix_columns(aes)
    add_key(aes)

    return


def get_initial_state(aes):
    '''
    The initial state is described as a block 4x4 matrix with the hexadecimal values of the message
    This function will obtain that for us and assign it to the object
    :param: aes_Obj
    :return: None
    '''
    bytes = wrap(aes.message_hex, 2)
    row1 = []
    row2 = []
    row3 = []
    row4 = []
    for index in range(4):
        row1.append(bytes[index])
    for index in bytes[4:8]:
        row2.append(index)
    for index in bytes[8:12]:
        row3.append(index)
    for index in bytes[12:16]:
        row4.append(index)
    aes.initial_state = np.array([row1, row2, row3, row4])
    print('Initial State Matrix: \n' + str(aes.initial_state))


def get_subkey_matrix(aes):
    '''
    We will need the subkey put into a 4x4 matrix represented using the numpy module
    :param: aes_Obj
    :return: None
    '''

    bytes = wrap(aes.subkey1_hex, 2)

    row1 = []
    row2 = []
    row3 = []
    row4 = []
    for index in range(4):
        row1.append('0x' + bytes[index])
    for index in bytes[4:8]:
        row2.append('0x' + index)
    for index in bytes[8:12]:
        row3.append('0x' + index)
    for index in bytes[12:16]:
        row4.append('0x' + index)
    aes.subkey_matrix = np.array([row1, row2, row3, row4])
    print('sub_key matrix: \n' + str(aes.subkey_matrix))


def get_subkeys(aes):
    '''
    Assigns the subkeys to our AES object in bit form(128-bits) while getting the hexadecimal from our file
    Sometimes our bit converter drops the leading 0 so we need to add it to ensure it is 128-bits
    :param: aes_Obj
    :return: None
    '''
    with open(aes.subkey_path, 'r') as f:
        lines = f.readlines()
        aes.subkey0_hex = lines[0]
        aes.subkey1_hex = lines[1]
    aes.subkey0_bin = format_to_bit(aes.subkey0_hex)
    aes.subkey1 = format_to_bit(aes.subkey1_hex)
    if aes.subkey0_bin is None or aes.subkey1 is None:
        raise Exception("The Subkeys were not able to be generated. Please read the file report.pdf")
    if len(aes.subkey0_bin) < 128:
        aes.subkey0_bin = '0' + aes.subkey0_bin
    if len(aes.subkey1) < 128:
        aes.subkey1_bin = '0' + aes.subkey1_bin


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
    get_initial_state(aes)
    get_subkey_matrix(aes)
    do_round(aes)


if __name__ == '__main__':
    try:
        aes = aes_Obj()
        script_execute(aes)
    except:
        print(traceback.format_exc())
        sys.stdout.flush()
        sys.exit(1)
