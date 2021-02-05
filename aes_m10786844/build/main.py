#!/usr/bin/python
#EJ Cervantes
import sys
import os
import traceback
import math
import binascii

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
        self.plaintext_path = None
        self.subkey_path = None
        self.subkey0 = None
        self.subkey1 = None


def to_string(ascii):
    '''
    Convert an ascii value to a string
    :param: ASCII value
    :return: string value
    '''

    return ascii_val


def to_ascii(string):
    '''
    Convert a string value to ASCII value
    :param: string value
    :return: ASCII value
    '''
    ascii_val = ''.join(str(ord(c)) for c in string)
    return ascii_val


def format_ascii_to_bit(text):
    '''
    Convert an ascii value to hex value
    :param: ascii value
    :return: bit value
    '''
    bit_val = bin(int(text))
    return bit_val


def format_to_hex(bit):
    '''
    Convert a bit value to a hexadecimal value
    :param: bit value
    :return: hexadecimal value
    '''
    hex_val = hex(int(bit, 2))
    return hex_val


def format_to_bit(hex):
    '''
    Convert a hexadecimal value to a bit value
    :param: hexadecimal value
    :return: bit value
    '''
    bit_val = bin(int(hex, SCALE))[2:].zfill(NUM_BITS)

    return bit_val


def do_round(aes):
    return

def calculate_add_key(aes):
    return

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


def get_message(aes):
    '''
    Assigns the plaintext message to our aes object from the file in ASCII format
    :param: aes_Obj
    :return: None
    '''
    with open(aes.plaintext_path, 'r') as f:
        message_plaintext = f.read().replace('\n', '')
        print(message_plaintext)
    aes.message_ascii = to_ascii(message_plaintext)   #Correct
    print(aes.message_ascii)
    aes.message_bit = format_ascii_to_bit(aes.message_ascii)
    print(aes.message_bit)
    print(len(aes.message_bit))
    if aes.message_ascii is None:
        raise Exception('Not able to obtain the plaintext message. Please read the file report.pdf')



def check_OS_and_files(aes):
    '''
    Used to determine what the OS is that is being run to determine correct directory structure.
    Also checks to verify that the message and subkey are located in the designated .txt
    :param: aes_Obj
    :return: None if successful
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
    calculate_add_key(aes)
    do_round(aes)


if __name__ == '__main__':
    try:
        aes = aes_Obj()
        script_execute(aes)
    except:
        print(traceback.format_exc())
        sys.stdout.flush()
        sys.exit(1)
