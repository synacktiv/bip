"""
    Functions and trics for supporting both python 2 and python 3 in
    Bip. This is for internal use only.
"""

import sys

def is_py3():
    """
        Function for checking if we are in python3. This is used in other
        part of Bip for compatibility between python2 and python3.
    """
    return sys.version_info[0] == 3

if sys.version_info[0] == 3:
    long = int # long does not exist in python3, everything is an int
    unicode = str # unicode is the base string type in python3
    def int2byte(i):
        """
            Method for converting an integer to a byte. This is a replacement of
            ``chr(i)`` in python2 and of ``bytes([i])`` in python3.

            :param int i: The value to get for the character.
            :return: A byte string (str or bytes in python2, bytes in python3)
                for the character.
        """
        return bytes([i])
else:
    def int2byte(i):
        """
            Method for converting an integer to a byte. This is a replacement of
            ``chr(i)`` in python2 and of ``bytes([i])`` in python3.

            :param int i: The value to get for the character.
            :return: A byte string (str or bytes in python2, bytes in python3)
                for the character.
        """
        return chr(i)


