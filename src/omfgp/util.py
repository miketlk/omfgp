#!/usr/bin/env python3

"""Utility functions"""

import sys
from binascii import hexlify

# True when uscard (Micropython) module is used to communicate with a card
USES_USCARD = sys.implementation.name == 'micropython'
# True when pyscard module is used to communicate with a card
USES_PYSCARD = not USES_USCARD

if USES_USCARD:
    from uscard import CardConnection
else:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection

    def get_reader(name=""):
        """Return first found reader."""
        rarr = [r for r in readers() if name in str(r)]
        if len(rarr) == 0:
            raise RuntimeError("Reader not found")
        return rarr[0]


def get_connection(reader=None, protocol=CardConnection.T1_protocol):
    """Establish connection with a card."""
    if reader is None:
        if USES_USCARD:
            raise ValueError("Reader is required")
        else:
            reader = get_reader()
    connection = reader.createConnection()
    connection.connect(protocol)
    return connection


def aid_to_str(aid: bytes):
    """Converts AID from bytes to string representation"""
    s = hexlify(aid).decode().upper()
    return s[1:] if s.startswith("0") else s


class AID(bytes):
    """Wrapper around byte string to store AID."""

    def __str__(self):
        return aid_to_str(self)

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


def int_to_bytes_big_endian(x: int, n_bytes: int) -> bytearray:
    """Converts integer to bytes in big endian mode"""
    if x >= 256 ** n_bytes:
        raise ValueError("Conversion overflow")
    res = bytearray(n_bytes)
    shift = 0
    for i in range(n_bytes - 1, -1, -1):
        res[i] = (x >> shift) & 0xff
        shift += 8
    return res

# Added because int.from_bytes() is incomplete in MicroPython


def bytes_to_int_big_endian(data: bytes) -> int:
    """Converts bytes to integer in big endian mode"""
    res = 0
    for x in data:
        res = (res << 8) | x
    return res


def xor_bytes(a: bytes, b: bytes) -> bytearray:
    """Returns result of a XOR operation over two byte strings or arrays"""
    if len(a) != len(b):
        raise ValueError("Operands have different size")
    res = bytearray(a)
    for i, b in enumerate(b):
        res[i] ^= b
    return res


def lshift1_bytes(data: bytes) -> bytearray:
    """Shifts data in byte array or string by one bit left"""
    res = bytearray(data)
    if len(data):
        idx = 0
        for _ in range(len(data) - 1):
            res[idx] = (data[idx] << 1) & 0xff | (data[idx + 1] >> 7)
            idx += 1
        res[idx] = (data[idx] << 1) & 0xff
    return res


class ProgressCallback:
    """Safe wrapper for progress callback"""

    def __init__(self, progress_cb=None):
        """Create new wrapper"""
        self._callback = progress_cb
        self._value = 0

    def __call__(self, percent):
        """Forward a call to progress callback"""
        self._value = percent
        self._value = 0 if self._value < 0 else self._value
        self._value = 100 if self._value > 100 else self._value
        if callable(self._callback):
            self._callback(self._value)

    def advance(self, percent_inc):
        """Increment progress value and forward a call to progress callback"""
        self(self._value + percent_inc)


def inlist(x) -> list:
    """Wrap argument in a list if it's not already a list itself"""
    if isinstance(x, list):
        return x
    return [x]


def merge_dicts(*dict_args):
    """
    Given any number of dictionaries, shallow copy and merge into a new dict,
    precedence goes to key-value pairs in latter dictionaries.

    This function is needed for compatibility with Python versions before 3.5.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result
