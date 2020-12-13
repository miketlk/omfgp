#!/usr/bin/env python3

"""Utility functions"""

from binascii import hexlify
from smartcard.System import readers
from smartcard.CardConnection import CardConnection


def get_reader(name=""):
    """Returns first found reader """
    rarr = [r for r in readers() if name in str(r)]
    if len(rarr) == 0:
        raise RuntimeError("Reader not found")
    return rarr[0]


def get_connection(reader=None, protocol=CardConnection.T1_protocol):
    """Establish connection with a card"""
    if reader is None:
        reader = get_reader()
    connection = reader.createConnection()
    connection.connect(protocol)
    return connection


def aid_to_str(aid: bytes):
    """Converts AID from bytes to string representation"""
    s = hexlify(aid).decode().upper()
    return s[1:] if s.startswith("0") else s


def int_to_bytes_big_endian(x: int, n_bytes):
    """Converts integer to bytes in big endian mode"""
    if x >= 256 ** n_bytes:
        raise ValueError("Conversion overflow")
    res = bytearray(n_bytes)
    shift = 0
    for i in range(n_bytes - 1, -1, -1):
        res[i] = (x >> shift) & 0xff
        shift += 8
    return res

def xor_bytes(a, b):
    """Returns result of a XOR operation over two byte strings or arrays"""
    if len(a) != len(b):
        raise ValueError("Operands have different size")
    res = bytearray(a)
    for i, b in enumerate(b):
        res[i] ^= b
    return res


def lshift1_bytes(data):
    """Shifts data in byte array or string by one bit left"""
    res = bytearray(data)
    if len(data):
        idx = 0
        for _ in range(len(data) - 1):
            res[idx] = (data[idx] << 1) & 0xff | (data[idx + 1] >> 7)
            idx += 1
        res[idx] = (data[idx] << 1) & 0xff
    return res