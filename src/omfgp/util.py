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
