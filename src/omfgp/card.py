from .util import get_connection
from . import commands

class ISOException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return f"ISO Exception 0x{self.code.hex()}"

    def __repr__(self):
        return f"ISOException(0x{self.code.hex()})"

def encode(data=b""):
    # str -> hex
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return bytes([len(data)])+bytes(data)

class GPCard:
    def __init__(self, connection=None, debug=False):
        if connection is None:
            connection = get_connection()
        self.connection = connection
        self.debug = debug

    def transmit(self, apdu):
        """Raw function from pyscard module"""
        return self.connection.transmit(apdu)

    def request(self, apdu):
        """More friendly function. Raises an error if card returned an error"""
        if self.debug:
            print(">>", bytes(apdu).hex())
        data, *sw = self.transmit(list(apdu))
        sw = bytes(sw)
        if sw!=b"\x90\x00":
            raise ISOException(sw)
        if self.debug:
            print("<<", sw.hex(), bytes(data).hex())
        return bytes(data)

    def disconnect(self):
        self.connection.disconnect()

    def select(self, aid=b""):
        return self.request(commands.SELECT+encode(aid))