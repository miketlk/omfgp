from binascii import hexlify
from collections import namedtuple
from .util import get_connection
from . import commands
from . import status
from . import scp
from . import scp_session

# Parsed APDU
APDU = namedtuple('APDU', ['cla', 'ins', 'p1', 'p2', 'lc', 'data'])


class ISOException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "0x%s '%s'" % (hexlify(self.code).decode(),
                              status.is_error(self.code))

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


def encode(data=b''):
    # str -> hex
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return bytes([len(data)])+bytes(data)


def parse_apdu(apdu) -> APDU:
    """Parses and validates APDU returning (CLA, INS, P1, P2, Lc, Data)"""
    if isinstance(apdu, APDU):
        return apdu
    elif isinstance(apdu, tuple):
        res = APDU(*apdu)
    else:
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu)
        if len(apdu) < 5:
            raise ValueError("Invalid APDU")
        data = apdu[5:]
        res = APDU(*(tuple(apdu[:5]) + (data,)))

    if res.lc != len(res.data):
        raise ValueError("Invalid APDU")

    if res.ins == commands.GET_RESPONSE[commands.OFF_INS]:
        if res.p1 != 0 or res.p2 != 0 or res.lc != 0:
            raise ValueError("Invalid APDU")
    elif res.ins & 0xF0 in (0x60, 0x90):
        raise ValueError("Invalid APDU")

    return res


def code_apdu(apdu_obj: APDU) -> bytes:
    """Creates APDU byte string from APDU named tuple or hex string"""
    if isinstance(apdu_obj, (bytes, bytearray)):
        return apdu_obj
    elif isinstance(apdu_obj, str):
        return bytes.fromhex(apdu_obj)
    elif not isinstance(apdu_obj, APDU):
        apdu_obj = APDU(*apdu_obj)

    return bytes(apdu_obj[:5]) + apdu_obj.data


class GPCard:
    def __init__(self, connection=None, debug=False):
        if connection is None:
            connection = get_connection()
        self.connection = connection
        self.debug = debug
        self._scp_inst = None

    def transmit(self, apdu):
        """Raw function from pyscard module"""
        return self.connection.transmit(apdu)

    def request_full(self, apdu):
        """Makes a request to smartcard returning data and status bytes"""
        if self.debug:
            print(">>", bytes(apdu).hex())
        data, *sw = self.transmit(list(apdu))
        sw = bytes(sw)
        if status.is_error(sw):
            raise ISOException(sw)
        if self.debug:
            print("<<", sw.hex(), bytes(data).hex())
        return bytes(data), sw

    def request(self, apdu):
        """Makes a request to smartcard returning only data"""
        data, _ = self.request_full(apdu)
        return data

    def disconnect(self):
        self.connection.disconnect()

    def select(self, aid=b''):
        """Selects an applet by AID"""
        # Select by name first or only occurrence of an applet
        params = b'\x04\x00'
        return self.request(commands.SELECT + params + encode(aid))

    def open_secure_channel(self, keys: scp.StaticKeys,
                            security_level: int = scp.SecurityLevel.C_MAC,
                            host_challenge=None, progress_cb=None):
        if self._scp_inst is not None:
            raise RuntimeError("Secure channel is already open")
        self._scp_inst = scp_session.open_secure_channel(
            self, keys, security_level, host_challenge, progress_cb)
