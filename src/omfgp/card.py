from binascii import hexlify
from collections import namedtuple
from .util import *
from .gp_types import *
from . import commands
from . import status
from . import scp
from . import scp_session
from . import tlv

# Parsed APDU
APDU = namedtuple('APDU', ['cla', 'ins', 'p1', 'p2', 'lc', 'data'])


class ISOException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "0x%s '%s'" % (hexlify(self.code).decode(),
                              status.response_text(self.code))

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


def encode(data=b''):
    # str -> hex
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return bytes([len(data)])+bytes(data)


def parse_apdu(apdu) -> APDU:
    """Parse and validates APDU returning (CLA, INS, P1, P2, Lc, Data)."""
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
    """Create APDU byte string from APDU named tuple or hex string."""
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

    def transmit(self: bytes, apdu: bytes) -> tuple:
        """Raw function from pyscard module with byte string API"""
        if len(apdu) < commands.OFF_DATA:
            raise RuntimeError("Invalid APDU")
        if apdu[commands.OFF_LC] != 0:
            if apdu[commands.OFF_LC] == len(apdu) - commands.OFF_DATA:
                apdu += b'\x00'
            elif apdu[commands.OFF_LC] != len(apdu) - commands.OFF_DATA + 1:
                raise RuntimeError("Invalid APDU")
        data, *sw = self.connection.transmit(list(apdu))
        return bytes(data), bytes(sw)

    def request_full(self, apdu: bytes, ignore_errors=[]) -> tuple:
        """Make a request to smartcard returning data and status bytes."""
        if self.debug:
            print(">>", hexlify(apdu).decode())

        if self._scp_inst is None:
            data, sw = self.transmit(apdu)
        else:
            resp = self.transmit(self._scp_inst.wrap_apdu(apdu))
            data, sw = self._scp_inst.unwrap_response(*resp)

        if status.is_error(sw) and sw not in ignore_errors:
            raise ISOException(sw)
        if self.debug:
            print("<<", hexlify(data).decode(), hexlify(sw).decode())
        return data, sw

    def request(self, apdu: bytes) -> bytes:
        """Make a request to smartcard returning only data."""
        data, _ = self.request_full(apdu)
        return data

    def disconnect(self):
        """Disconnect from smart card interface."""
        self.close_secure_channel()
        self.connection.disconnect()

    def select(self, aid: bytes = b'') -> tlv.TLV:
        """Select an applet by AID."""
        # Select by name first or only occurrence of an applet
        p1p2 = b'\x04\x00'
        data = self.request(commands.SELECT + p1p2 + encode(aid))
        return tlv.TLV.deserialize(data)

    def get_status(self, kind: int = StatusKind.APP_SD,
                   aid: bytes = b'') -> list:
        """Request status information from the card.

        :param aid: application AID, defaults to b''
        :param kind: kind of status information requested, defaults to
            StatusKind.APP_SD
        :return: a list of TLV decoded card responses
        """
        if kind not in StatusKind._values:
            raise ValueError("Invalid kind")

        res = []
        p2 = 0b10
        cdata = tlv.TLV({0x4f: aid}).serialize()
        while True:
            rdata, sw = self.request_full(
                commands.GET_STATUS + bytes([kind, p2]) + encode(cdata),
                ignore_errors=[status.ERR_NOT_FOUND])

            res.append(tlv.TLV.deserialize(rdata))
            if sw in (status.SUCCESS, status.ERR_NOT_FOUND):
                break
            elif sw != status.MORE_DATA:
                raise ISOException(sw)
            p2 = 0b11
        return res

    def open_secure_channel(self, keys: scp.StaticKeys = scp.DEFAULT_KEYS,
                            progress_cb=None, **kwargs):
        """Open secure channel using one of SCP protocols chosen by the card.

        :param keys: static keys used to derive session keys and parameters
        :param progress_cb: progress callback, invoked with percent of
        completeness (0-100) as a single argument

        :key key_version: key version, defaults to 0 (first available key)
        :key security_level: security level, a combination of scp.SecurityLevel
        constants, by defaults to only MAC in command

        :key host_challenge: host challenge override
        :key block_size: maximum allowed size of data block in bytes
        :key buggy_icv_counter: flag forcing increment of ICV counter even if
        command has no data, defaults to False

        :key min_scp_version: minimum acceptable SCP version, defaults to 0
        """
        self.close_secure_channel()
        self._scp_inst = scp_session.open_secure_channel(
            self, keys=keys, progress_cb=progress_cb, **kwargs)

    def close_secure_channel(self):
        if self._scp_inst is not None:
            self._scp_inst.close()
            self._scp_inst = None
