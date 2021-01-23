"""Secure Channel Protocol version 02"""

from io import BytesIO
from binascii import hexlify
from struct import pack

from . import status
from . import card
from .commands import *
from . import crypto
from .scp import *
from .util import xor_bytes, int_to_bytes_big_endian

# Block of DES cipher containing all zeroes
ZERO_BLOCK = crypto.DES.BLOCK_N_BYTES * b'\0'


class IParam:
    """Bits of the "i" parameter"""
    # 3 Secure Channel Keys
    KEYS_SENC_SMAC_DEK = 0b00000001
    # C-MAC on unmodified APDU
    CMAC_UNMODIFIED_APDU = 0b00000010
    # Initiation mode explicit
    EXPLICIT_INITIATION = 0b00000100
    # ICV set to MAC over AID
    ICV_MAC_OVER_AID = 0b00001000
    # ICV encryption for C-MAC session
    ICV_ENCRYPTION = 0b00010000
    # R-MAC support
    RMAC_SUPPORT = 0b00100000
    # Well-known pseudo-random algorithm (card challenge)
    CARD_PRNG = 0b01000000


class KDC:
    """Key derivation constants"""
    # Secure Channel C-MAC session key
    SESSION_CMAC = b'\x01\x01'
    # Secure Channel R-MAC session key
    SESSION_RMAC = b'\x01\x02'
    # Secure Channel encryption session key
    SESSION_ENC = b'\x01\x82'
    # Secure Channel data encryption session key
    SESSION_DEK = b'\x01\x81'


def _derive_key(base_key: bytes, kdc: bytes, data: bytes) -> bytes:
    """Derive key using given derivation constant and session data."""
    in_block = kdc + data
    if len(in_block) > 2 * crypto.DES.BLOCK_N_BYTES:
        raise ValueError("Derivation constant and data must fit in DES block")
    in_block += (2 * crypto.DES.BLOCK_N_BYTES - len(in_block)) * b'\0'
    des_cbc = crypto.DES(base_key, crypto.MODE_CBC, IV=ZERO_BLOCK)
    return des_cbc.encrypt(in_block)


class SCP02:
    """Secure Channel Protocol version 02."""
    # SCP version
    version = 2
