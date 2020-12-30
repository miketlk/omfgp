"""Global Platform data types"""

from collections import namedtuple
from .util import *

# Parsed APDU
APDU = namedtuple('APDU', ['cla', 'ins', 'p1', 'p2', 'lc', 'data'])


class StatusKind:
    """Kind of status information requested."""

    # Issuer security domain
    ISD = 0x80
    # Applications or supplementary security domains
    APP_SD = 0x40
    # Executable load files
    LOAD_FILES = 0x20
    # Executable load files and their executable modules
    LOAD_FILES_MOD = 0x10

    # Allowed values
    _values = (ISD, APP_SD, LOAD_FILES, LOAD_FILES_MOD)


class Privileges(list):
    """List of Privileges."""

    # Mapping between privilege name and (set_bits, clear_bits)
    _MAP = {
        # Privileges byte 1
        'security_domain': (0b100000000000000000000000, 0),
        'dap_verification': (0b110000000000000000000000,
                             0b000000010000000000000000),
        'delegated_management': (0b101000000000000000000000, 0),
        'card_lock': (0b000100000000000000000000, 0),
        'card_terminate': (0b000010000000000000000000, 0),
        'card_reset': (0b000001000000000000000000, 0),
        'cvm_management': (0b000000100000000000000000, 0),
        'mandated_dap_verification': (0b110000010000000000000000, 0),
        # Privileges byte 2
        'trusted_path': (0b1000000000000000, 0),
        'authorized_management': (0b0100000000000000, 0),
        'token_management': (0b0010000000000000, 0),
        'global_delete': (0b0001000000000000, 0),
        'global_lock': (0b0000100000000000, 0),
        'global_registry': (0b0000010000000000, 0),
        'final_application': (0b0000001000000000, 0),
        'global_service': (0b1100000100000000, 0),
        # Privileges byte 3
        'receipt_generation': (0b10000000, 0),
        'ciphered_load_file_data_block': (0b01000000, 0),
        'contactless_activation': (0b00100000, 0),
        'contactless_self_activation': (0b00010000, 0)
    }

    @classmethod
    def deserialize(cls, priv_bytes: bytes) -> object:
        """Deserialize privilege bytes to Privileges object."""
        if len(priv_bytes) not in (1, 3):
            raise ValueError("Invalid privilege bytes")
        priv_bytes += (3 - len(priv_bytes)) * b'\0'
        value = bytes_to_int_big_endian(priv_bytes)
        lst = cls()
        for key, bits in cls._MAP.items():
            if value & bits[0] == bits[0] and value & bits[1] == 0:
                lst.append(key)
        return lst

    def serialize(self, n_bytes: int = 3) -> bytes:
        """Serialize Privileges to privilege bytes."""
        value = 0
        for priv in self:
            set_bits = self._MAP[priv][0]
            value |= set_bits
        priv_bytes = int_to_bytes_big_endian(value, 3)
        return priv_bytes[:n_bytes]
