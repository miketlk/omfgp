"""Global Platform data types"""

from collections import namedtuple
from .util import *


class StatusKind:
    """Kind of status information requested."""

    # Issuer security domain
    ISD = 0x80
    # Applications or supplementary security domains
    APP_SSD = 0x40
    # Executable load files
    LOAD_FILES = 0x20
    # Executable load files and their executable modules
    LOAD_FILES_MOD = 0x10

    # Allowed values
    _values = (ISD, APP_SSD, LOAD_FILES, LOAD_FILES_MOD)
    # Kinds related to executable load files
    _file_kinds = (LOAD_FILES, LOAD_FILES_MOD)


class Privileges(list):
    """List of Privileges."""

    # Mapping between privilege name and (set_bits, clear_bits)
    _MAP = {
        # Privileges byte 1
        'SECURITY_DOMAIN': (0b100000000000000000000000, 0),
        'DAP_VERIFICATION': (0b110000000000000000000000,
                             0b000000010000000000000000),
        'DELEGATED_MANAGEMENT': (0b101000000000000000000000, 0),
        'CARD_LOCK': (0b000100000000000000000000, 0),
        'CARD_TERMINATE': (0b000010000000000000000000, 0),
        'CARD_RESET': (0b000001000000000000000000, 0),
        'CVM_MANAGEMENT': (0b000000100000000000000000, 0),
        'MANDATED_DAP_VERIFICATION': (0b110000010000000000000000, 0),
        # Privileges byte 2
        'TRUSTED_PATH': (0b1000000000000000, 0),
        'AUTHORIZED_MANAGEMENT': (0b0100000000000000, 0),
        'TOKEN_MANAGEMENT': (0b0010000000000000, 0),
        'GLOBAL_DELETE': (0b0001000000000000, 0),
        'GLOBAL_LOCK': (0b0000100000000000, 0),
        'GLOBAL_REGISTRY': (0b0000010000000000, 0),
        'FINAL_APPLICATION': (0b0000001000000000, 0),
        'GLOBAL_SERVICE': (0b0000000100000000, 0),
        # Privileges byte 3
        'RECEIPT_GENERATION': (0b10000000, 0),
        'CIPHERED_LOAD_FILE_DATA_BLOCK': (0b01000000, 0),
        'CONTACTLESS_ACTIVATION': (0b00100000, 0),
        'CONTACTLESS_SELF_ACTIVATION': (0b00010000, 0)
    }

    @classmethod
    def deserialize(cls, priv_bytes: bytes) -> object:
        """Deserialize privilege bytes to Privileges object."""
        if len(priv_bytes) not in (0, 1, 3):
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
        # This masks clears 'security_domain' bit
        check_mask = ~(self._MAP['SECURITY_DOMAIN'][0])
        for priv in self:
            set_bits = self._MAP[priv][0]
            if (value & check_mask) & set_bits != 0:
                raise ValueError("Incompatible privileges")
            value |= set_bits
        priv_bytes = int_to_bytes_big_endian(value, 3)
        return priv_bytes[:n_bytes]


class _LifeCycleBase(int):
    """Base class for card object life cycle."""

    # Mapping between life cycle name and (set_bits, clear_bits)
    _MAP = {}

    def __new__(cls, value):
        if isinstance(value, str):
            try:
                value = cls._MAP[value][0]
            except KeyError:
                raise ValueError

        if 0x00 <= value <= 0xFF:
            return super(_LifeCycleBase, cls).__new__(cls, value)
        raise ValueError

    def in_state(self, state: str) -> bool:
        """Check if object is in given lifecycle state."""
        bits = self._MAP.get(state)
        if bits is None:
            raise ValueError("Invalid state")
        return self & bits[0] == bits[0] and self & bits[1] == 0

    def __str__(self):
        for key, bits in self._MAP.items():
            if self & bits[0] == bits[0] and self & bits[1] == 0:
                return key
        return str(int(self))

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


class FileLifeCycle(_LifeCycleBase):
    """Executable Load File Life Cycle."""

    # Mapping between life cycle name and (set_bits, clear_bits)
    _MAP = {'LOADED': (0b00000001, 0b11111110)}


class AppLifeCycle(_LifeCycleBase):
    """Application Life Cycle."""

    # Mapping between life cycle name and (set_bits, clear_bits)
    # APP_SPECIFIC is handled separately as APP_SPECIFIC1 ... APP_SPECIFIC15
    _MAP = {
        'INSTALLED': (0b00000011, 0b11111100),
        'SELECTABLE': (0b00000111, 0b11111000),
        'LOCKED': (0b10000011, 0b00000000)
    }

    def __new__(cls, value):
        if isinstance(value, str) and value.startswith('APP_SPECIFIC'):
            app_state = int(value[len('APP_SPECIFIC'):])
            if not (1 <= app_state <= 15):
                raise ValueError
            value = (app_state << 3) | 0b00000111

        return super(cls, cls).__new__(cls, value)

    def in_state(self, state: str) -> bool:
        """Check if object is in given lifecycle state."""
        if state.startswith('APP_SPECIFIC'):
            app_state = int(state[len('APP_SPECIFIC'):])
            value = (app_state << 3) | 0b00000111
            return self == value
        return super(AppLifeCycle, self).in_state(state)

    def __str__(self):
        if 0b00000111 < self <= 0b01111111:
            return 'APP_SPECIFIC' + str((self >> 3) & 0b1111)
        return super(AppLifeCycle, self).__str__()


class SDLifeCycle(_LifeCycleBase):
    """Security Domain Life Cycle."""

    # Mapping between life cycle name and (set_bits, clear_bits)
    _MAP = {
        'INSTALLED': (0b00000011, 0b11111100),
        'SELECTABLE': (0b00000111, 0b11111000),
        'PERSONALIZED': (0b00001111, 0b11110000),
        'LOCKED': (0b10000011, 0b01110000)
    }


class CardLifeCycle(_LifeCycleBase):
    """Card Life Cycle."""

    # Mapping between life cycle name and (set_bits, clear_bits)
    _MAP = {
        'OP_READY': (0b00000001, 0b11111110),
        'INITIALIZED': (0b00000111, 0b11111000),
        'SECURED': (0b00001111, 0b11110000),
        'CARD_LOCKED': (0b01111111, 0b10000000),
        'TERMINATED': (0b11111111, 0b00000000)
    }


class GetStatusP2:
    """Bits of P2 parameter of the GET STATUS command"""
    # Tagged response format
    TAGGED = 0b00000010
    # Get next occurrence
    NEXT = 0b00000001


class InstallRole:
    """Roles of the INSTALL command (P1 parameter)"""
    # More INSTALL commands
    MORE = 0b10000000
    # For registry update
    REGISTRY_UPDATE = 0b01000000
    # For personalization
    PERSONALIZATION = 0b00100000
    # For extradition
    EXTRADITION = 0b00010000
    # For make selectable
    MAKE_SELECTABLE = 0b00001000
    # For install
    INSTALL = 0b00000100
    # For load
    LOAD = 0b00000010
    # A combination of the [for install] and [for make selectable]
    INSTALL_MAKE_SELECTABLE = INSTALL | MAKE_SELECTABLE
    # A combination of the [for load], [for install] and [for make selectable]
    LOAD_INSTALL_MAKE_SELECTABLE = (LOAD | INSTALL | MAKE_SELECTABLE)
    # Allowed values
    _values = (REGISTRY_UPDATE, PERSONALIZATION, EXTRADITION,
               MAKE_SELECTABLE, INSTALL, LOAD, INSTALL_MAKE_SELECTABLE,
               LOAD_INSTALL_MAKE_SELECTABLE)


class InstallProcess:
    """Values specifying process to which INSTALL command belongs"""
    # No information is provided
    NONE = 0x00
    # Beginning of the combined Load, Install and Make Selectable process
    PROCESS_BEGIN = 0x01
    # End of the combined Load, Install and Make Selectable process
    PROCESS_END = 0x03


class LoadP1:
    """Bits of P1 parameter of the LOAD command"""
    # Last block in the sequence
    LAST = 0b10000000
