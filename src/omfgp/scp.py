"""Common definition for Secure Channel Protocols"""

from collections import namedtuple

# Size of MAC in bytes
HOST_CHALLENGE_SIZE = 8

# Offset of key version inside INITIALIZE UPDATE response
IU_RESP_KEY_VER = 10
# Offset of protocol identifier inside INITIALIZE UPDATE response
IU_RESP_SCP_ID = IU_RESP_KEY_VER + 1

# Static keys of secure channel
StaticKeys = namedtuple('StaticKeys', ['key_enc', 'key_mac', 'key_dek'])


class SecurityLevel(int):
    """ Bit values used by EXTERNAL AUTHENTICATE command"""
    CLEAR = 0
    C_MAC = 0b00000001
    C_DECRYPTION = 0b00000010
    R_MAC = 0b00010000
    R_ENCRYPTION = 0b00100000

    def __new__(cls, value, *args, **kwargs):
        return super(cls, cls).__new__(cls, cls._normalize(value))

    @classmethod
    def _normalize(cls, level):
        """Enables dependent bits"""
        if level & cls.R_ENCRYPTION:
            level |= cls.C_DECRYPTION | cls.R_MAC
        if (level & cls.C_DECRYPTION) or (level & cls.R_MAC):
            level |= cls.C_MAC
        return level