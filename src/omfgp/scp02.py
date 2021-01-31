"""Secure Channel Protocol version 02"""

from io import BytesIO
from binascii import hexlify

from . import status
from . import card
from .commands import *
from . import crypto
from .scp import *

# Block of DES cipher containing all zeroes
ZERO_BLOCK = crypto.DES.BLOCK_N_BYTES * b'\0'
# Size of MAC in bytes
MAC_N_BYTES = 8
# Constant value of the class byte used for MAC calculation (0x84)
MAC_CONST_CLA = ClaBits.GP | ClaBits.First.GP_SECURE
# Allowed values for security_level parameter
ALLOWED_SECURITY_LEVELS = (
    SecurityLevel.CLEAR,
    SecurityLevel.C_MAC,
    SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC,
    SecurityLevel.R_MAC,
    SecurityLevel.C_MAC | SecurityLevel.R_MAC,
    SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC | SecurityLevel.R_MAC)


class IParam:
    """Bits of the "i" parameter"""
    # 3 Secure Channel Keys (ignored, always requiring to provide 3 keys)
    KEYS_SENC_SMAC_DEK = 0b00000001
    # C-MAC on unmodified APDU
    CMAC_UNMODIFIED_APDU = 0b00000010
    # Initiation mode explicit
    EXPLICIT_INITIATION = 0b00000100 # TODO: support implicit initialization
    # ICV set to MAC over AID
    ICV_MAC_OVER_AID = 0b00001000  # TODO: support
    # ICV encryption for C-MAC session
    ICV_ENCRYPTION = 0b00010000
    # R-MAC support
    RMAC_SUPPORT = 0b00100000
    # Well-known pseudo-random algorithm (card challenge)
    CARD_PRNG = 0b01000000


class KDC:
    """Key derivation constants"""
    # Secure Channel C-MAC session key
    S_MAC = b'\x01\x01'
    # Secure Channel R-MAC session key
    S_RMAC = b'\x01\x02'
    # Secure Channel encryption session key
    S_ENC = b'\x01\x82'
    # Secure Channel data encryption session key
    S_DEK = b'\x01\x81'


def _derive_key(base_key: bytes, kdc: bytes, data: bytes) -> bytes:
    """Derive key using given derivation constant and session data."""
    in_block = kdc + data
    if len(in_block) > 2 * crypto.DES.BLOCK_N_BYTES:
        raise ValueError("Derivation constant and data must fit in DES block")
    in_block += (2 * crypto.DES.BLOCK_N_BYTES - len(in_block)) * b'\0'
    des_cbc = crypto.DES(base_key, crypto.MODE_CBC, IV=ZERO_BLOCK)
    return des_cbc.encrypt(in_block)


def _compute_block_size(block_size_in: int,
                        security_level: SecurityLevel) -> int:
    """Compute maximum block size for the specified security level."""
    if block_size_in <= 0:
        raise ValueError("Invalid block size")

    block_size = block_size_in if block_size_in <= LC_MAX else LC_MAX
    if security_level & SecurityLevel.C_MAC:
        block_size -= MAC_N_BYTES
    if security_level & SecurityLevel.C_DECRYPTION:
        block_size -= block_size % crypto.DES.BLOCK_N_BYTES
        block_size -= 1  # At least one padding byte

    if block_size <= 0:
        raise ValueError("Invalid block size")

    return block_size


class SCP02:
    """Secure Channel Protocol version 02."""
    # SCP version
    _VERSION = 2

    def __init__(self, card_obj, iu_response, keys: StaticKeys,
                 security_level: SecurityLevel, host_challenge,
                 block_size, scp02_i, **options):
        if security_level not in ALLOWED_SECURITY_LEVELS:
            raise ValueError("Invalid security level")
        self._debug = card_obj.debug
        self._security_level = security_level
        self._intf_block_size = block_size
        self._block_size = _compute_block_size(block_size, security_level)
        self._scp_i = scp02_i

        # Parse INITIALIZE UPDATE response
        if len(iu_response) < 28:
            raise RuntimeError("Invalid INITIALIZE UPDATE response")
        stream = BytesIO(iu_response)
        key_dvs_data = stream.read(10)
        key_ver = stream.read(1)[0]
        scp_id = stream.read(1)[0]
        seq_ctr = stream.read(2)
        card_challenge = stream.read(6)
        card_cryptogram = stream.read(8)
        if scp_id != self._VERSION:
            raise RuntimeError("Invalid INITIALIZE UPDATE response")
        if self._debug:
            print("SCP %02x, key version %02x, i=%02x" % (scp_id, key_ver,
                                                          self._scp_i))
            print("Host challenge:", hexlify(host_challenge).decode())
            print("Card challenge:", hexlify(card_challenge).decode())
            print("Card cryptogram:", hexlify(card_cryptogram).decode())
            print("Key diversification data:", hexlify(key_dvs_data).decode())
            print("Sequence counter:", hexlify(seq_ctr).decode())

        # Derive session keys
        self._initialize_keys(keys, seq_ctr)
        if self._debug:
            print("S-ENC:", hexlify(self._s_enc).decode())
            print("S-MAC:", hexlify(self._s_mac).decode())
            print("S-RMAC:", hexlify(self._s_rmac).decode())
            print("S-DEK:", hexlify(self._s_dek).decode())

        # Generate and verify authentication cryptograms
        card_cryptogram_check = crypto.DES.cbc_mac(self._s_enc,
                                                   host_challenge + seq_ctr + card_challenge)
        host_cryptogram = crypto.DES.cbc_mac(self._s_enc,
                                             seq_ctr + card_challenge + host_challenge)
        if card_cryptogram_check != card_cryptogram:
            raise RuntimeError("Invalid card authentication cryptogram")

        # Authenticate host with EXTERNAL AUTHENTICATE selecting security level
        p1p2 = bytes([security_level, 0])
        _, sw = card_obj.request_full(
            self.wrap_apdu(EXTERNAL_AUTHENTICATE + p1p2 +
                           card.encode(host_cryptogram),
                           sl_override=SecurityLevel.C_MAC))
        if sw != status.SUCCESS:
            raise RuntimeError("EXTERNAL AUTHENTICATE failed")

    def _initialize_keys(self, keys: StaticKeys, seq_ctr: bytes):
        """Derive session keys and initialize security parameters."""
        if len(keys.key_enc) != len(keys.key_mac) != len(keys.key_dek):
            raise ValueError("Keys must have the same length")
        if len(keys.key_enc) not in crypto.DES.TDES_ALLOWED_KEY_LEN:
            raise ValueError("Invalid length of a Triple DES key")

        # Derive session keys
        self._s_enc = _derive_key(keys.key_enc, KDC.S_ENC, seq_ctr)
        self._s_mac = _derive_key(keys.key_mac, KDC.S_MAC, seq_ctr)
        self._s_rmac = _derive_key(keys.key_mac, KDC.S_RMAC, seq_ctr)
        self._s_dek = _derive_key(keys.key_dek, KDC.S_DEK, seq_ctr)

        # Initialize MAC ICV initial value and cipher instance (if needed)
        self._mac_icv = ZERO_BLOCK
        if (self._scp_i & IParam.ICV_ENCRYPTION):
            self._mac_icv_enc = crypto.DES(self._s_mac[:8], crypto.MODE_ECB)
        else:
            self._mac_icv_enc = None

        # Initialize R-MAC state
        self._rmac_session = False

    def wrap_apdu(self, apdu: bytes, sl_override=None) -> bytes:
        """Apply secure channel wrapping to APDU."""
        sl = sl_override if sl_override is not None else self._security_level
        if not isinstance(apdu, bytearray):
            apdu = bytearray(apdu)
        if len(apdu) < OFF_DATA or apdu[OFF_LC] != len(apdu) - OFF_DATA:
            raise ValueError("Invalid APDU")
        if apdu[OFF_LC] > self.block_size:
            raise ValueError("APDU too long for wrapping")

        # TODO: R-MAC support
        # TODO: encryption and R-MAC over non-segmented data for GET RESPONSE
        if apdu[OFF_INS] == GET_RESPONSE[OFF_INS]:
            return apdu

        # Parse the header partially and prepare bit masks
        orig_cla = apdu[OFF_CLA]
        if orig_cla & ClaBits.FURTHER:
            sec_bit, iso_sec_bit, lc_mask = (
                ClaBits.Further.SECURE, 0, ClaBits.Further.LC_MASK)
        else:
            sec_bit, iso_sec_bit, lc_mask = (ClaBits.First.GP_SECURE,
                                             ClaBits.First.ISO_SECURE, ClaBits.First.LC_MASK)

        # Add MAC if needed, also patching the CLA byte
        mac = b''
        if sl & SecurityLevel.C_MAC:
            apdu[OFF_CLA] &= ~lc_mask  # Remove logical channel information
            if (self._scp_i & IParam.CMAC_UNMODIFIED_APDU) == 0:
                apdu[OFF_CLA] |= sec_bit
                apdu[OFF_CLA] &= ~iso_sec_bit
                apdu[OFF_LC] += MAC_N_BYTES
            mac = crypto.DES.cbc_mac_single(self._s_mac, apdu, self._mac_icv)
            if (self._scp_i & IParam.CMAC_UNMODIFIED_APDU):
                apdu[OFF_CLA] |= sec_bit
                apdu[OFF_CLA] &= ~iso_sec_bit
                apdu[OFF_LC] += MAC_N_BYTES
            # Restore logical channel information
            apdu[OFF_CLA] |= orig_cla & lc_mask
            # Prepare ICV for the next APDU
            self._mac_icv = (
                self._mac_icv_enc.encrypt(mac) if self._mac_icv_enc else mac)

        # Encrypt data field if needeed
        if (sl & SecurityLevel.C_DECRYPTION) and apdu[OFF_LC] > 0:
            des_cbc = crypto.DES(self._s_enc, crypto.MODE_CBC, IV=ZERO_BLOCK)
            ct = des_cbc.encrypt(des_cbc.add_padding(apdu[OFF_DATA:]))
            apdu = apdu[:OFF_DATA] + ct
            apdu[OFF_LC] = len(ct) + len(mac)

        apdu += mac
        assert apdu[OFF_LC] == len(apdu) - OFF_DATA
        assert apdu[OFF_LC] <= self._intf_block_size
        return bytes(apdu)

    def unwrap_response(self, data: bytes, sw: bytes) -> bytes:
        """Remove secure channel wrapping from APDU response."""
        # Verify R-MAC if needed
        if self._security_level & SecurityLevel.R_MAC:
            raise NotImplementedError("R-MAC not implemented yet in SCP02")

        return data, sw

    def encrypt_data(self, data, mode: int = crypto.MODE_ECB):
        """Encrypt sensitive data with Session DEK."""
        if len(data) == 0 or (len(data) % crypto.DES.BLOCK_N_BYTES) != 0:
            raise ValueError("Data block must be a multiple of cipher block")
        des_ecb = crypto.DES(self._s_dek, crypto.MODE_ECB, IV=ZERO_BLOCK)
        return des_ecb.encrypt(data)

    def decrypt_data(self, data, mode: int = crypto.MODE_ECB):
        """Decrypt sensitive data with Session DEK."""
        if len(data) == 0 or (len(data) % crypto.DES.BLOCK_N_BYTES) != 0:
            raise ValueError("Data block must be a multiple of cipher block")
        des_ecb = crypto.DES(self._s_dek, crypto.MODE_ECB, IV=ZERO_BLOCK)
        return des_ecb.decrypt(data)

    def close(self):
        """Clear all session data."""
        del self._security_level
        del self._s_enc
        del self._s_mac
        del self._s_rmac
        del self._s_dek
        del self._mac_icv
        del self._mac_icv_enc
        del self._rmac_session

    @property
    def block_size(self):
        return self._block_size

    @property
    def version(self):
        return self._VERSION
